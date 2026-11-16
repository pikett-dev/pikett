#!/usr/bin/env python3
"""Collects security facts on this server and posts them to the ops service (POST /api/v1/host-reports).

Runs as root from the systemd timers in this folder:

    ops-collect.py KIND [KIND ...]

It only reads. Every kind is sent raw; the ops service interprets it, so this script stays small and the logic is
tested there. When reading fails, the report carries {"error": ...}, so a broken check is never silent.

Configuration in /etc/ops-collect.env (KEY=VALUE lines, see ops-collect.env.example). Standard library only, so it
runs on a plain Ubuntu without extra Python packages.
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ENV_FILE = Path(os.environ.get("OPS_COLLECT_ENV", "/etc/ops-collect.env"))
TIMEOUT_SECONDS = 60
# Same image as the trivy-server in deploy/ops-server/compose.yml (Renovate keeps both in step).
TRIVY_IMAGE = "aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip('"').strip("'")
    return {**values, **os.environ}  # the environment wins, which is handy for a manual run


def iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat()


# ---- kinds -------------------------------------------------------------------------------------------------------


def tail(path: str, max_bytes: int = 200_000) -> str:
    """The end of a log file, cut at a line start."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - max_bytes))
        data = f.read().decode(errors="replace")
    return data if size <= max_bytes else data.split("\n", 1)[-1]


def check_url(url: str) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(url, timeout=20) as response:  # noqa: S310 (our own health URLs)
            return {"url": url, "status": response.status}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status": exc.code}
    except Exception as exc:
        return {"url": url, "error": str(exc)[:200]}


def collect_patches(env: dict[str, str]) -> dict[str, Any]:
    """What the patch window did: the unattended-upgrades logs, needrestart, reboot-required and health after it."""
    log_dir = env.get("UU_LOG_DIR", "/var/log/unattended-upgrades")
    log = Path(log_dir) / "unattended-upgrades.log"
    if not log.exists():
        return {"error": f"{log} is missing (is unattended-upgrades installed?)"}
    dpkg = Path(log_dir) / "unattended-upgrades-dpkg.log"
    try:
        needrestart = subprocess.run(  # noqa: S603
            ["needrestart", "-b", "-r", "l"],  # noqa: S607 (batch mode, list only, restarts nothing)
            capture_output=True, text=True, timeout=120,
        ).stdout  # fmt: skip
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        needrestart = f"NEEDRESTART-ERROR: {exc}"
    flag = Path(env.get("REBOOT_FLAG", "/var/run/reboot-required"))
    pkgs = flag.with_name(flag.name + ".pkgs")
    return {
        "log": tail(str(log)),
        "dpkg_log": tail(str(dpkg)) if dpkg.exists() else "",
        "needrestart": needrestart,
        "reboot_required": flag.exists(),
        "reboot_packages": pkgs.read_text().split() if pkgs.exists() else [],
        "health": [check_url(url) for url in env.get("HEALTH_URLS", "").split()],
    }


LYNIS_KEYS = ("lynis_version=", "hardening_index=", "warning[]=", "suggestion[]=", "report_datetime_start=")


def collect_lynis(env: dict[str, str]) -> dict[str, Any]:
    """Run the Lynis audit and send the lines of its report the ops service reads."""
    report = Path(env.get("LYNIS_REPORT", "/var/log/lynis-report.dat"))
    try:
        result = subprocess.run(  # noqa: S603
            ["lynis", "audit", "system", "--cronjob", "--quiet", "--report-file", str(report)],  # noqa: S607
            capture_output=True, text=True, timeout=1800,
        )  # fmt: skip
    except FileNotFoundError:
        return {"error": "lynis is not installed (apt-get install lynis)"}
    if result.returncode != 0 or not report.exists():
        return {"error": f"lynis exited with {result.returncode}: {(result.stderr or result.stdout).strip()[-300:]}"}
    lines = [line for line in report.read_text(errors="replace").splitlines() if line.startswith(LYNIS_KEYS)]
    return {"report": "\n".join(lines)}


def cscli(*args: str) -> Any:
    result = subprocess.run(  # noqa: S603
        ["cscli", *args, "-o", "json"],  # noqa: S607
        capture_output=True, text=True, check=True, timeout=120,
    )  # fmt: skip
    return json.loads(result.stdout or "null") or []


def collect_crowdsec(env: dict[str, str]) -> dict[str, Any]:
    """CrowdSec's alerts of the last day and the bans in force, trimmed to what the weekly report shows."""
    try:
        alerts = cscli("alerts", "list", "--since", "25h", "--limit", "0")
        decisions = cscli("decisions", "list", "--limit", "0")
    except FileNotFoundError:
        return {"error": "cscli is missing (is CrowdSec installed?)"}
    except subprocess.CalledProcessError as exc:
        return {"error": f"cscli failed: {(exc.stderr or '').strip()[-300:]}"}
    return {
        "alerts": [
            {
                "scenario": a.get("scenario", ""),
                "ip": (a.get("source") or {}).get("ip", ""),
                "country": (a.get("source") or {}).get("cn", ""),
                "at": a.get("created_at", ""),
                "banned": bool(a.get("decisions")),
            }
            for a in alerts[:1000]
        ],
        "active_bans": sum(len(a.get("decisions") or []) for a in decisions),
    }


def collect_ssh(env: dict[str, str]) -> dict[str, Any]:
    """Successful SSH logins of the last 25 hours from journald."""
    result = subprocess.run(  # noqa: S603
        ["journalctl", "-u", "ssh", "-u", "sshd", "--since", "-25h", "-o", "json", "--no-pager"],  # noqa: S607
        capture_output=True, text=True, timeout=120,
    )  # fmt: skip
    if result.returncode != 0:
        return {"error": f"journalctl exited with {result.returncode}: {result.stderr.strip()[-300:]}"}
    logins = []
    for line in result.stdout.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        message = entry.get("MESSAGE")
        if isinstance(message, str) and message.startswith("Accepted "):
            logins.append({"at": iso(int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000), "message": message[:300]})
    return {"logins": logins[-500:]}


def docker(*args: str, timeout: int = 60) -> str:
    result = subprocess.run(  # noqa: S603 (fixed program, arguments from docker itself)
        ["docker", *args],  # noqa: S607 (docker from PATH, as root under systemd)
        capture_output=True,
        text=True,
        check=True,
        timeout=timeout,
    )
    return result.stdout


def running_images() -> list[dict[str, Any]]:
    """The images of the running containers, one entry per image with the containers that run it."""
    ids = docker("ps", "-q", "--no-trunc").split()
    if not ids:
        return []
    by_image: dict[str, dict[str, Any]] = {}
    for container in json.loads(docker("inspect", *ids)):
        image_id = container["Image"]
        entry = by_image.setdefault(
            image_id, {"image": container["Config"]["Image"], "image_id": image_id, "containers": []}
        )
        entry["containers"].append(container["Name"].lstrip("/"))
    return list(by_image.values())


def trim_trivy(report: dict[str, Any]) -> list[dict[str, str]]:
    """Only what the ops service stores; the full Trivy JSON carries descriptions and CVSS vectors."""
    return [
        {
            "id": v.get("VulnerabilityID", ""),
            "package": v.get("PkgName", ""),
            "installed": v.get("InstalledVersion", ""),
            "fixed": v.get("FixedVersion", ""),
            "severity": v.get("Severity", "UNKNOWN"),
            "title": (v.get("Title") or "")[:200],
        }
        for result in report.get("Results") or []
        for v in result.get("Vulnerabilities") or []
    ]


# One image can carry thousands of findings, and the ops service refuses report bodies over 4 MB (app/api/limits.py).
# The most severe ones are kept; the report says how many were left out. The budget is per report, shared by all
# images, so the size does not depend on how many images a server runs. tests/test_collector.py pins the sums.
MAX_VULNS_PER_IMAGE = 200
MAX_VULNS_PER_REPORT = 5000
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def cap_vulnerabilities(vulns: list[dict[str, str]], images: int = 1) -> tuple[list[dict[str, str]], int]:
    """The most severe findings (stable within a severity) and the number left out.

    One image keeps at most MAX_VULNS_PER_IMAGE; with many images each gets an equal share of MAX_VULNS_PER_REPORT.
    """
    limit = max(1, min(MAX_VULNS_PER_IMAGE, MAX_VULNS_PER_REPORT // max(1, images)))
    ranked = sorted(vulns, key=lambda v: SEVERITY_ORDER.get(v["severity"], len(SEVERITY_ORDER)))
    return ranked[:limit], max(0, len(ranked) - limit)


def collect_trivy(env: dict[str, str]) -> dict[str, Any]:
    """Scan the image of every running container against the trivy-server on the ops server."""
    server = env.get("TRIVY_SERVER", "")
    if not server:
        return {"error": "TRIVY_SERVER is not set"}
    try:
        with urllib.request.urlopen(server.rstrip("/") + "/healthz", timeout=10) as response:  # noqa: S310
            response.read()
    except Exception as exc:
        return {"server": server, "error": f"Trivy server {server} not reachable: {exc}"}
    images = []
    running = running_images()
    for image in running:
        # The client runs in a container of the same version as the server; it reads the image from the local
        # Docker engine. The token is passed through the environment, not the command line. The label lets Alloy
        # drop the JSON report the client prints, which would otherwise be most of the server's log lines.
        command = [
            "run", "--rm", "--label", "ops-collect=trivy", "--network", "host", "-e", "TRIVY_TOKEN",
            "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
            env.get("TRIVY_IMAGE", TRIVY_IMAGE),
            "image", "--server", server, "--scanners", "vuln", "--format", "json", "--quiet",
            "--image-src", "docker", "--timeout", "10m", image["image"],
        ]  # fmt: skip
        try:
            result = subprocess.run(  # noqa: S603
                ["docker", *command],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=900,
                env={**os.environ, "TRIVY_TOKEN": env.get("TRIVY_TOKEN", "")},
            )
        except subprocess.TimeoutExpired:
            images.append({**image, "error": "time limit of 15 min exceeded"})
            continue
        if result.returncode != 0:
            images.append({**image, "error": (result.stderr or result.stdout).strip()[-500:]})
            continue
        vulnerabilities, omitted = cap_vulnerabilities(trim_trivy(json.loads(result.stdout)), len(running))
        images.append({**image, "vulnerabilities": vulnerabilities, "vulnerabilities_omitted": omitted})
    return {"server": server, "images": images}


def collect_images(env: dict[str, str]) -> dict[str, Any]:
    """The running images with their registry digests, for the update check on the ops server."""
    images = running_images()
    if images:
        inspected = json.loads(docker("image", "inspect", *[image["image_id"] for image in images]))
        digests = {item["Id"]: item.get("RepoDigests") or [] for item in inspected}
        for image in images:
            image["repo_digests"] = digests.get(image["image_id"], [])
    return {"images": images}


COLLECTORS: dict[str, Callable[[dict[str, str]], dict[str, Any]]] = {
    "crowdsec": collect_crowdsec,
    "images": collect_images,
    "lynis": collect_lynis,
    "patches": collect_patches,
    "ssh": collect_ssh,
    "trivy": collect_trivy,
}


# ---- sending -----------------------------------------------------------------------------------------------------


def collect(kind: str, env: dict[str, str]) -> dict[str, Any]:
    try:
        return COLLECTORS[kind](env)
    except Exception as exc:  # the report itself tells the ops service that this check is broken
        return {"error": f"{type(exc).__name__}: {exc}"[:2000]}


def post(env: dict[str, str], kind: str, data: dict[str, Any]) -> None:
    body = json.dumps(
        {"host": env["HOST_NAME"], "kind": kind, "collected_at": datetime.now(UTC).isoformat(), "data": data},
        ensure_ascii=False,  # non-ASCII text costs 1 to 4 bytes, not the 6 of a \\u escape: the size budget assumes it
    ).encode()
    request = urllib.request.Request(  # noqa: S310 (OPS_URL is our own service over Tailscale)
        env["OPS_URL"].rstrip("/") + "/api/v1/host-reports",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {env['HOST_REPORT_TOKEN']}"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
        response.read()


def main(argv: list[str]) -> int:
    kinds = argv[1:]
    unknown = [k for k in kinds if k not in COLLECTORS]
    if unknown:
        print(f"usage: {argv[0]} KIND [KIND ...]; kinds: {', '.join(COLLECTORS)}", file=sys.stderr)
        return 2
    if not kinds:  # a timer whose list is empty on this server (HOURLY_KINDS= in the env file)
        print("nothing to collect")
        return 0
    env = load_env(ENV_FILE)
    failed = False
    for kind in kinds:
        try:
            post(env, kind, collect(kind, env))
        except Exception as exc:
            print(f"sending {kind} failed: {exc}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
