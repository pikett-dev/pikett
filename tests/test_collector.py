import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "deploy" / "host-agent" / "ops-collect.py"


@pytest.fixture(scope="module")
def collector():
    spec = importlib.util.spec_from_file_location("ops_collect", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_crashing_collector_becomes_an_error_report(collector, monkeypatch):
    def boom(env):
        raise OSError("permission denied")

    monkeypatch.setitem(collector.COLLECTORS, "images", boom)

    assert collector.collect("images", {}) == {"error": "OSError: permission denied"}


def test_env_file_is_read_and_the_environment_wins(collector, tmp_path, monkeypatch):
    env_file = tmp_path / "ops-collect.env"
    env_file.write_text('# comment\nOPS_URL="http://100.64.0.1:8030"\nHOST_NAME=app-1\n')
    monkeypatch.setenv("HOST_NAME", "other")

    env = collector.load_env(env_file)

    assert env["OPS_URL"] == "http://100.64.0.1:8030"
    assert env["HOST_NAME"] == "other"


def test_unknown_kinds_are_refused(collector):
    assert collector.main(["ops-collect.py", "nonsense"]) == 2


TRIVY_JSON = {
    "Results": [
        {
            "Target": "postgres:18 (debian 12.8)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2025-1",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.2",
                    "FixedVersion": "3.0.15",
                    "Severity": "HIGH",
                    "Title": "a" * 500,
                    "Description": "long text the service does not need",
                }
            ],
        },
        {"Target": "usr/local/bin/gosu", "Vulnerabilities": None},
    ]
}


def test_trivy_json_is_trimmed_to_what_the_service_stores(collector):
    [v] = collector.trim_trivy(TRIVY_JSON)

    assert v == {
        "id": "CVE-2025-1",
        "package": "openssl",
        "installed": "3.0.2",
        "fixed": "3.0.15",
        "severity": "HIGH",
        "title": "a" * 200,
    }


def test_trivy_reports_an_unreachable_server(collector):
    data = collector.collect("trivy", {"TRIVY_SERVER": "http://127.0.0.1:9"})

    assert "not reachable" in data["error"]


def test_running_images_name_containers_by_their_coolify_resource_when_they_have_one(collector, monkeypatch):
    inspected = [
        {
            "Name": "/k3x9-2026",
            "Image": "sha256:a",
            "Config": {"Image": "core:abc", "Labels": {"coolify.resourceName": "core"}},
        },
        {
            "Name": "/k3x9-2027",
            "Image": "sha256:a",
            "Config": {"Image": "core:abc", "Labels": {"coolify.resourceName": "core"}},
        },
        {"Name": "/plain", "Image": "sha256:a", "Config": {"Image": "core:abc", "Labels": None}},
    ]

    def fake_docker(*args, timeout=60):
        return "id1\nid2\nid3\n" if args[0] == "ps" else json.dumps(inspected)

    monkeypatch.setattr(collector, "docker", fake_docker)

    [entry] = collector.running_images()
    assert entry["containers"] == ["core", "plain"]


def test_running_images_groups_containers_by_image(collector, monkeypatch):
    inspect = [
        {"Name": "/core-1", "Image": "sha256:a", "Config": {"Image": "core:abc"}},
        {"Name": "/core-2", "Image": "sha256:a", "Config": {"Image": "core:abc"}},
        {"Name": "/db", "Image": "sha256:b", "Config": {"Image": "postgres:18"}},
    ]

    def fake_docker(*args, timeout=60):
        return "id1 id2 id3" if args[0] == "ps" else __import__("json").dumps(inspect)

    monkeypatch.setattr(collector, "docker", fake_docker)

    assert collector.running_images() == [
        {"image": "core:abc", "image_id": "sha256:a", "containers": ["core-1", "core-2"]},
        {"image": "postgres:18", "image_id": "sha256:b", "containers": ["db"]},
    ]


def test_images_add_the_registry_digests(collector, monkeypatch):
    monkeypatch.setattr(
        collector,
        "running_images",
        lambda: [{"image": "postgres:18", "image_id": "sha256:b", "containers": ["db"]}],
    )
    monkeypatch.setattr(
        collector, "docker", lambda *args, timeout=60: '[{"Id": "sha256:b", "RepoDigests": ["postgres@sha256:x"]}]'
    )

    assert collector.collect("images", {}) == {
        "images": [
            {
                "image": "postgres:18",
                "image_id": "sha256:b",
                "containers": ["db"],
                "repo_digests": ["postgres@sha256:x"],
            }
        ]
    }


def test_lynis_reports_a_missing_binary(collector, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")

    assert collector.collect("lynis", {}) == {"error": "lynis is not installed (apt-get install lynis)"}


def test_ssh_keeps_only_accepted_logins(collector, monkeypatch):
    import json
    import subprocess

    lines = [
        {
            "MESSAGE": "Accepted publickey for root from 100.101.1.2 port 1 ssh2",
            "__REALTIME_TIMESTAMP": "1794600000000000",
        },
        {"MESSAGE": "Connection closed by 100.101.1.2", "__REALTIME_TIMESTAMP": "1794600001000000"},
    ]

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args, 0, "\n".join(json.dumps(line) for line in lines), "")

    monkeypatch.setattr(collector.subprocess, "run", fake_run)

    [entry] = collector.collect("ssh", {})["logins"]
    assert entry["message"].startswith("Accepted publickey for root")
    assert entry["at"].startswith("2026-")


def test_crowdsec_reports_a_missing_cscli(collector, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")

    assert collector.collect("crowdsec", {}) == {"error": "cscli is missing (is CrowdSec installed?)"}


def test_trivy_findings_are_capped_per_image_most_severe_first(collector):
    vulns = [{"id": f"CVE-{i}", "severity": "LOW"} for i in range(300)]
    vulns += [{"id": "CVE-HIGH", "severity": "HIGH"}, {"id": "CVE-CRIT", "severity": "CRITICAL"}]

    kept, omitted = collector.cap_vulnerabilities(vulns)

    assert len(kept) == collector.MAX_VULNS_PER_IMAGE
    assert [v["id"] for v in kept[:2]] == ["CVE-CRIT", "CVE-HIGH"]
    assert omitted == 302 - collector.MAX_VULNS_PER_IMAGE
    assert collector.cap_vulnerabilities(vulns[:3]) == (vulns[:3], 0)


def test_many_images_share_the_report_budget(collector):
    vulns = [{"id": f"CVE-{i}", "severity": "LOW"} for i in range(1000)]

    kept, omitted = collector.cap_vulnerabilities(vulns, images=100)

    assert len(kept) == collector.MAX_VULNS_PER_REPORT // 100
    assert omitted == 1000 - len(kept)
    assert len(collector.cap_vulnerabilities(vulns, images=5000)[0]) == 1  # never zero: the image still shows a finding


def test_a_capped_trivy_report_fits_the_body_limit_whatever_the_image_count(collector):
    import json

    from app.api.limits import HOST_REPORTS_LIMIT

    worst = {  # every field generously long: package and version strings are not capped by the collector
        "id": "CVE-2026-123456",
        "package": "p" * 80,
        "installed": "1" * 60,
        "fixed": "2" * 60,
        "severity": "CRITICAL",
        "title": "t" * 200,
    }
    image = {"image": "i" * 120, "image_id": "sha256:" + "a" * 64, "containers": ["c" * 60] * 3}
    for count in (1, 25, 100, 400):
        share = min(collector.MAX_VULNS_PER_IMAGE, collector.MAX_VULNS_PER_REPORT // count)
        data = {"images": [{**image, "vulnerabilities": [worst] * share}] * count}
        report = {"host": "app-1", "kind": "trivy", "collected_at": "2026-11-16T00:00:00Z", "data": data}
        assert len(json.dumps(report)) < HOST_REPORTS_LIMIT, count
