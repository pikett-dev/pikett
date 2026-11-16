"""The patch window exists three times: as files, as a cloud-init fragment, and in the ops server's cloud-init."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent
PATCHING = ROOT / "deploy" / "host-agent" / "patching"
FILES = {
    "/etc/apt/apt.conf.d/20auto-upgrades": "20auto-upgrades",
    "/etc/apt/apt.conf.d/52ops-unattended-upgrades": "52ops-unattended-upgrades",
    "/etc/needrestart/conf.d/ops.conf": "needrestart-ops.conf",
    "/etc/systemd/system/apt-daily.timer.d/ops-window.conf": "apt-daily.timer.conf",
    "/etc/systemd/system/apt-daily-upgrade.timer.d/ops-window.conf": "apt-daily-upgrade.timer.conf",
}


def written(path: Path) -> dict[str, str]:
    document = yaml.safe_load(path.read_text())
    entries = document if isinstance(document, list) else document["write_files"]
    return {entry["path"]: entry["content"] for entry in entries}


@pytest.mark.parametrize("source", [PATCHING / "cloud-init-fragment.yaml", ROOT / "deploy/ops-server/cloud-init.yaml"])
def test_cloud_init_writes_the_same_files_as_the_retrofit(source):
    files = written(source)
    for target, name in FILES.items():
        assert files[target] == (PATCHING / name).read_text(), f"{source.name}: {target} differs from {name}"


def test_only_the_security_pockets_are_allowed():
    config = (PATCHING / "52ops-unattended-upgrades").read_text()

    assert "#clear Unattended-Upgrade::Allowed-Origins;" in config
    origins = [line.strip() for line in config.splitlines() if line.strip().startswith('"${distro_id}')]
    assert origins and all("security" in origin for origin in origins)
