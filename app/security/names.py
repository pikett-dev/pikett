"""Stable names of the checks, for catalog keys (`security.<key>.*`, `help.<key>.*`) and the groups of the overview."""

CHECK_KEYS = {
    "PatchCheck": "patch",
    "RebootQuestions": "reboot",
    "BackupCheck": "backup",
    "FindingsReport": "findings",
    "TrivyCheck": "trivy",
    "OsvCheck": "osv",
    "IntelCheck": "intel",
    "ImageUpdatesCheck": "images",
    "LynisCheck": "lynis",
    "CrowdSecCheck": "crowdsec",
    "SshLoginCheck": "ssh",
    "RunnerHeartbeat": "runner",  # not a check: app/actions/overview.py builds its rows
}

# The checks in the order of the reports, grouped the way people think about them. Titles: `web.group.<id>`.
GROUPS = [
    ("vulns", ("FindingsReport", "TrivyCheck", "OsvCheck", "IntelCheck")),
    ("patches", ("PatchCheck", "RebootQuestions")),
    ("backup", ("BackupCheck",)),
    ("hardening", ("LynisCheck", "CrowdSecCheck", "SshLoginCheck")),
    ("updates", ("ImageUpdatesCheck",)),
    ("actions", ("RunnerHeartbeat",)),
]
GROUP_OF = {name: group for group, names in GROUPS for name in names}
OTHER_GROUP = "other"
