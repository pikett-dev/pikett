"""What each security check is and why Pikett runs it, for the help on the overview and /ops/help.

The texts live in the message catalogs (`help.<check>.what|why|ours|link.<n>`); the link targets are here. The checks
are keyed by their class name, like `names.CHECK_KEYS`.
"""

from dataclasses import dataclass

from app.i18n import Locale
from app.security.names import CHECK_KEYS


@dataclass(frozen=True)
class Link:
    title: str
    url: str


@dataclass(frozen=True)
class Help:
    what: str
    why: str
    ours: str  # when it runs here and what raises an alarm
    links: tuple[Link, ...]


LINK_URLS = {
    "findings": ("https://nvd.nist.gov/vuln-metrics/cvss",),
    "trivy": ("https://trivy.dev/", "https://trivy.dev/docs/latest/target/container_image/"),
    "osv": ("https://osv.dev/", "https://google.github.io/osv-scanner/"),
    "intel": ("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "https://www.first.org/epss/"),
    "patch": (
        "https://ubuntu.com/server/docs/how-to/software/automatic-updates/",
        "https://github.com/liske/needrestart",
    ),
    "reboot": (),
    "backup": ("https://coolify.io/docs/databases/backups",),
    "lynis": ("https://cisofy.com/lynis/",),
    "crowdsec": ("https://docs.crowdsec.net/",),
    "ssh": ("https://tailscale.com/docs/features/tailscale-ssh",),
    "images": ("https://crazymax.dev/diun/", "https://github.com/coollabsio/coolify/releases"),
    "runner": (),
}


def help_for(locale: Locale, name: str) -> Help:
    key = CHECK_KEYS[name]
    return Help(
        what=locale.t(f"help.{key}.what"),
        why=locale.t(f"help.{key}.why"),
        ours=locale.t(f"help.{key}.ours"),
        links=tuple(Link(locale.t(f"help.{key}.link.{i}"), url) for i, url in enumerate(LINK_URLS[key])),
    )


def all_help(locale: Locale) -> dict[str, Help]:
    return {name: help_for(locale, name) for name in CHECK_KEYS}
