from collections.abc import Callable
from datetime import datetime

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.incidents.service import IncidentService
from app.notify.base import ChatNotifier
from app.security.backup import BackupCheck, CoolifyBackups
from app.security.base import Check, Section
from app.security.findings import FindingsReport
from app.security.images import HttpCoolify, HttpRegistry, ImageUpdatesCheck
from app.security.intel import HttpIntel, IntelCheck
from app.security.intrusion import CrowdSecCheck, SshLoginCheck
from app.security.lynis import LynisCheck
from app.security.osv import OsvCheck, OsvCliScanner
from app.security.patches import PatchCheck
from app.security.reboot import RebootQuestions
from app.security.service import SecurityService
from app.security.signals import Signals
from app.security.trivy import TrivyCheck


def build_security(
    settings: Settings,
    sessions: async_sessionmaker[AsyncSession],
    incidents: IncidentService,
    clock: Callable[[], datetime],
    client: httpx.AsyncClient,
    chat: ChatNotifier,
) -> tuple[SecurityService, RebootQuestions]:
    """The checks in the order their lines appear in the reports, and the reboot questions for the Slack button."""
    locale = settings.locale
    signals = Signals(sessions, incidents, clock)
    patches = PatchCheck(
        sessions, signals, clock, settings.security_hosts, self_rebooting=settings.self_rebooting_hosts, locale=locale
    )
    reboots = RebootQuestions(sessions, chat, clock, self_rebooting=settings.self_rebooting_hosts, locale=locale)
    patches.on_reboot_state(reboots.on_patch_report)
    coolify = None
    if settings.coolify_url and settings.coolify_token:
        coolify = HttpCoolify(client, settings.coolify_url, settings.coolify_token)
    scanner = OsvCliScanner(settings.bitbucket_read_tokens, locale=locale) if settings.bitbucket_read_tokens else None
    backups = None
    if settings.coolify_url and settings.coolify_token:
        backups = CoolifyBackups(client, settings.coolify_url, settings.coolify_token, locale)
    backup = BackupCheck(
        sessions, signals, clock, backups, settings.backup_databases, locale=locale, link=settings.coolify_url or ""
    )
    findings = FindingsReport(sessions, locale=locale)
    trivy = TrivyCheck(sessions, signals, clock, settings.security_hosts, locale=locale)
    osv = OsvCheck(sessions, signals, clock, sorted(settings.bitbucket_read_tokens), scanner, locale=locale)
    intel = IntelCheck(sessions, signals, clock, HttpIntel(client, locale), locale=locale)
    images = ImageUpdatesCheck(
        sessions, clock, settings.security_hosts, HttpRegistry(client, locale), coolify, locale=locale
    )
    lynis = LynisCheck(sessions, signals, clock, settings.security_hosts, locale=locale)
    crowdsec = CrowdSecCheck(sessions, signals, clock, settings.security_hosts, locale=locale)
    ssh = SshLoginCheck(
        sessions,
        signals,
        chat,
        clock,
        settings.security_hosts,
        known_users=settings.ssh_known_users,
        any_time_users=settings.ssh_any_time_users,
        known_keys=settings.ssh_known_keys,
        locale=locale,
    )
    checks: list[Check] = [patches, reboots, backup, findings, trivy, osv, intel, images, lynis, crowdsec, ssh]
    daily = [
        Section(locale.t("security.section.vulns"), (findings, intel, trivy, osv)),
        Section(locale.t("security.section.patches"), (patches, reboots)),
        Section(locale.t("security.section.backup"), (backup,)),
    ]
    weekly = [
        Section(locale.t("security.section.vulns"), (findings,)),
        Section(locale.t("security.section.hardening"), (lynis,)),
        Section(locale.t("security.section.attacks"), (crowdsec, ssh)),
        Section(locale.t("security.section.updates"), (images,)),
    ]
    return SecurityService(sessions, signals, clock, checks, daily=daily, weekly=weekly, locale=locale), reboots
