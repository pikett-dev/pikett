# Host collector for the security checks

`ops-collect.py` runs on every monitored server (app servers and the ops server itself) as root from systemd timers. It only reads. It sends the raw data over Tailscale to `POST /api/v1/host-reports` of the ops service, with a token that belongs to that one server (a server cannot report for another), and changes nothing on the server. The evaluation (alarms, findings, reports) happens in the ops service (`app/security/`). Standard library only.

If one read fails, the report arrives as `{"error": ...}` and the ops service reports it. If no report arrives at all, the ops service opens a P2 `HostReportMissing` once the deadline of that kind has passed. A broken collector does not stay silent.

| Timer | Time (local) | List in `/etc/ops-collect.env` |
|---|---|---|
| `ops-collect-hourly` | hourly at :17 | `HOURLY_KINDS` |
| `ops-collect-daily` | 03:40, after the patch window | `DAILY_KINDS` |
| `ops-collect-weekly` | Sunday 04:30 | `WEEKLY_KINDS` |

| Kind | What is read | Deadline for `HostReportMissing` |
|---|---|---|
| `patches` | unattended-upgrades logs, `needrestart -b -r l`, `reboot-required`, `HEALTH_URLS` | 26 h |
| `images` | running containers with image and `RepoDigests` | 26 h |
| `trivy` | a Trivy scan of every running image against the trivy-server on the ops server | 26 h |
| `crowdsec` | `cscli alerts list --since 25h` and `cscli decisions list`, shortened | 26 h |
| `ssh` | successful SSH logins of the last 25 h from journald | 26 h |
| `lynis` | `lynis audit system --cronjob`: score, warnings and suggestions from `/var/log/lynis-report.dat` | 8 days |

Backups are not read by the collector. The ops service checks them every 30 minutes through the Coolify API (`BACKUP_DATABASES`, `COOLIFY_TOKEN`), because Coolify uploads dumps to S3 and removes the local copies.

## Rollout

**Before:** no collector on the servers. The ops service accepts no host reports (`HOST_REPORT_TOKENS` unset) and expects none (`SECURITY_HOSTS` empty).

**Steps:**

1. Create one token per server (`openssl rand -hex 32`) and set them in `ops-service.env` on the ops server: `HOST_REPORT_TOKENS={"app-1":"...","ops-server":"..."}`, `SECURITY_HOSTS=["app-1","ops-server"]`. Restart the ops service.
2. Copy and install, for each server, from your own machine:
   ```
   rsync -az deploy/host-agent/ root@app-1:/opt/ops-collect-src/
   ssh root@app-1 /opt/ops-collect-src/install.sh   # creates /etc/ops-collect.env and stops
   ssh root@app-1 vi /etc/ops-collect.env            # OPS_URL, token, HOST_NAME, kind lists
   ssh root@app-1 /opt/ops-collect-src/install.sh   # installs the timers and runs once
   ```
3. Check: `journalctl -u ops-collect-hourly -n 20` shows no error and the incident page shows no new `HostReportMissing`.

**Undo:** `systemctl disable --now ops-collect-hourly.timer ops-collect-daily.timer ops-collect-weekly.timer`, then `rm /etc/systemd/system/ops-collect-* /etc/ops-collect.env && rm -r /opt/ops-collect && systemctl daemon-reload`. Empty `SECURITY_HOSTS` in the ops service, or it reports the missing reports.

**Expected result:** every day at 03:40 the reports `patches`, `images`, `ssh`, `crowdsec` and `trivy` per server, `lynis` on Sundays. If one is missing, a P2 `HostReportMissing` opens.

## Patch window

The files in `patching/` restrict unattended-upgrades to the security archives (`#clear` removes the release archive from Ubuntu's default list), set the window to 03:00 daily (package lists at 02:30) and let needrestart restart affected services without asking. `docker`, `containerd` and `tailscaled` are excluded: restarting them would stop every application container or cut the connection. Those services show up in the daily digest as "needs a manual restart". App servers never reboot on their own; a pending kernel reboot becomes a question in Slack. Hosts in `SELF_REBOOTING_HOSTS` (normally the ops server) reboot on Sunday at 05:00 when `reboot-required` exists.

The same files exist three times: in `patching/` for existing servers, as `patching/cloud-init-fragment.yaml` for new servers, and built into `deploy/ops-server/cloud-init.yaml`. `tests/test_patching_files.py` fails when the three drift apart.

**Before:** Ubuntu's default unattended-upgrades (release and security archives, random time); needrestart asks interactively.

**Steps:**

1. On each server: `rsync -az deploy/host-agent/ root@<server>:/opt/ops-collect-src/` and `ssh root@<server> /opt/ops-collect-src/patching/install-patching.sh`. At the end the script prints the allowed archives (only `-security`) and the new timer times.
2. In `/etc/ops-collect.env` on each server, add `patches` to `DAILY_KINDS` and set `HEALTH_URLS` (app servers: the public health URLs of your applications; ops server: `http://<tailscale-ip>:8030/health`).
3. For new servers, copy the entries from `patching/cloud-init-fragment.yaml` into your cloud-init under `write_files` and add `needrestart` to `packages`.
4. Next morning: the daily digest has a "Patches (...)" line per server.

**Undo:** `rm /etc/apt/apt.conf.d/52ops-unattended-upgrades /etc/needrestart/conf.d/ops.conf /etc/systemd/system/apt-daily*.timer.d/ops-window.conf && systemctl daemon-reload && systemctl restart apt-daily.timer apt-daily-upgrade.timer`. Ubuntu's defaults apply again. `20auto-upgrades` can stay.

**Expected result:** security updates only, daily at 03:00. At 03:40 the collector reports what was patched and restarted. A failed patch, or a health URL that is not 2xx afterwards, opens a P1 (`PatchFailed`, `PatchHealthRed`). A window that did not run opens a P2 `PatchWindowMissed`.

## Lynis

**Steps:** on each server `apt-get install -y lynis` and `WEEKLY_KINDS=lynis` in `/etc/ops-collect.env`. Run it once by hand with `systemctl start ops-collect-weekly.service` (takes a few minutes), then check `journalctl -u ops-collect-weekly -n 20`.

**Undo:** `apt-get remove lynis` and empty `WEEKLY_KINDS`. Stored scores stay in the ops service.

**Expected result:** one run per server on Sunday at 04:30. Monday's weekly report shows the score, the change from last week, the trend of the last 6 weeks and new warnings. A failed run opens a P2 `LynisFailed`, a missing one `HostReportMissing` after 8 days. Lynis only reads.

## CrowdSec and SSH logins

CrowdSec runs on every server and bans automatically through the iptables bouncer in the chains `INPUT` and `DOCKER-USER` (Docker-published ports such as a reverse proxy on 80/443 do not pass `INPUT`). CrowdSec's local API listens on `127.0.0.1:8086` (`crowdsec/config.yaml.local`), because Coolify's Traefik already uses 8080. The whitelist `crowdsec/tailscale-whitelist.yaml` exempts the Tailscale network (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) from every ban and is installed before the bouncer.

**Steps:**

1. App server: `ssh root@app-1 /opt/ops-collect-src/crowdsec/install-crowdsec.sh --web`. The script adds CrowdSec's package repository, installs `crowdsec` with the `linux` and `sshd` collections, reads the access log of `coolify-proxy` with `--web` (enable `--accesslog=true` on the proxy in Coolify) and installs the bouncer last.
2. Ops server: the same without `--web`.
3. Check: `cscli parsers list | grep tailscale` shows the whitelist, `cscli bouncers list` the bouncer. Log in over SSH from a machine in your tailnet to confirm you are not locked out.
4. Add `ssh crowdsec` to `DAILY_KINDS` in `/etc/ops-collect.env`.
5. fail2ban can stay; banning twice does no harm.

**Undo:** `apt-get remove crowdsec-firewall-bouncer-iptables crowdsec` removes the bouncer and its rules. Then remove `ssh crowdsec` from `DAILY_KINDS`. Locked out: log in through your provider's console and run `cscli decisions delete --ip <ip>`.

**Expected result:** the weekly report lists detections, the number of addresses, bans and the most frequent scenarios per server. Unusual SSH logins arrive once per report and server as one message in the ops channel, grouped by source, user and key with count and period. If no key in `SSH_KNOWN_KEYS` (see below) applies to a server, a login is unusual when it comes from outside Tailscale, by an unknown user (`SSH_KNOWN_USERS`, default `root` and `deploy`) or between 23:00 and 07:00 (except users in `SSH_ANY_TIME_USERS`). If at least one key applies, every login that does not match a known key (fingerprint, user and network) is unusual: an unknown key, a login without a key, or a known key with the wrong user or from the wrong network. Those get a message of their own per source and key (at most 5 per report, the rest in one more). An entry applies to all servers unless `hosts` names them (`["app-1"]`); a fingerprint may be listed once. If CrowdSec does not answer, a P2 `CrowdSecDown` opens.

`SSH_KNOWN_KEYS` is JSON with a label, the fingerprint (`ssh-keygen -lf ~/.ssh/authorized_keys`), the user and the allowed networks. Example:

```
SSH_KNOWN_KEYS=[{"label":"backup","fingerprint":"SHA256:<fingerprint>","user":"root","networks":["10.0.1.0/24"]},{"label":"admin","fingerprint":"SHA256:<fingerprint>","user":"root","networks":["100.64.0.0/10"]},{"label":"pipeline","fingerprint":"SHA256:<fingerprint>","user":"deploy","networks":["198.51.100.10/32"]}]
```

A known key is never reported from its networks at any time, so keep the networks as narrow as possible: a stolen key used from those networks stays silent.

The collector needs no change: the journal line `Accepted publickey ... ssh2: ED25519 SHA256:...` already carries the fingerprint.
