# RHEL daily security & operational audit (Ansible + AWX)

Read-only audit of ~20-25 RHEL 8/9/10 VMs. Produces PASS / WARNING / FAIL / CRITICAL /
NOT_APPLICABLE / UNKNOWN results, an HTML + CSV + JSON report, and e-mails it.
Follow the SOP for the AWX side (credentials, inventory, project, template, schedule).

## Layout
```
site.yml                       3 plays: register targets -> audit hosts -> build report + e-mail
ansible.cfg  requirements.yml
filter_plugins/audit_filters.py  audit_add / audit_kv / audit_threshold / audit_build_report
group_vars/all.yml             global policy, thresholds, mail recipients   <- edit this first
group_vars/RHEL8|RHEL9|RHEL10.yml   per-version settings (names must equal the AWX group names)
host_vars/<host>.yml           per-server approved baseline (file name = inventory host name)
roles/audit_common             facts + RHEL version + repositories
roles/audit_security           password policy, accounts, SSH, SELinux, firewall, sudo, cron, auth failures
roles/audit_system             disks, inodes, directories, failed units, load/memory/swap, chrony, network, updates, reboot
roles/audit_server_specific    approved services/ports, backups, database, certificates, heartbeat
roles/audit_report             HTML/CSV/JSON + e-mail   (templates/: report.html.j2, report.csv.j2, email_body.html.j2)
inventory/hosts.yml            example inventory for command-line use only (AWX keeps its own)
scripts/                       validate.sh, run-one-host.sh
execution-environment/         optional ansible-builder definition for an air-gapped EE
```

## Intranet deployment checklist
1. Push this directory to the internal Git repository (SOP section 5).
2. Make `community.general` (provides `community.general.mail`) and `ansible.posix` available
   **inside the execution environment** (see `execution-environment/`). AWX only auto-installs
   collections from `collections/requirements.yml`, which is intentionally not shipped so that
   project sync never needs Internet access.
3. The EE must use an ansible-core that can talk to your oldest target. RHEL 8 ships Python 3.6,
   which ansible-core 2.17+ no longer supports on managed nodes: either install `python3.9`+
   on RHEL 8 targets, or use an EE with ansible-core 2.16 or older.
4. Create the AWX objects exactly as in the SOP. The job template needs the SSH machine
   credential and the "RHEL Audit SMTP" custom credential; set `become` (privilege escalation)
   on the job template, the play also sets `become: true`.
5. Edit `group_vars/all.yml` (policy, thresholds, recipients) and the `host_vars/*.yml` files.
   Create one `host_vars/<inventory host name>.yml` per server.
6. Roll out in the phases from the SOP (1 VM -> 3-5 -> 10 -> all). Review every FAIL before
   deciding whether the baseline or the server is wrong.

## Differences from the SOP file tree (on purpose)
* `group_vars/RHEL8.yml` (not `rhel8.yml`): Ansible matches group_vars file names to group names
  case-sensitively, and the AWX groups are `RHEL8/RHEL9/RHEL10`.
* host_vars files are named after the inventory hosts (`RHEL-DB01.yml`), not `server01.yml`.
* A Python filter plugin (`filter_plugins/`) is used instead of long inline dictionaries. Appending a
  result the SOP way still works:
  `audit_results + [{'category': ..., 'check': ..., 'status': ..., 'actual': ..., 'expected': ..., 'finding': ...}]`
  but `audit_results | audit_add('Cat', 'Check', 'PASS', actual, expected, finding)` is shorter and
  sanitises the text.

## How results are decided (key rules)
* Disk: `< warning` PASS, `warning..critical-1` WARNING, `>= critical` CRITICAL. Per-mount overrides:
  `filesystem_thresholds`. Directory checks use the usage of the filesystem that contains the path.
* SSH: every key under `security_baseline.ssh` is compared with the *effective* `sshd -T` value.
* Firewall: explicit ports/services open in any active zone must be in `firewall_baseline` +
  host `expected_ports` + optional `firewall_baseline_extra`.
* Services: running services must be in `expected_services.allowed` (+ common list) unless they match
  `audit.service_ignore_patterns`. `expected_services.required` (default: allowed) must be running.
* Listening ports: non-loopback listeners must be in `expected_ports` + `audit.common_expected_ports`.
* Unreachable host or a host that produced no data -> one UNKNOWN row; the other hosts continue.
* `NOT_APPLICABLE` rows appear when a server has no backup/database/certificate check defined.

## Read-only guarantees and side effects
No package, service, firewall, user, password or configuration changes are made. Side effects are
limited to normal read activity: `dnf check-update` may refresh its metadata cache; `ausearch`,
`journalctl` and `sshd -T` read logs/config. Report files are written only on the controller/EE.

## Extra variables (job template "Extra variables" / `-e`)
`audit_target_group` (default `RHEL`), `audit_history_dir`, `audit_debug_mail=true` (show the e-mail
task output, which may contain secrets), `{"audit": {...}}` is NOT overridable per run - edit group_vars.
Environment variables: `AUDIT_REPORT_DIR`, `AUDIT_HISTORY_DIR` (needs a path exposed to the EE in AWX settings).

## Adding things
* New server: add host + groups in AWX, create `host_vars/<host>.yml`, commit, sync project.
* New global check: add the task to the owning role and append with `audit_add`.
* New server-specific check: put the expectation in host_vars and read it in
  `audit_server_specific` (see the heartbeat check as a pattern).

## Not covered / limitations
Not a CIS benchmark; no OpenSCAP/CVE scanning; failed-login counts depend on journald retention and
rsyslog; password-age data uses `/etc/shadow` metadata only (no hashes are read into results).
