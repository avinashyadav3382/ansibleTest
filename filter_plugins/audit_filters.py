# -*- coding: utf-8 -*-
"""Helper filters for the RHEL daily audit project.

Pure Python, no third-party dependencies.

  audit_add        append one normalised result to the audit_results list
  audit_kv         parse KEY=VALUE lines (command output) into a dict
  audit_threshold  PASS / WARNING / CRITICAL for a numeric value
  audit_build_report  aggregate every host's results into one report structure
"""
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re

VALID_STATUSES = ("PASS", "WARNING", "FAIL", "CRITICAL", "NOT_APPLICABLE", "UNKNOWN")
# Worst first. Used for sorting and for "worst status of a host".
SEVERITY_ORDER = ["CRITICAL", "FAIL", "WARNING", "UNKNOWN", "PASS", "NOT_APPLICABLE"]
_RANK = dict((s, i) for i, s in enumerate(SEVERITY_ORDER))
ATTENTION = ("CRITICAL", "FAIL", "WARNING", "UNKNOWN")
MAX_TEXT = 1000


def _text(value, limit=MAX_TEXT):
    """Return a single-line, template-safe string."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        value = ", ".join(_text(v, limit) for v in value)
    elif isinstance(value, dict):
        value = ", ".join("%s=%s" % (k, _text(v, limit)) for k, v in value.items())
    value = re.sub(r"\s+", " ", str(value)).strip()
    # Never let command output look like Jinja to a later templating pass.
    value = value.replace("{{", "{ {").replace("{%", "{ %").replace("{#", "{ #")
    if len(value) > limit:
        value = value[: limit - 3] + "..."
    return value


def _status(value):
    value = str(value or "").strip().upper().replace(" ", "_")
    return value if value in VALID_STATUSES else "UNKNOWN"


def _entry(category, check, status, actual="", expected="", finding=""):
    return {
        "category": _text(category, 100),
        "check": _text(check, 200),
        "status": _status(status),
        "actual": _text(actual),
        "expected": _text(expected),
        "finding": _text(finding),
    }


def audit_add(results, category, check, status, actual="", expected="", finding=""):
    """audit_results | audit_add('Disk', 'Filesystem /', 'PASS', '42%', '<80%', 'ok')"""
    out = list(results) if results else []
    out.append(_entry(category, check, status, actual, expected, finding))
    return out


def audit_kv(text):
    """Parse 'KEY=value' lines. Keys must look like identifiers; last one wins."""
    data = {}
    for line in str(text or "").splitlines():
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            data[key] = val.strip()
    return data


def audit_threshold(value, warning, critical):
    """PASS below warning, WARNING from warning, CRITICAL from critical."""
    try:
        value = float(value)
        warning = float(warning)
        critical = float(critical)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if value >= critical:
        return "CRITICAL"
    if value >= warning:
        return "WARNING"
    return "PASS"


def _get(mapping, key, default=None):
    try:
        value = mapping.get(key, default)
    except Exception:  # unreachable host, undefined variable, ...
        return default
    return default if value is None else value


def _zero_counts():
    return dict((s, 0) for s in SEVERITY_ORDER)


def _worst(counts):
    for status in SEVERITY_ORDER:
        if status == "NOT_APPLICABLE":
            continue
        if counts.get(status):
            return status
    return "NOT_APPLICABLE" if counts.get("NOT_APPLICABLE") else "UNKNOWN"


def audit_build_report(hostvars, hosts, title="RHEL audit", generated_utc="", generated_local=""):
    """Aggregate per-host audit_results into one structure used by every template.

    A host that produced no result (unreachable, failed fact gathering, ...) is
    reported as UNKNOWN instead of silently disappearing from the report.
    """
    host_list = sorted(set(str(h) for h in (hosts or [])), key=lambda s: s.lower())
    hosts_out = []
    findings = []
    totals = _zero_counts()
    host_status_counts = _zero_counts()

    for name in host_list:
        try:
            hv = hostvars[name]
        except Exception:
            hv = {}
        raw = _get(hv, "audit_results", None)
        info = _get(hv, "audit_host_info", None) or {}
        reachable = bool(raw)
        results = []
        for item in raw or []:
            get = item.get if hasattr(item, "get") else (lambda k, d="": d)
            results.append(
                _entry(
                    get("category", ""),
                    get("check", ""),
                    get("status", "UNKNOWN"),
                    get("actual", ""),
                    get("expected", ""),
                    get("finding", ""),
                )
            )
        if not reachable:
            results = [
                _entry(
                    "Connectivity",
                    "Audit execution",
                    "UNKNOWN",
                    "No audit result produced",
                    "Host reachable and audited",
                    "No audit result produced for this server (unreachable, "
                    "authentication/sudo failure, or the audit did not run)",
                )
            ]
        counts = _zero_counts()
        for r in results:
            counts[r["status"]] += 1
            totals[r["status"]] += 1
        status = _worst(counts)
        host_status_counts[status] += 1
        address = _text(_get(info, "address", "") or _get(hv, "ansible_host", name), 100)
        anchor = re.sub(r"[^A-Za-z0-9_-]", "-", name)
        hosts_out.append(
            {
                "name": name,
                "anchor": anchor,
                "address": address,
                "hostname": _text(_get(info, "hostname", ""), 100),
                "fqdn": _text(_get(info, "fqdn", ""), 200),
                "ip_addresses": _text(_get(info, "ip_addresses", ""), 200),
                "os": _text(_get(info, "os", "unknown"), 200),
                "kernel": _text(_get(info, "kernel", ""), 100),
                "roles": _text(_get(info, "roles", ""), 200),
                "groups": _text(_get(info, "groups", ""), 300),
                "reachable": reachable,
                "status": status,
                "counts": counts,
                "results": results,
            }
        )
        for r in results:
            f = dict(r)
            f["host"] = name
            f["address"] = address
            f["anchor"] = anchor
            findings.append(f)

    attention = [f for f in findings if f["status"] in ATTENTION]
    attention.sort(key=lambda f: (_RANK[f["status"]], f["host"].lower()))

    overall = "UNKNOWN"
    if hosts_out:
        overall = _worst(
            dict((s, sum(1 for h in hosts_out if h["status"] == s)) for s in SEVERITY_ORDER)
        )

    return {
        "title": _text(title, 200),
        "generated_utc": _text(generated_utc, 100),
        "generated_local": _text(generated_local, 100),
        "severity_order": SEVERITY_ORDER,
        "summary": {
            "hosts_total": len(hosts_out),
            "hosts_without_data": sum(1 for h in hosts_out if not h["reachable"]),
            "hosts_clean": sum(1 for h in hosts_out if h["status"] in ("PASS", "NOT_APPLICABLE")),
            "checks_total": len(findings),
            "overall": overall,
            "counts": totals,
            "host_status_counts": host_status_counts,
        },
        "hosts": hosts_out,
        "findings": findings,
        "attention": attention,
    }


class FilterModule(object):
    def filters(self):
        return {
            "audit_add": audit_add,
            "audit_kv": audit_kv,
            "audit_threshold": audit_threshold,
            "audit_build_report": audit_build_report,
        }
