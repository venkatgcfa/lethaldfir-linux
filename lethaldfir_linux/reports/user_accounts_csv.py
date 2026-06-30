"""
reports.user_accounts_csv
=========================

Writes ``user_accounts.csv`` from ``case.artifacts['local_users']``.

Columns
-------
username, uid, gid, gecos, home, shell, password_status, hash_algorithm,
password_last_changed, account_expires, min_days, max_days, warn_days,
inactive_days, never_expires, primary_groups, supplementary_groups,
is_privileged, is_service_account, has_interactive_shell, anomalies,
passwd_file
"""

from __future__ import annotations

import csv
from pathlib import Path

from ..core.utils import neutralize_formula as _nf


FIELDS = [
    "username", "uid", "gid", "gecos", "home", "shell",
    "password_status", "hash_algorithm",
    "password_last_changed", "account_expires",
    "min_days", "max_days", "warn_days", "inactive_days",
    "never_expires",
    "supplementary_groups",
    "is_privileged", "is_service_account", "has_interactive_shell",
    "anomalies", "passwd_file",
]


def write_user_accounts_csv(case, path) -> Path:
    path = Path(path)
    users = case.artifacts.get("local_users") or []

    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        for u in sorted(users, key=lambda x: (x.get("uid") or 99999, x.get("name") or "")):
            grps = u.get("groups") or []
            row = {
                "username":             u.get("name", ""),
                "uid":                  u.get("uid", ""),
                "gid":                  u.get("gid", ""),
                "gecos":                u.get("gecos", ""),
                "home":                 u.get("home", ""),
                "shell":                u.get("shell", ""),
                "password_status":      u.get("password_status") or "",
                "hash_algorithm":       u.get("hash_algorithm") or "",
                "password_last_changed":u.get("password_last_changed") or "",
                "account_expires":      u.get("account_expires") or "",
                "min_days":             u.get("min_days") or "",
                "max_days":             u.get("max_days") or "",
                "warn_days":            u.get("warn_days") or "",
                "inactive_days":        u.get("inactive_days") or "",
                "never_expires":        u.get("never_expires"),
                "supplementary_groups": ",".join(grps),
                "is_privileged":        u.get("is_privileged"),
                "is_service_account":   u.get("is_service_account"),
                "has_interactive_shell":u.get("has_interactive_shell"),
                "anomalies":            u.get("anomalies", ""),
                "passwd_file":          u.get("passwd_file", ""),
            }
            w.writerow({k: _nf(v) for k, v in row.items()})
    return path
