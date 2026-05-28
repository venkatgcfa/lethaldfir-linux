"""
LethalDFIR Linux Forensics
==========================

Offline Linux DFIR triage and timeline tool.

Parses logs, configuration files, persistence locations, and binary
accounting files from a mounted disk image, an extracted directory tree,
or a forensic collector ZIP, and produces:

  * A structured JSON evidence bundle
  * A super-timeline (CSV) covering log entries, package installs,
    auth events, file MAC times, cron entries, etc.
  * A human-readable HTML investigation report with findings.

Author : LethalDFIR
License: MIT
"""

__version__ = "1.0.0"
__author__ = "LethalDFIR"
__brand__ = "LethalDFIR Linux Forensics"
