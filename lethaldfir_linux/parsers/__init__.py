"""
LethalDFIR Linux Forensics — parser registry.

All parsers inherit from BaseParser and append TimelineEvents / Findings
to the shared Case container.
"""

from .base import BaseParser

from .auth_log import AuthLogParser
from .history_files import HistoryFilesParser
from .cron import CronParser
from .passwd import PasswdParser
from .passwd_backup import PasswdBackupParser
from .ssh import SSHParser
from .sudoers import SudoersParser
from .systemd import SystemdParser
from .audit import AuditParser
from .packages import PackageLogParser
from .wtmp import WtmpParser
from .lastlog import LastlogParser
from .syslog import SyslogParser
from .web_logs import WebLogsParser
from .persistence import PersistenceParser
from .host_metadata import HostMetadataParser

# ---- New parsers ----
from .faillog import FaillogParser
from .at_jobs import AtJobsParser
from .firewall_logs import FirewallLogsParser
from .web_error_logs import WebErrorLogsParser
from .ftp_logs import FtpLogsParser
from .database_logs import DatabaseLogsParser
from .container_logs import ContainerLogsParser
from .samba_logs import SambaLogsParser
from .nfs_exports import NfsExportsParser
from .pam_config import PamConfigParser
from .kernel_modules import KernelModulesParser
from .journald import JournaldParser


# Order matters: HostMetadataParser first so case.host_info is populated
# for downstream parsers/reports. PasswdParser must run before
# PasswdBackupParser so the live account dataset is on the case when the
# diff runs. Other parsers are independent.
ALL_PARSERS = [
    HostMetadataParser,
    PasswdParser,
    PasswdBackupParser,
    SSHParser,
    SudoersParser,
    AuthLogParser,
    SyslogParser,
    JournaldParser,
    WtmpParser,
    LastlogParser,
    FaillogParser,
    HistoryFilesParser,
    CronParser,
    AtJobsParser,
    SystemdParser,
    AuditParser,
    PackageLogParser,
    WebLogsParser,
    WebErrorLogsParser,
    FirewallLogsParser,
    FtpLogsParser,
    DatabaseLogsParser,
    ContainerLogsParser,
    SambaLogsParser,
    NfsExportsParser,
    PamConfigParser,
    KernelModulesParser,
    PersistenceParser,
]


PARSERS_BY_NAME = {cls.name: cls for cls in ALL_PARSERS}


__all__ = [
    "BaseParser",
    "ALL_PARSERS",
    "PARSERS_BY_NAME",
    "AuthLogParser",
    "HistoryFilesParser",
    "CronParser",
    "PasswdParser",
    "PasswdBackupParser",
    "SSHParser",
    "SudoersParser",
    "SystemdParser",
    "AuditParser",
    "PackageLogParser",
    "WtmpParser",
    "LastlogParser",
    "SyslogParser",
    "WebLogsParser",
    "PersistenceParser",
    "HostMetadataParser",
    # New parsers
    "FaillogParser",
    "AtJobsParser",
    "FirewallLogsParser",
    "WebErrorLogsParser",
    "FtpLogsParser",
    "DatabaseLogsParser",
    "ContainerLogsParser",
    "SambaLogsParser",
    "NfsExportsParser",
    "PamConfigParser",
    "KernelModulesParser",
    "JournaldParser",
]
