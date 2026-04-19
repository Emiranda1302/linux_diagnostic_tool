"""
Whitelist Module - False Positives for Scanner

Contains whitelists for legitimate binaries, processes, and connections
to filter out false positives from security scans.
"""

# ============================================================================
# SUID BINARIES WHITELIST
# ============================================================================
SUID_WHITELIST = [
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/su",
    "/usr/bin/newgrp",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/gpasswd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/fusermount",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/libexec/openssh/ssh-keysign",
    "/usr/bin/pkexec",
    "/usr/bin/Xvfb",
    "/usr/bin/X",
    "/usr/sbin/cron",
    "/usr/sbin/cupsd",
    "/usr/bin/lppasswd",
    "/usr/libexec/sudo",
    "/usr/sbin/sendmail",
    "/usr/sbin/postfix",
]

# ============================================================================
# CRON WHITELIST
# ============================================================================
CRON_WHITELIST = {
    "suspicious_keywords": [
        "/usr/bin/updatedb",
        "/usr/bin/locate",
        "/usr/sbin/updatedb",
        "/usr/bin/man-db",
        "/usr/lib/man-db/mandb",
        "/usr/bin/backup",
        "/usr/bin/tar",
        "/usr/bin/rsync",
        "/usr/sbin/logrotate",
        "/usr/bin/find",
        "/bin/rm",
        "/bin/sh",
        "/bin/bash",
        "/usr/bin/apt",
        "/usr/bin/apt-get",
        "/usr/bin/yum",
        "/usr/bin/dnf",
        "/usr/bin/curl",
        "/usr/bin/wget",
        "/usr/bin/python",
        "/usr/bin/python3",
    ],
    "safe_users": [
        "root",
        "postgres",
        "mysql",
        "www-data",
        "nginx",
        "apache",
        "mongodb",
        "redis",
        "elasticsearch",
    ],
}

# ============================================================================
# BASHRC WHITELIST
# ============================================================================
BASHRC_WHITELIST = [
    "export PATH=",
    "export HOME=",
    "export USER=",
    "export SHELL=",
    "export LANG=",
    "export LC_",
    "alias ls=",
    "alias ll=",
    "alias la=",
    "alias grep=",
    "alias rm=",
    "alias cp=",
    "alias mv=",
    "function ",
    "set -o",
    "shopt -s",
    "PS1=",
    "PS2=",
    "HISTSIZE=",
    "HISTFILESIZE=",
    "#",
    "source /etc/",
    "source $HOME/",
    ". /etc/",
]

# ============================================================================
# SYSTEM PROCESSES WHITELIST
# ============================================================================
PROCESS_WHITELIST = [
    "kworker",
    "kthreadd",
    "ksoftirqd",
    "kdevtmpfs",
    "watchdog",
    "migration",
    "systemd",
    "systemd-journal",
    "systemd-logind",
    "systemd-udevd",
    "dbus-daemon",
    "NetworkManager",
    "sshd",
    "ssh-agent",
    "cron",
    "anacron",
    "sudo",
    "init",
    "upstart",
    "rsyslogd",
    "auditd",
]

# ============================================================================
# NETWORK CONNECTIONS WHITELIST
# ============================================================================
NETWORK_WHITELIST = {
    "safe_processes": [
        "systemd-resolved",
        "dnsmasq",
        "NetworkManager",
        "wpa_supplicant",
        "dhclient",
        "ntp",
        "chrony",
        "curl",
        "wget",
        "apt",
        "yum",
        "dnf",
        "ssh",
        "git",
        "docker",
        "java",
        "python",
        "node",
        "apache2",
        "nginx",
        "mysql",
        "postgresql",
        "mongodb",
    ],
    "safe_remote_ips": [
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
    ],
    "safe_ports": [
        80, 443, 53, 123, 25, 587, 110, 143, 993, 995,
        22, 20, 21, 9418, 8000, 8080, 8443, 3306, 5432,
        27017, 6379, 9200,
    ]
}

# ============================================================================
# SUSPICIOUS PATHS
# ============================================================================
SUSPICIOUS_PATHS = [
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/run/user",
    "/dev",
]

# ============================================================================
# CRITICAL SYSTEM BINARIES (for hashing)
# ============================================================================
CRITICAL_BINARIES = [
    "/bin/bash",
    "/bin/sh",
    "/bin/ls",
    "/bin/cat",
    "/bin/grep",
    "/usr/bin/sudo",
    "/usr/bin/ssh",
    "/usr/sbin/sshd",
    "/usr/bin/find",
    "/bin/ps",
    "/sbin/init",
]

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def is_suid_suspicious(filepath: str) -> bool:
    """Check if a SUID binary is suspicious"""
    return filepath not in SUID_WHITELIST


def is_cron_suspicious(command: str, user: str = None) -> bool:
    """Check if a cron job is suspicious"""
    if user and user in CRON_WHITELIST["safe_users"]:
        return False
    
    for safe_cmd in CRON_WHITELIST["suspicious_keywords"]:
        if safe_cmd in command:
            return False
    
    return True


def is_bashrc_suspicious(line: str) -> bool:
    """Check if a bashrc line is suspicious"""
    line_lower = line.lower()
    
    for safe_pattern in BASHRC_WHITELIST:
        if safe_pattern.lower() in line_lower:
            return False
    
    return True


def is_process_suspicious(process_name: str) -> bool:
    """Check if a process is suspicious"""
    return process_name not in PROCESS_WHITELIST


def is_connection_suspicious(process_name: str, remote_ip: str, port: int, is_root: bool = False) -> bool:
    """Check if a network connection is suspicious"""
    if process_name in NETWORK_WHITELIST["safe_processes"]:
        return False
    
    if port in NETWORK_WHITELIST["safe_ports"]:
        return False
    
    if remote_ip in NETWORK_WHITELIST["safe_remote_ips"]:
        return False
    
    if is_root and remote_ip not in NETWORK_WHITELIST["safe_remote_ips"]:
        return True
    
    return False
