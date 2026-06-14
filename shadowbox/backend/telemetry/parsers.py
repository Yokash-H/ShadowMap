"""
ShadowBox — Telemetry Parsers
Parse strace logs and system diffs into structured data.
"""
import re


def parse_strace_processes(strace_log: str) -> list:
    """Extract process creation events from strace log."""
    processes = []
    seen = set()

    # Match execve calls: execve("/bin/bash", ["bash", "script.sh"], ...)
    execve_pattern = re.compile(
        r'(\d+)\s+execve\("([^"]+)",\s*\[([^\]]*)\]'
    )
    for match in execve_pattern.finditer(strace_log):
        pid = int(match.group(1))
        binary = match.group(2)
        args_raw = match.group(3)
        # Clean up args
        args = re.findall(r'"([^"]*)"', args_raw)
        command = " ".join(args) if args else binary

        key = (pid, command)
        if key not in seen:
            seen.add(key)
            processes.append({"pid": pid, "ppid": 0, "command": command})

    # Match clone/fork for parent-child relationships
    clone_pattern = re.compile(r'(\d+)\s+clone\(.*\)\s*=\s*(\d+)')
    pid_parent_map = {}
    for match in clone_pattern.finditer(strace_log):
        parent_pid = int(match.group(1))
        child_pid = int(match.group(2))
        pid_parent_map[child_pid] = parent_pid

    # Update ppid references
    for proc in processes:
        if proc["pid"] in pid_parent_map:
            proc["ppid"] = pid_parent_map[proc["pid"]]

    return processes


def parse_strace_network(strace_log: str) -> list:
    """Extract network connection events from strace log."""
    network = []
    seen = set()

    # Match connect() calls with IPv4: connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, ...)
    connect_pattern = re.compile(
        r'connect\(\d+,\s*\{.*?sin_port=htons\((\d+)\).*?sin_addr=inet_addr\("([^"]+)"\)'
    )
    for match in connect_pattern.finditer(strace_log):
        port = int(match.group(1))
        ip = match.group(2)
        key = (ip, port)
        if key not in seen:
            seen.add(key)
            network.append({
                "domain": None,
                "ip": ip,
                "port": port,
                "protocol": "tcp"
            })

    # Match DNS resolution from strace (getaddrinfo etc.)
    dns_pattern = re.compile(r'getaddrinfo\("([^"]+)"')
    for match in dns_pattern.finditer(strace_log):
        domain = match.group(1)
        # Try to associate with existing network entries or create new one
        found = False
        for entry in network:
            if entry["domain"] is None:
                entry["domain"] = domain
                found = True
                break
        if not found:
            network.append({
                "domain": domain,
                "ip": "0.0.0.0",
                "port": 0,
                "protocol": "tcp"
            })

    return network


def parse_strace_files(strace_log: str) -> list:
    """Extract file system operations from strace log."""
    files = []
    seen = set()

    # Paths to ignore (system noise)
    ignore_prefixes = [
        "/proc/", "/sys/", "/dev/", "/lib/", "/usr/lib/",
        "/etc/ld.so", "/etc/nsswitch", "/etc/passwd",
        "/tmp/strace", "/telemetry/"
    ]

    # Match open/openat with write flags
    open_write_pattern = re.compile(
        r'(?:open|openat)\(.*?"([^"]+)".*?(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)'
    )
    for match in open_write_pattern.finditer(strace_log):
        path = match.group(1)
        if any(path.startswith(p) for p in ignore_prefixes):
            continue
        if path not in seen:
            seen.add(path)
            flags = match.group(2)
            operation = "created" if "O_CREAT" in flags else "modified"
            files.append({"path": path, "operation": operation})

    # Match unlink (file deletion)
    unlink_pattern = re.compile(r'unlink(?:at)?\(.*?"([^"]+)"')
    for match in unlink_pattern.finditer(strace_log):
        path = match.group(1)
        if any(path.startswith(p) for p in ignore_prefixes):
            continue
        if path not in seen:
            seen.add(path)
            files.append({"path": path, "operation": "deleted"})

    # Match rename
    rename_pattern = re.compile(r'rename\("([^"]+)",\s*"([^"]+)"\)')
    for match in rename_pattern.finditer(strace_log):
        old_path = match.group(1)
        new_path = match.group(2)
        if new_path not in seen:
            seen.add(new_path)
            files.append({"path": new_path, "operation": "modified"})

    return files


def parse_persistence_diffs(crontab_diff: str, bashrc_diff: str, profile_diff: str) -> list:
    """Parse diff output for persistence indicators."""
    persistence = []

    if crontab_diff.strip():
        # Extract added lines from diff
        for line in crontab_diff.split("\n"):
            if line.startswith(">") or line.startswith("+"):
                detail = line.lstrip(">+").strip()
                if detail:
                    persistence.append({"type": "cron", "detail": detail})

    if bashrc_diff.strip():
        for line in bashrc_diff.split("\n"):
            if line.startswith(">") or line.startswith("+"):
                detail = line.lstrip(">+").strip()
                if detail:
                    persistence.append({"type": "bashrc", "detail": detail})

    if profile_diff.strip():
        for line in profile_diff.split("\n"):
            if line.startswith(">") or line.startswith("+"):
                detail = line.lstrip(">+").strip()
                if detail:
                    persistence.append({"type": "profile", "detail": detail})

    return persistence
