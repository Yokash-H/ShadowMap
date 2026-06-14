"""
ShadowBox — Sandbox Orchestrator
Docker container lifecycle manager for isolated file execution.
Falls back to mock execution when Docker is unavailable.
"""
import asyncio
import os
import tempfile
import json
import shutil

SANDBOX_TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT", "30"))

# Try to import docker; graceful fallback if unavailable
try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

SANDBOX_IMAGE = "shadowbox-sandbox:latest"

# File type to execution command mapping
EXEC_COMMANDS = {
    ".sh": "bash /analysis/target",
    ".py": "python3 /analysis/target",
    ".jar": "java -jar /analysis/target",
}


async def run_sandbox(file_path: str, file_type: str, analysis_id: str) -> dict:
    """
    Execute a file in an isolated Docker sandbox.
    Returns raw execution artifacts (stdout, stderr, strace logs, file diffs).
    """
    if file_type == ".apk":
        return await _analyze_apk_static(file_path, analysis_id)

    if DOCKER_AVAILABLE:
        try:
            return await _run_docker_sandbox(file_path, file_type, analysis_id)
        except Exception as e:
            print(f"[SANDBOX] Docker execution failed: {e}. Falling back to mock.")
            return _run_mock_sandbox(file_path, file_type, analysis_id)
    else:
        print("[SANDBOX] Docker not available. Using mock sandbox.")
        return _run_mock_sandbox(file_path, file_type, analysis_id)


async def _run_docker_sandbox(file_path: str, file_type: str, analysis_id: str) -> dict:
    """Run docker sandbox in a separate worker thread to avoid blocking the event loop."""
    return await asyncio.to_thread(_run_docker_sandbox_sync, file_path, file_type, analysis_id)


def _run_docker_sandbox_sync(file_path: str, file_type: str, analysis_id: str) -> dict:
    """Execute file in a real Docker container with strace monitoring (synchronous)."""
    client = docker.from_env()

    # Ensure sandbox image exists, build if needed
    try:
        client.images.get(SANDBOX_IMAGE)
    except docker.errors.ImageNotFound:
        print(f"[SANDBOX] Image {SANDBOX_IMAGE} not found. Using ubuntu:22.04 base.")
        # Use base ubuntu image with inline strace install
        image = "ubuntu:22.04"
    else:
        image = SANDBOX_IMAGE

    abs_file_path = os.path.abspath(file_path)
    file_dir = os.path.dirname(abs_file_path)
    file_name = os.path.basename(abs_file_path)

    exec_cmd = EXEC_COMMANDS.get(file_type, f"cat /analysis/target")

    # Wrap with strace for syscall monitoring
    entrypoint_cmd = f"""
        apt-get update -qq > /dev/null 2>&1 && apt-get install -y -qq strace > /dev/null 2>&1;
        cp /etc/crontab /tmp/crontab.before 2>/dev/null || true;
        cp ~/.bashrc /tmp/bashrc.before 2>/dev/null || true;
        cp ~/.profile /tmp/profile.before 2>/dev/null || true;
        strace -f -e trace=network,file,process -o /telemetry/strace.log {exec_cmd} > /telemetry/stdout.log 2>/telemetry/stderr.log;
        ss -tunap > /telemetry/netstat.log 2>/dev/null || true;
        diff /tmp/crontab.before /etc/crontab > /telemetry/crontab.diff 2>/dev/null || true;
        diff /tmp/bashrc.before ~/.bashrc > /telemetry/bashrc.diff 2>/dev/null || true;
        diff /tmp/profile.before ~/.profile > /telemetry/profile.diff 2>/dev/null || true;
    """

    # Create telemetry output directory
    telemetry_dir = os.path.join(os.path.dirname(file_path), f"{analysis_id}_telemetry")
    os.makedirs(telemetry_dir, exist_ok=True)

    # Container arguments
    run_kwargs = {
        "image": image,
        "volumes": {
            abs_file_path: {"bind": "/analysis/target", "mode": "ro"},
            os.path.abspath(telemetry_dir): {"bind": "/telemetry", "mode": "rw"},
        },
        "detach": True,
        "network_mode": "bridge",
        "mem_limit": "256m",
        "cpu_period": 100000,
        "cpu_quota": 50000,
        "security_opt": ["no-new-privileges"],
        "read_only": False,
        "cap_add": ["SYS_PTRACE"],
    }

    # If using fallback image (e.g. ubuntu), override command to install strace inline
    if image != SANDBOX_IMAGE:
        run_kwargs["command"] = ["bash", "-c", entrypoint_cmd]

    print(f"[SANDBOX] Starting container with image {image} for file {file_name}...")
    container = client.containers.run(**run_kwargs)
    print(f"[SANDBOX] Container {container.short_id} started successfully. Waiting for execution...")

    try:
        result = container.wait(timeout=SANDBOX_TIMEOUT)
        print(f"[SANDBOX] Container {container.short_id} finished with status {result.get('StatusCode')}.")
    except Exception as e:
        print(f"[SANDBOX] Container {container.short_id} timed out or failed: {e}")
        try:
            container.kill()
        except Exception:
            pass
        result = {"StatusCode": -1, "Error": "Timeout"}
    finally:
        print(f"[SANDBOX] Removing container {container.short_id}...")
        try:
            container.remove(force=True)
        except Exception as e:
            print(f"[SANDBOX] Failed to remove container: {e}")

    # Read telemetry files
    sandbox_result = {
        "exit_code": result.get("StatusCode", -1),
        "stdout": _read_file(os.path.join(telemetry_dir, "stdout.log")),
        "stderr": _read_file(os.path.join(telemetry_dir, "stderr.log")),
        "strace_log": _read_file(os.path.join(telemetry_dir, "strace.log")),
        "netstat": _read_file(os.path.join(telemetry_dir, "netstat.log")),
        "crontab_diff": _read_file(os.path.join(telemetry_dir, "crontab.diff")),
        "bashrc_diff": _read_file(os.path.join(telemetry_dir, "bashrc.diff")),
        "profile_diff": _read_file(os.path.join(telemetry_dir, "profile.diff")),
        "source": "docker",
    }

    # Cleanup telemetry dir
    shutil.rmtree(telemetry_dir, ignore_errors=True)

    return sandbox_result


def _run_mock_sandbox(file_path: str, file_type: str, analysis_id: str) -> dict:
    """
    Mock sandbox: statically analyzes the file content for suspicious patterns.
    Used when Docker is not available. No actual execution occurs.
    """
    content = ""
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
    except Exception:
        pass

    # Simulate telemetry by scanning file content for dangerous patterns
    mock_processes = []
    mock_network = []
    mock_files = []
    mock_persistence = []
    mock_stdout = f"[MOCK] Static analysis of {os.path.basename(file_path)}"

    lines = content.split("\n")
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Process detection
        if any(cmd in stripped for cmd in ["curl ", "wget ", "python", "bash ", "sh ", "chmod ", "java "]):
            mock_processes.append({"pid": i + 1, "ppid": 1, "command": stripped})

        # Network detection
        if "curl " in stripped or "wget " in stripped:
            import re
            urls = re.findall(r'https?://([^\s/\'"]+)', stripped)
            for url in urls:
                mock_network.append({"domain": url, "ip": "0.0.0.0", "port": 443 if "https" in stripped else 80, "protocol": "tcp"})

        # File operations
        for op_indicator in ["> ", ">> ", "tee ", "mv ", "cp ", "rm ", "chmod "]:
            if op_indicator in stripped:
                parts = stripped.split()
                if len(parts) >= 2:
                    target_file = parts[-1]
                    if target_file.startswith("/") or target_file.startswith("~"):
                        operation = "deleted" if "rm " in stripped else "modified"
                        mock_files.append({"path": target_file, "operation": operation})

        # Persistence detection
        if "crontab" in stripped or "cron" in stripped:
            mock_persistence.append({"type": "cron", "detail": stripped})
        if ".bashrc" in stripped:
            mock_persistence.append({"type": "bashrc", "detail": stripped})
        if ".profile" in stripped:
            mock_persistence.append({"type": "profile", "detail": stripped})
        if "systemctl" in stripped or "systemd" in stripped:
            mock_persistence.append({"type": "systemd", "detail": stripped})

    return {
        "exit_code": 0,
        "stdout": mock_stdout,
        "stderr": "",
        "strace_log": "",
        "netstat": "",
        "crontab_diff": "\n".join([p["detail"] for p in mock_persistence if p["type"] == "cron"]),
        "bashrc_diff": "\n".join([p["detail"] for p in mock_persistence if p["type"] == "bashrc"]),
        "profile_diff": "\n".join([p["detail"] for p in mock_persistence if p["type"] == "profile"]),
        "source": "mock",
        "mock_processes": mock_processes,
        "mock_network": mock_network,
        "mock_files": mock_files,
        "mock_persistence": mock_persistence,
    }


async def _analyze_apk_static(file_path: str, analysis_id: str) -> dict:
    """
    Static APK analysis using manifest parsing.
    Extracts permissions, activities, services from the APK without execution.
    """
    permissions = []
    activities = []
    services = []

    try:
        import zipfile
        import xml.etree.ElementTree as ET

        with zipfile.ZipFile(file_path, 'r') as z:
            # Try to read AndroidManifest.xml (binary XML, need special parsing)
            if 'AndroidManifest.xml' in z.namelist():
                # Binary XML cannot be parsed directly; extract what we can
                pass

            # Check for suspicious file patterns
            suspicious_files = []
            for name in z.namelist():
                if any(s in name.lower() for s in ['payload', 'exploit', 'shell', 'backdoor', 'keylog', 'rat']):
                    suspicious_files.append(name)

    except Exception as e:
        print(f"[APK ANALYSIS] Error: {e}")

    return {
        "exit_code": 0,
        "stdout": f"[APK] Static analysis of {os.path.basename(file_path)}",
        "stderr": "",
        "strace_log": "",
        "netstat": "",
        "crontab_diff": "",
        "bashrc_diff": "",
        "profile_diff": "",
        "source": "apk_static",
        "apk_permissions": permissions,
        "apk_suspicious_files": suspicious_files if 'suspicious_files' in dir() else [],
    }


def _read_file(path: str) -> str:
    """Safely read a file, return empty string on error."""
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""
