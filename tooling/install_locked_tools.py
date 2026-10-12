#!/usr/bin/env python3
"""Install SHA-locked official Linux releases for the actual target CPU."""
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

MACHINES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
ELF_MACHINES = {"amd64": 62, "arm64": 183}


def runtime_arch(target=None, machine=None):
    if platform.system() != "Linux":
        raise ValueError("Linux is required")
    actual = MACHINES.get((machine or platform.machine()).lower())
    if actual is None:
        raise ValueError("unsupported CPU: " + (machine or platform.machine()))
    requested = target or os.environ.get("TARGETARCH") or actual
    if requested not in ELF_MACHINES or requested != actual:
        raise ValueError(f"target CPU {requested} differs from runtime CPU {actual}")
    return actual


def verify_elf(path, arch):
    path = Path(path).resolve(strict=True)
    with path.open("rb") as source:
        header = source.read(20)
    if len(header) < 20 or header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
        raise ValueError("expected 64-bit little-endian ELF: " + str(path))
    machine = struct.unpack("<H", header[18:20])[0]
    if machine != ELF_MACHINES[arch]:
        raise ValueError(f"ELF CPU differs from {arch}: {path} (machine={machine})")


def validate_lock(lock):
    if lock.get("schema_version") != 2 or set(lock.get("platforms", [])) != {"linux/amd64", "linux/arm64"}:
        raise ValueError("both Linux CPUs must be present in schema 2")
    for tool in lock["tools"]:
        if set(tool.get("artifacts", {})) != {"amd64", "arm64"}:
            raise ValueError("both CPU artifacts required: " + tool["name"])
        for artifact in tool["artifacts"].values():
            if not artifact["url"].startswith("https://") or not re.fullmatch("[0-9a-f]{64}", artifact["sha256"]):
                raise ValueError("invalid URL or SHA lock: " + tool["name"])


def safe_member(name):
    p = Path(name)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError("unsafe archive member: " + name)


def install_record(record, artifact, arch, work):
    dest = work / record["name"]
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(artifact["url"], timeout=120) as response, dest.open("wb") as out:
        while chunk := response.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            out.write(chunk)
    if digest.hexdigest() != artifact["sha256"]:
        raise ValueError("release SHA differs from lock: " + record["name"])
    if "bytes" in artifact and size != artifact["bytes"]:
        raise ValueError("release length differs from lock: " + record["name"])
    target = Path("/usr/local/bin") / record["binary"]
    kind = record["archive"]
    if kind == "raw":
        shutil.copyfile(dest, target)
    elif kind == "zip":
        safe_member(artifact["member"])
        with zipfile.ZipFile(dest) as archive, archive.open(artifact["member"]) as source, target.open("wb") as out:
            shutil.copyfileobj(source, out)
    elif kind == "tar":
        safe_member(artifact["member"])
        with tarfile.open(dest) as archive, archive.extractfile(artifact["member"]) as source, target.open("wb") as out:
            shutil.copyfileobj(source, out)
    elif kind == "deb":
        package_arch = subprocess.check_output(["dpkg-deb", "--field", str(dest), "Architecture"], text=True).strip()
        if package_arch != arch:
            raise ValueError("Debian package CPU differs: " + record["name"])
        subprocess.run(["dpkg", "--install", str(dest)], check=True)
    elif kind == "aws":
        awsdir = work / "aws-unpack"
        awsdir.mkdir()
        with zipfile.ZipFile(dest) as archive:
            for item in archive.infolist():
                safe_member(item.filename)
            archive.extractall(awsdir)
        installer = awsdir / "aws/install"
        installer.chmod(0o755)
        for path in (awsdir / "aws/dist").rglob("*"):
            if path.is_file():
                with path.open("rb") as source:
                    is_elf = source.read(4) == b"\x7fELF"
                if is_elf:
                    verify_elf(path, arch)
                    path.chmod(0o755)
        subprocess.run([str(installer), "--install-dir", "/opt/aws-cli", "--bin-dir", "/usr/local/bin"], check=True)
    elif kind in {"go", "node"}:
        with tarfile.open(dest) as archive:
            for item in archive.getmembers():
                safe_member(item.name)
            archive.extractall("/opt", filter="data")
        node_arch = "x64" if arch == "amd64" else "arm64"
        source = Path("/opt/go/bin") if kind == "go" else Path(f"/opt/node-v{record['version']}-linux-{node_arch}/bin")
        for path in source.iterdir():
            link = Path("/usr/local/bin") / path.name
            if not link.exists():
                link.symlink_to(path)
    else:
        raise ValueError("unknown archive kind: " + kind)
    if kind in {"raw", "tar", "zip"}:
        target.chmod(0o755)
    verify_elf(target, arch)
    print(f"installed {record['name']} {record['version']} linux/{arch}", flush=True)


def main():
    lock = json.loads(Path("/opt/tooling/toolchain.lock.json").read_text())
    validate_lock(lock)
    arch = runtime_arch()
    with tempfile.TemporaryDirectory() as directory:
        for record in lock["tools"]:
            install_record(record, record["artifacts"][arch], arch, Path(directory))


if __name__ == "__main__":
    main()
