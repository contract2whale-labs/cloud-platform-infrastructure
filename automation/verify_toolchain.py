#!/usr/bin/env python3
"""Check CPU, ELF binaries, tool versions and hash-locked Python versions."""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from importlib.metadata import distribution, version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tooling"))
from install_locked_tools import runtime_arch, validate_lock, verify_elf

COMMANDS = {
    "gh": ["gh", "--version"],
    "session-manager-plugin": ["session-manager-plugin", "--version"],
    "terraform": ["terraform", "version", "-json"],
    "helm": ["helm", "version", "--short"],
    "kubectl": ["kubectl", "version", "--client", "-o", "json"],
    "kustomize": ["kustomize", "version"],
    "awscli": ["aws", "--version"],
    "argocd": ["argocd", "version", "--client", "--short"],
    "argo-rollouts": ["kubectl-argo-rollouts", "version", "--short"],
    "kubeconform": ["kubeconform", "-v"],
    "cosign": ["cosign", "version"],
    "syft": ["syft", "version"],
    "trivy": ["trivy", "--version"],
    "istioctl": ["istioctl", "version", "--remote=false"],
    "nodejs": ["node", "--version"],
    "golang": ["go", "version"],
    "kyverno": ["kyverno", "version"],
    "actionlint": ["actionlint", "-version"],
    "tflint": ["tflint", "--version"],
    "zizmor": ["zizmor", "--version"],
    "yq": ["yq", "--version"],
    "promtool": ["promtool", "--version"],
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-arch", choices=["amd64", "arm64"])
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") == "true" and not re.fullmatch(
        r"ghcr\.io/[a-z0-9._-]+/platform-toolchain@sha256:[0-9a-f]{64}",
        os.environ.get("TOOLCHAIN_IMAGE", ""),
    ):
        raise SystemExit("CI toolchain must use the reviewed immutable image digest")
    lock = json.loads((ROOT / "tooling/toolchain.lock.json").read_text())
    validate_lock(lock)
    arch = runtime_arch(target=args.expected_arch)
    if sys.version.split()[0] != lock["python"]:
        raise SystemExit("wrong Python version")
    verify_elf(sys.executable, arch)
    print("platform linux/" + arch, flush=True)
    for tool in lock["tools"]:
        binary = shutil.which(tool["binary"])
        if binary is None:
            raise SystemExit("missing tool: " + tool["name"])
        verify_elf(binary, arch)
        result = subprocess.run(COMMANDS[tool["name"]], capture_output=True, text=True, check=True)
        if not re.search(r"(?<![0-9])" + re.escape(tool["version"]) + r"(?![0-9])", result.stdout + result.stderr):
            raise SystemExit("wrong tool version: " + tool["name"])
        print(tool["name"] + " " + tool["version"] + " ELF=" + arch, flush=True)
    for name, wanted in re.findall(
        r"^([A-Za-z0-9._-]+)==([^\s\\]+)",
        (ROOT / "tooling/requirements.lock").read_text(),
        re.M,
    ):
        if version(name) != wanted:
            raise SystemExit("wrong Python dependency version: " + name)
        package = distribution(name)
        for entry in package.files or []:
            if str(entry).endswith(".so"):
                verify_elf(package.locate_file(entry), arch)
        print("python-library " + name + " " + wanted, flush=True)


if __name__ == "__main__":
    main()
