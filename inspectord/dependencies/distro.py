"""Distro detection from /etc/os-release. Spec §30.4."""

from __future__ import annotations

import shlex
from enum import StrEnum
from pathlib import Path


class Distro(StrEnum):
    arch = "arch"
    debian = "debian"
    fedora = "fedora"
    opensuse = "opensuse"


class DistroDetectionError(RuntimeError):
    pass


_ID_TO_FAMILY: dict[str, Distro] = {
    "arch": Distro.arch,
    "cachyos": Distro.arch,
    "manjaro": Distro.arch,
    "endeavouros": Distro.arch,
    "garuda": Distro.arch,
    "debian": Distro.debian,
    "ubuntu": Distro.debian,
    "linuxmint": Distro.debian,
    "pop": Distro.debian,
    "fedora": Distro.fedora,
    "rhel": Distro.fedora,
    "centos": Distro.fedora,
    "rocky": Distro.fedora,
    "almalinux": Distro.fedora,
    "opensuse": Distro.opensuse,
    "opensuse-leap": Distro.opensuse,
    "opensuse-tumbleweed": Distro.opensuse,
    "sles": Distro.opensuse,
}

_LIKE_TO_FAMILY: dict[str, Distro] = {
    "arch": Distro.arch,
    "debian": Distro.debian,
    "ubuntu": Distro.debian,
    "fedora": Distro.fedora,
    "rhel": Distro.fedora,
    "suse": Distro.opensuse,
    "opensuse": Distro.opensuse,
}


def _parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        try:
            parsed = shlex.split(val)
        except ValueError:
            parsed = [val]
        out[key.strip()] = parsed[0] if parsed else ""
    return out


def detect_distro_from_text(text: str) -> Distro:
    fields = _parse_os_release(text)
    id_val = fields.get("ID", "").lower()
    if id_val in _ID_TO_FAMILY:
        return _ID_TO_FAMILY[id_val]
    like_val = fields.get("ID_LIKE", "")
    for raw_tok in like_val.split():
        tok = raw_tok.lower()
        if tok in _LIKE_TO_FAMILY:
            return _LIKE_TO_FAMILY[tok]
    if not id_val:
        raise DistroDetectionError("/etc/os-release has no ID field")
    raise DistroDetectionError(
        f"unknown distro: ID={id_val!r}, ID_LIKE={like_val!r} (supported families: "
        f"{', '.join(d.value for d in Distro)})"
    )


def detect_distro(os_release_path: Path = Path("/etc/os-release")) -> Distro:
    try:
        text = Path(os_release_path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise DistroDetectionError(f"{os_release_path}: not found") from exc
    return detect_distro_from_text(text)
