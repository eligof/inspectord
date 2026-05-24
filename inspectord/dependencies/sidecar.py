"""Sidecar config writer (spec §30.6)."""

from __future__ import annotations

import grp
import os
import pwd
import tempfile
from importlib.resources import as_file, files
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from inspectord.dependencies.schemas import ConfigStrategy, DependencyManifest


class SidecarError(RuntimeError):
    pass


def _render_template(template_rel_path: str, ctx: dict[str, object]) -> str:
    pkg = files("inspectord.dependencies.templates")
    with as_file(pkg) as templates_root:
        env = Environment(
            loader=FileSystemLoader(str(templates_root)),
            autoescape=select_autoescape(default=False, default_for_string=False),
            keep_trailing_newline=True,
        )
        return env.get_template(template_rel_path).render(**ctx)


def _atomic_write(target: Path, content: str, mode: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, target)
    except Exception:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def write_sidecar(
    manifest: DependencyManifest,
    *,
    include_dir: Path,
    chown: bool = True,
    extra_ctx: dict[str, object] | None = None,
) -> Path:
    if manifest.config is None or manifest.config.strategy is not ConfigStrategy.sidecar:
        raise SidecarError(f"{manifest.name}: no sidecar config")
    if manifest.config.dropin is None:
        raise SidecarError(f"{manifest.name}: config.dropin not set")

    ctx: dict[str, object] = {"manifest": manifest, "name": manifest.name}
    if extra_ctx:
        ctx.update(extra_ctx)
    content = _render_template(manifest.config.dropin.template, ctx)
    mode = int(manifest.config.dropin.mode, 8)
    target = Path(include_dir) / manifest.config.dropin.filename
    _atomic_write(target, content, mode)
    if chown:
        try:
            uid = pwd.getpwnam(manifest.config.dropin.owner).pw_uid
            gid = grp.getgrnam(manifest.config.dropin.owner).gr_gid
            os.chown(target, uid, gid)
        except (KeyError, PermissionError):
            pass  # dev / test fallback
    return target
