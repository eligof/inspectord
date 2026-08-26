"""Tests for the process-tree walker + secret scrubbing (proc-tree spec §3, §4, §6)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from inspectord.evidence import proctree
from inspectord.evidence.proctree import (
    capture_process_tree,
    scrub_cmdline,
    scrub_env_value,
    scrub_value,
)

# --- fake /proc builder ---


def _mk_proc(
    root: Path,
    pid: int,
    *,
    ppid: int,
    comm: str = "proc",
    argv: tuple[str, ...] | None = None,
    env: dict[str, str] | None = None,
    environ_raw: bytes | None = None,
    uid: int = 1000,
    euid: int = 1000,
    exe: Path | None = None,
    cwd: Path | None = None,
    status: bool = True,
) -> Path:
    d = root / str(pid)
    d.mkdir(parents=True)
    (d / "stat").write_text(f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 0 0 0 0 0 0 0\n")
    if status:
        (d / "status").write_text(
            f"Name:\t{comm}\nUid:\t{uid}\t{euid}\t{uid}\t{uid}\nGid:\t1000\t1000\t1000\t1000\n"
        )
    args = argv if argv is not None else (comm,)
    (d / "cmdline").write_bytes(b"".join(a.encode() + b"\0" for a in args))
    if environ_raw is not None:
        (d / "environ").write_bytes(environ_raw)
    else:
        env_dict = env if env is not None else {"PATH": "/usr/bin"}
        (d / "environ").write_bytes(
            b"".join(f"{k}={v}".encode() + b"\0" for k, v in env_dict.items())
        )
    if exe is not None:
        (d / "exe").symlink_to(exe)
    if cwd is not None:
        (d / "cwd").symlink_to(cwd)
    return d


@pytest.fixture
def proc(tmp_path: Path) -> Path:
    d = tmp_path / "proc"
    d.mkdir()
    return d


# --- walk contract (§3) ---


def test_chain_to_pid1(proc: Path) -> None:
    _mk_proc(proc, 1, ppid=0, comm="systemd")
    _mk_proc(proc, 4100, ppid=1, comm="bash")
    _mk_proc(proc, 4242, ppid=4100, comm="curl")
    snap = capture_process_tree(4242, proc_root=str(proc))
    assert snap is not None
    assert snap["root_pid"] == 4242
    assert snap["truncated"] is False
    assert [n["pid"] for n in snap["nodes"]] == [4242, 4100, 1]
    assert [n["ppid"] for n in snap["nodes"]] == [4100, 1, 0]
    assert [n["comm"] for n in snap["nodes"]] == ["curl", "bash", "systemd"]
    assert "captured_at" in snap


def test_ppid0_kernel_chain_not_truncated(proc: Path) -> None:
    # usermode helper spawned by kthreadd: 300 -> 2 (kthreadd, ppid 0). Complete chain,
    # NOT truncated even though it never reaches pid 1.
    _mk_proc(proc, 2, ppid=0, comm="kthreadd", environ_raw=b"", argv=())
    _mk_proc(proc, 300, ppid=2, comm="modprobe")
    snap = capture_process_tree(300, proc_root=str(proc))
    assert snap is not None
    assert [n["pid"] for n in snap["nodes"]] == [300, 2]
    assert snap["truncated"] is False


def test_hostile_comm_parsed_after_last_paren(proc: Path) -> None:
    _mk_proc(proc, 1, ppid=0, comm="systemd")
    _mk_proc(proc, 55, ppid=1, comm=")(  ) x")
    snap = capture_process_tree(55, proc_root=str(proc))
    assert snap is not None
    node = snap["nodes"][0]
    assert node["comm"] == ")(  ) x"
    assert node["ppid"] == 1
    assert snap["truncated"] is False


def test_depth_cap_truncates(proc: Path) -> None:
    # 40-deep chain: 100 -> 101 -> ... -> 139 (ppid of the last points at a missing pid,
    # but the cap fires first).
    for i in range(40):
        _mk_proc(proc, 100 + i, ppid=100 + i + 1)
    snap = capture_process_tree(100, proc_root=str(proc))
    assert snap is not None
    assert len(snap["nodes"]) == 32
    assert snap["truncated"] is True


def test_vanished_ancestor_truncated_prior_nodes_kept(proc: Path) -> None:
    _mk_proc(proc, 4242, ppid=4100, comm="orphan")  # 4100 does not exist
    snap = capture_process_tree(4242, proc_root=str(proc))
    assert snap is not None
    assert [n["pid"] for n in snap["nodes"]] == [4242]
    assert snap["truncated"] is True


def test_dead_root_returns_none(proc: Path) -> None:
    assert capture_process_tree(9999, proc_root=str(proc)) is None


def test_root_with_unreadable_stat_returns_none(proc: Path) -> None:
    d = proc / "77"
    d.mkdir()
    # directory exists but stat is absent
    assert capture_process_tree(77, proc_root=str(proc)) is None


def test_zombie_empty_environ_gives_empty_env_no_error(proc: Path) -> None:
    _mk_proc(proc, 1, ppid=0, comm="systemd")
    _mk_proc(proc, 88, ppid=1, comm="defunct", environ_raw=b"", argv=())
    snap = capture_process_tree(88, proc_root=str(proc))
    assert snap is not None
    node = snap["nodes"][0]
    assert node["env"] == {}
    assert node["env_bytes"] == 0
    assert node["env_truncated"] is False
    assert not any(e.startswith("environ") for e in node["errors"])


def test_uid_euid_from_status_uid_line(proc: Path) -> None:
    _mk_proc(proc, 1, ppid=0, comm="systemd")
    _mk_proc(proc, 90, ppid=1, uid=1000, euid=0)  # setuid escalation signal
    snap = capture_process_tree(90, proc_root=str(proc))
    assert snap is not None
    node = snap["nodes"][0]
    assert node["uid"] == 1000
    assert node["euid"] == 0


def test_exe_sha256_and_link_fields(proc: Path, tmp_path: Path) -> None:
    payload = tmp_path / "bin" / "evil"
    payload.parent.mkdir()
    payload.write_bytes(b"#!/bin/sh\necho pwned\n")
    workdir = tmp_path / "wd"
    workdir.mkdir()
    _mk_proc(proc, 1, ppid=0, comm="systemd")
    _mk_proc(proc, 91, ppid=1, exe=payload, cwd=workdir)
    snap = capture_process_tree(91, proc_root=str(proc))
    assert snap is not None
    node = snap["nodes"][0]
    assert node["exe"] == str(payload)
    assert node["exe_sha256"] == hashlib.sha256(payload.read_bytes()).hexdigest()
    assert node["cwd"] == str(workdir)


def test_exe_over_cap_omitted_with_error(
    proc: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(proctree, "_MAX_FILE_BYTES", 4)
    payload = tmp_path / "big"
    payload.write_bytes(b"0123456789")
    _mk_proc(proc, 1, ppid=0, comm="systemd")
    _mk_proc(proc, 92, ppid=1, exe=payload)
    snap = capture_process_tree(92, proc_root=str(proc))
    assert snap is not None
    node = snap["nodes"][0]
    assert "exe_sha256" not in node
    assert any(e.startswith("exe_sha256") for e in node["errors"])


def test_per_field_errors_keep_node(proc: Path) -> None:
    # No status, no exe, no cwd: each failure lands in errors, the node survives.
    _mk_proc(proc, 1, ppid=0, comm="systemd")
    _mk_proc(proc, 93, ppid=1, status=False)
    snap = capture_process_tree(93, proc_root=str(proc))
    assert snap is not None
    node = snap["nodes"][0]
    assert node["pid"] == 93
    assert "uid" not in node
    assert "exe" not in node
    fields_with_errors = {e.split(":")[0] for e in node["errors"]}
    assert {"status", "exe", "exe_sha256", "cwd"} <= fields_with_errors
    # walk continued to pid 1 regardless
    assert [n["pid"] for n in snap["nodes"]] == [93, 1]


# --- env parsing (§3) ---


def test_env_nul_parse(proc: Path) -> None:
    _mk_proc(proc, 1, ppid=0, comm="systemd")
    _mk_proc(proc, 94, ppid=1, env={"PATH": "/usr/bin", "HOME": "/home/u", "LANG": "C"})
    snap = capture_process_tree(94, proc_root=str(proc))
    assert snap is not None
    node = snap["nodes"][0]
    assert node["env"] == {"PATH": "/usr/bin", "HOME": "/home/u", "LANG": "C"}
    assert node["env_truncated"] is False
    assert node["env_redacted"] == 0


def test_env_cap_plus_one_sets_truncated_and_bytes(
    proc: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(proctree, "_MAX_ENV_BYTES", 16)
    raw = b"A=1\0B=2\0LONGNAME=abcdefgh\0"
    _mk_proc(proc, 1, ppid=0, comm="systemd")
    _mk_proc(proc, 95, ppid=1, environ_raw=raw)
    snap = capture_process_tree(95, proc_root=str(proc))
    assert snap is not None
    node = snap["nodes"][0]
    assert node["env_truncated"] is True
    assert node["env_bytes"] == 17  # cap + 1 bytes actually read
    assert node["env"] == {"A": "1", "B": "2"}


def test_env_trailing_fragment_dropped_on_cap(proc: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proctree, "_MAX_ENV_BYTES", 12)
    # read of 13 bytes ends exactly on "XYZ=9" without its NUL: parseable-looking but
    # partial, so it must be dropped.
    raw = b"A=1\0B=2\0XYZ=987654\0"
    _mk_proc(proc, 1, ppid=0, comm="systemd")
    _mk_proc(proc, 96, ppid=1, environ_raw=raw)
    snap = capture_process_tree(96, proc_root=str(proc))
    assert snap is not None
    node = snap["nodes"][0]
    assert node["env_truncated"] is True
    assert node["env"] == {"A": "1", "B": "2"}
    assert "XYZ" not in node["env"]


def test_env_malformed_only_content_omits_env(proc: Path) -> None:
    _mk_proc(proc, 1, ppid=0, comm="systemd")
    _mk_proc(proc, 97, ppid=1, environ_raw=b"noequals\0alsobad\0")
    snap = capture_process_tree(97, proc_root=str(proc))
    assert snap is not None
    node = snap["nodes"][0]
    assert "env" not in node
    assert any(e.startswith("environ") for e in node["errors"])


def test_env_malformed_fragment_skipped_good_kept(proc: Path) -> None:
    _mk_proc(proc, 1, ppid=0, comm="systemd")
    _mk_proc(proc, 98, ppid=1, environ_raw=b"GOOD=1\0bad\0")
    snap = capture_process_tree(98, proc_root=str(proc))
    assert snap is not None
    node = snap["nodes"][0]
    assert node["env"] == {"GOOD": "1"}
    assert any("malformed" in e for e in node["errors"])


def test_env_redacted_counts_variables(proc: Path) -> None:
    _mk_proc(
        proc,
        1,
        ppid=0,
        comm="systemd",
        environ_raw=b"",
    )
    _mk_proc(
        proc,
        99,
        ppid=1,
        env={"PATH": "/bin", "API_TOKEN": "abc", "MY_SECRET": "def"},
    )
    snap = capture_process_tree(99, proc_root=str(proc))
    assert snap is not None
    node = snap["nodes"][0]
    assert node["env_redacted"] == 2
    assert node["env"]["PATH"] == "/bin"


def test_capture_redacts_secret_in_serialized_snapshot(proc: Path) -> None:
    _mk_proc(proc, 1, ppid=0, comm="systemd")
    _mk_proc(proc, 4242, ppid=1, env={"API_TOKEN": "s3cret-value"})
    snap = capture_process_tree(4242, proc_root=str(proc))
    assert snap is not None
    blob = json.dumps(snap)
    assert "s3cret-value" not in blob
    assert "API_TOKEN" in blob  # names are kept (deliberate, spec §2)
    assert snap["nodes"][0]["env"]["API_TOKEN"] == "<redacted>"


# --- §4 rule 1: name-based redaction ---


@pytest.mark.parametrize(
    "name",
    [
        "GITHUB_TOKEN",  # TOKEN
        "MY_SECRET",  # SECRET
        "DB_PASSWORD",  # PASS
        "PGPASSFILE",  # PASS
        "MYSQL_PWD",  # _PWD
        "STRIPE_API_KEY",  # API_KEY
        "OPENAI_APIKEY",  # APIKEY
        "WG_PRIVATE",  # PRIVATE
        "GOOGLE_CREDENTIALS",  # CREDENTIAL
        "OAUTH_CLIENT",  # AUTH
        "MY_SESSION",  # SESSION
        "HTTP_COOKIE",  # COOKIE
        "SENTRY_DSN",  # DSN
        "AWS_ACCESS_KEY",  # ACCESS_KEY
        "AZURE_CONNECTION_STRING",  # CONNECTION_STRING
        "BEARER_VALUE",  # BEARER
        "SLACK_WEBHOOK",  # WEBHOOK
    ],
)
def test_rule1_name_substrings_redact(name: str) -> None:
    value, redacted = scrub_env_value(name, "supersecret")
    assert value == "<redacted>"
    assert redacted is True


@pytest.mark.parametrize("name", ["github_token", "my_secret", "Db_Password"])
def test_rule1_matching_is_case_insensitive(name: str) -> None:
    value, redacted = scrub_env_value(name, "supersecret")
    assert value == "<redacted>"
    assert redacted is True


@pytest.mark.parametrize("name", ["PWD", "OLDPWD", "PATH", "HOME"])
def test_rule1_does_not_hit_benign_names(name: str) -> None:
    value, redacted = scrub_env_value(name, "/some/dir")
    assert value == "/some/dir"
    assert redacted is False


def test_redacted_empty_marker_no_length_leak() -> None:
    value, redacted = scrub_env_value("API_TOKEN", "")
    assert value == "<redacted:empty>"
    assert redacted is True


def test_redacted_marker_carries_no_length() -> None:
    short, _ = scrub_env_value("API_TOKEN", "x")
    long, _ = scrub_env_value("API_TOKEN", "x" * 500)
    assert short == long == "<redacted>"


# --- §4 rule 2: exact-name exemptions ---


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SSH_AUTH_SOCK", "/run/user/1000/keyring/ssh"),
        ("XAUTHORITY", "/home/u/.Xauthority"),
        ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
        ("XDG_SESSION_ID", "3"),
        ("XDG_SESSION_TYPE", "wayland"),
        ("XDG_SESSION_CLASS", "user"),
        ("XDG_SESSION_DESKTOP", "KDE"),
        ("SESSION_MANAGER", "local/host:@/tmp/.ICE-unix/1234,unix/host:/tmp/.ICE-unix/1234"),
    ],
)
def test_rule2_exemptions_stay_raw(name: str, value: str) -> None:
    got, redacted = scrub_env_value(name, value)
    assert got == value
    assert redacted is False


# --- §4 rule 3: URL-credential scrub ---


def test_url_credential_scrub_keeps_scheme_user_host() -> None:
    got = scrub_value("postgres://alice:hunter2@db.local:5432/app")
    assert got == "postgres://alice:<redacted>@db.local:5432/app"


def test_url_without_credentials_untouched() -> None:
    assert scrub_value("https://example.com:8080/path") == "https://example.com:8080/path"


def test_url_credential_scrub_applies_to_kept_env_value() -> None:
    got, redacted = scrub_env_value("DATABASE_URL", "mysql://bob:pw@host/db")
    assert got == "mysql://bob:<redacted>@host/db"
    assert redacted is True


# --- §4 rule 4: known-prefix backstop ---


@pytest.mark.parametrize(
    "secret",
    # Fixture tokens are assembled at runtime so no literal secret-shaped string
    # exists in this file (GitHub push protection scans blob content, and these
    # synthetic shapes are indistinguishable from real leaks to a scanner).
    [
        "AKIA" + "IOSFODNN7EXAMPLE",
        "ghp_" + "abcdefghijklmnopqrstuv0123456789",
        "gho_" + "abcdefghijklmnopqrstuv0123456789",
        "ghs_" + "abcdefghijklmnopqrstuv0123456789",
        "github_pat_" + "11ABCDEFG_abcdefghij",
        "glpat-" + "Xy12abcdEFGH3456ijkl",
        "sk-ant-" + "api03-abc123-def456",
        "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "rk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "xoxb-" + "1234567890-abcdefghij",
        "xoxp-" + "1234567890-abcdefghij",
        "xoxc-" + "1234567890-abcdefghij",
        "xoxa-" + "1234567890-abcdefghij",
        "AIza" + "SyA1234567890abcdefghijklmnopqrstuv",
        "-----BEGIN RSA PRIVATE" + " KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
        "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpM",
    ],
)
def test_rule4_prefix_backstop_hits(secret: str) -> None:
    got = scrub_value(f"prefix {secret} suffix")
    assert "<redacted>" in got
    # no fragment of the secret body may survive
    body = secret.split("\n")[1] if "\n" in secret else secret[8:]
    assert body not in got


def test_rule4_benign_value_untouched() -> None:
    benign = "/usr/local/bin:/usr/bin:/bin"
    assert scrub_value(benign) == benign


# --- §4 rule 5: cmdline scrub ---


def test_cmdline_authorization_header() -> None:
    got = scrub_cmdline(["curl", "-H", "Authorization: Bearer eyJx.yy.zz", "https://x"])
    assert got == "curl -H 'Authorization: <redacted>' https://x"


def test_cmdline_bearer_token() -> None:
    got = scrub_cmdline(["cmd", "bearer eyJa.bb.cc"])
    assert "eyJa.bb.cc" not in got
    assert "<redacted>" in got


def test_cmdline_password_flag() -> None:
    got = scrub_cmdline(["mysqldump", "--password=hunter2", "db"])
    assert "hunter2" not in got
    assert "--password=<redacted>" in got


def test_cmdline_sshpass_p_next_arg() -> None:
    got = scrub_cmdline(["sshpass", "-p", "hunter2", "ssh", "host"])
    assert "hunter2" not in got
    assert "ssh host" in got


def test_cmdline_mysql_glued_p() -> None:
    got = scrub_cmdline(["mysql", "-phunter2", "-u", "root"])
    assert "hunter2" not in got
    assert "-p<redacted>" in got
    assert "root" in got


def test_cmdline_user_colon_pair() -> None:
    got = scrub_cmdline(["curl", "-u", "bob:pw123", "https://x"])
    assert "pw123" not in got
    assert "bob" in got


def test_cmdline_user_equals_colon_pair() -> None:
    got = scrub_cmdline(["curl", "--user=bob:pw123", "https://x"])
    assert "pw123" not in got
    assert "bob" in got


def test_cmdline_name_value_prefix() -> None:
    got = scrub_cmdline(["env", "API_TOKEN=s3cret", "true"])
    assert "s3cret" not in got
    assert "API_TOKEN" in got


def test_cmdline_url_userinfo_password() -> None:
    got = scrub_cmdline(["git", "clone", "https://bob:pw123@github.com/x/y.git"])
    assert "pw123" not in got
    assert "github.com" in got
    assert "bob" in got


def test_cmdline_benign_verbatim() -> None:
    assert scrub_cmdline(["ls", "-la", "/tmp"]) == "ls -la /tmp"


def test_cmdline_empty() -> None:
    assert scrub_cmdline([]) == ""


# --- review-fix regressions (raw-@ URL password, mysql family, space/3-arg forms) ---


def test_url_password_with_raw_at_fully_redacted():
    out = scrub_value("mysql://root:p@ssw0rd@db.internal/x")
    assert "ssw0rd" not in out
    assert out.startswith("mysql://root:<redacted>@")


def test_glued_p_covers_mysql_family():
    out = scrub_cmdline(["mysqldump", "-psecret", "mydb"])
    assert "secret" not in out and "-p<redacted>" in out


def test_space_form_password_flag_redacted():
    out = scrub_cmdline(["mongosh", "--password", "hunter2"])
    assert "hunter2" not in out and "<redacted>" in out


def test_three_arg_authorization_bearer_redacted():
    out = scrub_cmdline(["curl", "-H", "Authorization:", "Bearer", "tok123"])
    assert "tok123" not in out and "Bearer" in out
