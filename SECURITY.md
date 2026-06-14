# Security Policy

`inspectord` is a personal, single-host Linux endpoint security console. It
is pre-release software under active development and carries no formal support
or backporting guarantees.

## Supported versions

Only the `main` branch is supported. There are no released versions yet; fixes
land on `main`.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.

Use GitHub's private vulnerability reporting: open the repository's
**Security** tab and choose **Report a vulnerability**. This opens a private
advisory visible only to the maintainer.

When reporting, please include:

- affected component (eBPF program, native extension, a worker, IPC, etc.)
- a description of the impact and, if possible, steps to reproduce
- the kernel version and distro, since the eBPF collectors are kernel-sensitive

You can expect an initial acknowledgement within a few days. As a solo
project, remediation timelines are best-effort.

## Scope notes

`inspectord` loads eBPF programs and reads kernel memory via BTF-resolved
offsets, and runs collector workers under a supervisor. Reports touching
privilege boundaries (the IPC socket, polkit/dependency installation paths,
or anything that escalates from the daemon's privileges) are especially
welcome.
