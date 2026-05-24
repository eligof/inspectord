# Dependency Manager — Manual Acceptance

This procedure verifies the dep manager end-to-end on a **real Arch / CachyOS host**.
The automated test suite uses fake backends; only this manual run touches `pacman`.

## Preconditions

- Arch family host with sudo or root.
- inspectord built from source and installed in a venv (`pip install -e '.[dev]'`).
- The inspectord daemon is **not** running.

## Acceptance steps

### 1. Bring up the daemon

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
rm -rf var/
inspectord --dev &
sleep 2
```

### 2. Status

```bash
inspectorctl deps status
```

Expected: a table with rows for `aide`, `auditd`, `ebpf_features`, `journald`, `libudev`, `yara`.

### 3. Plan

```bash
inspectorctl deps plan --profile minimal
```

Expected: a plan id, listed items for each missing dep. If everything is already installed, you'll get `Nothing to install`.

### 4. Install (the privileged path)

If any deps were missing in step 3, run:

```bash
sudo -E env "PATH=$PATH" inspectorctl deps install --profile minimal
```

(We use `sudo` here in dev because polkit policy isn't installed yet. In a real package install, `inspectorctl deps install` would call `pkexec /usr/libexec/inspectord/pkg-helper --plan-id <uuid>` instead.)

Expected: `pacman -Sy` runs, then `pacman -S --noconfirm --needed <packages>`, sidecar configs land in `/etc/audit/rules.d/` and `/etc/systemd/journald.conf.d/`, systemd services start, verify probes report green.

### 5. Verify and re-status

```bash
inspectorctl deps status
```

All required deps should now show `Installed=yes`, `Drop-in=yes` (for those with configs), `Last verify=pass`.

### 6. Audit trail

```bash
inspectorctl deps audit --target auditd
```

Expected: chronological list of every action for `auditd` (`plan_created`, `metadata_refresh`, `install`, `dropin_written`, `service_action`, `verify_pass`).

### 7. Stop the daemon

```bash
kill %1
wait %1 2>/dev/null || true
```

## Rollback

For each dep with a drop-in:

```bash
sudo rm /etc/audit/rules.d/inspectord.rules
sudo rm /etc/systemd/journald.conf.d/inspectord.conf
sudo augenrules --load
sudo systemctl restart auditd
sudo systemctl restart systemd-journald
```

Third-party packages (audit, aide, yara) are left in place — uninstalling them is the user's call via pacman.
