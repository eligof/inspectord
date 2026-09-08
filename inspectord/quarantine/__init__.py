"""File quarantine (quarantine design 2026-09-08 §3).

Isolate a file into the forensic store and remove the original, reversibly.
The core operations live in :mod:`inspectord.quarantine.ops`; typed refusals
in :mod:`inspectord.quarantine.errors`; dirfd path discipline in
:mod:`inspectord.quarantine.paths`.
"""
