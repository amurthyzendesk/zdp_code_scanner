#!/usr/bin/env python3
"""
Transaction Log - Append-only JSONL log for all findings
=========================================================

Provides crash-safe, atomic append-only logging of security findings.
Every finding is written immediately with fsync to ensure durability.

Key Features:
- One JSON line per finding
- Atomic writes with fsync
- Survives kill -9 and crashes
- Can replay entire scan history
"""

import os
import json
import fcntl
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from contextlib import contextmanager


class TransactionLog:
    """
    Append-only JSONL transaction log for security findings.

    Each line is a complete JSON object representing either:
    - A finding: {"type":"finding","timestamp":"...","finding":{...}}
    - A checkpoint: {"type":"checkpoint","timestamp":"...","data":{...}}

    Writes are atomic and durable (fsync after each append).
    """

    def __init__(self, log_file: Path):
        """
        Initialize transaction log.

        Args:
            log_file: Path to JSONL log file (will be created if doesn't exist)
        """
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        # Create file if it doesn't exist
        if not self.log_file.exists():
            self.log_file.touch()

        # Open in append mode with line buffering
        self._file_handle = None
        self._entries_written = 0

    @contextmanager
    def _open_for_append(self):
        """Context manager for safe file operations."""
        handle = None
        try:
            # Open in append mode with exclusive lock
            handle = open(self.log_file, 'a', encoding='utf-8', buffering=1)
            # Acquire exclusive lock (blocking)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield handle
        finally:
            if handle:
                # Release lock and close
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
                handle.close()

    def append_finding(self, finding: Dict) -> None:
        """
        Append a finding to the transaction log.

        Args:
            finding: Dictionary containing finding data with keys:
                - repo: Repository name
                - file: File path
                - finding: Finding details (severity, category, line_number, etc.)

        The entry is written atomically with fsync for durability.
        """
        entry = {
            'type': 'finding',
            'timestamp': datetime.now().isoformat(),
            'finding': finding
        }

        self._append_entry(entry)

    def append_checkpoint(self, checkpoint_data: Dict) -> None:
        """
        Append a checkpoint marker to the transaction log.

        Args:
            checkpoint_data: Dictionary containing checkpoint state:
                - files_scanned: Number of files processed
                - processed_files: List of file paths
                - current_repo: Current repository name
                - findings_count: Total findings so far
        """
        entry = {
            'type': 'checkpoint',
            'timestamp': datetime.now().isoformat(),
            'data': checkpoint_data
        }

        self._append_entry(entry)

    def _append_entry(self, entry: Dict) -> None:
        """
        Internal method to append entry with atomic write and fsync.

        Args:
            entry: Complete entry dictionary
        """
        try:
            with self._open_for_append() as handle:
                # Serialize to single line JSON
                line = json.dumps(entry, separators=(',', ':'))

                # Write with newline
                handle.write(line + '\n')

                # Force write to disk (critical for crash safety)
                handle.flush()
                os.fsync(handle.fileno())

                self._entries_written += 1

        except Exception as e:
            # Log error but don't crash - graceful degradation
            print(f"WARNING: Failed to write transaction log entry: {e}")

    def replay(self) -> List[Dict]:
        """
        Replay the entire transaction log.

        Returns:
            List of all findings from the log (checkpoint markers are excluded)

        This is used for crash recovery to reconstruct the current state.
        """
        findings = []

        if not self.log_file.exists():
            return findings

        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)

                        # Only include findings, skip checkpoints
                        if entry.get('type') == 'finding':
                            findings.append(entry['finding'])

                    except json.JSONDecodeError as e:
                        print(f"WARNING: Corrupted log entry at line {line_num}: {e}")
                        # Continue reading - partial corruption shouldn't stop recovery
                        continue

        except Exception as e:
            print(f"ERROR: Failed to replay transaction log: {e}")

        return findings

    def get_last_checkpoint(self) -> Optional[Dict]:
        """
        Get the most recent checkpoint from the log.

        Returns:
            Most recent checkpoint data, or None if no checkpoint exists
        """
        last_checkpoint = None

        if not self.log_file.exists():
            return None

        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)
                        if entry.get('type') == 'checkpoint':
                            last_checkpoint = entry
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            print(f"ERROR: Failed to read checkpoint from log: {e}")

        return last_checkpoint

    def get_stats(self) -> Dict:
        """
        Get statistics about the transaction log.

        Returns:
            Dictionary with stats:
                - total_entries: Total lines in log
                - findings_count: Number of finding entries
                - checkpoint_count: Number of checkpoint markers
                - file_size_bytes: Size of log file
        """
        stats = {
            'total_entries': 0,
            'findings_count': 0,
            'checkpoint_count': 0,
            'file_size_bytes': 0
        }

        if not self.log_file.exists():
            return stats

        try:
            stats['file_size_bytes'] = self.log_file.stat().st_size

            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    stats['total_entries'] += 1

                    try:
                        entry = json.loads(line)
                        entry_type = entry.get('type')

                        if entry_type == 'finding':
                            stats['findings_count'] += 1
                        elif entry_type == 'checkpoint':
                            stats['checkpoint_count'] += 1
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            print(f"ERROR: Failed to compute log stats: {e}")

        return stats

    def close(self) -> None:
        """Clean up resources."""
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None
