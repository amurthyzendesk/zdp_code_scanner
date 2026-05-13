#!/usr/bin/env python3
"""
Recovery Manager - Crash recovery and scan resumption
======================================================

Detects incomplete scans and provides state for resumption.
Combines checkpoint data with transaction log replay for complete recovery.

Key Features:
- Detects crash scenarios
- Rebuilds scan state from checkpoints + transaction log
- Identifies which files/repos to skip
- Preserves all findings from before crash
"""

from pathlib import Path
from typing import Dict, Set, List, Optional
from datetime import datetime

from .transaction_log import TransactionLog
from .checkpoint_manager import CheckpointManager


class RecoveryManager:
    """
    Manages crash recovery and scan resumption.

    Uses both checkpoint data (for efficiency) and transaction log replay
    (for completeness) to restore scan state after a crash.
    """

    def __init__(
        self,
        transaction_log: TransactionLog,
        checkpoint_mgr: CheckpointManager
    ):
        """
        Initialize recovery manager.

        Args:
            transaction_log: Transaction log instance
            checkpoint_mgr: Checkpoint manager instance
        """
        self.transaction_log = transaction_log
        self.checkpoint_mgr = checkpoint_mgr

    def detect_incomplete_scan(self) -> bool:
        """
        Detect if there's an incomplete scan that can be resumed.

        Returns:
            True if checkpoint exists (indicating incomplete scan)

        An incomplete scan is detected if:
        1. Checkpoint files exist, OR
        2. Transaction log has entries but no summary checkpoint
        """
        # Check for checkpoint files
        if self.checkpoint_mgr.checkpoint_exists():
            return True

        # Check transaction log
        log_stats = self.transaction_log.get_stats()
        if log_stats['findings_count'] > 0:
            # Has findings but no checkpoint - likely crashed early
            return True

        return False

    def resume_state(self) -> Dict:
        """
        Build resume state from checkpoint and transaction log.

        Returns:
            Dictionary containing:
                - start_index: File index to resume from (0 if starting fresh)
                - processed_files: Set of file paths already processed
                - existing_findings: List of findings recovered from log
                - repos_completed: List of repository names completed
                - files_scanned: Total files scanned before crash
                - findings_count: Total findings before crash
                - current_repo: Repository being scanned when crashed
                - checkpoint_timestamp: When last checkpoint was saved
                - recovery_method: 'checkpoint' or 'transaction_log'

        Priority:
        1. Use checkpoint if available (faster)
        2. Fall back to transaction log replay (slower but complete)
        """
        resume_state = {
            'start_index': 0,
            'processed_files': set(),
            'existing_findings': [],
            'repos_completed': [],
            'files_scanned': 0,
            'findings_count': 0,
            'current_repo': None,
            'checkpoint_timestamp': None,
            'recovery_method': 'none'
        }

        # Try checkpoint first (most efficient)
        checkpoint = self.checkpoint_mgr.load_latest_checkpoint()

        if checkpoint:
            resume_state.update(self._restore_from_checkpoint(checkpoint))
            resume_state['recovery_method'] = 'checkpoint'

            # Get findings from transaction log
            resume_state['existing_findings'] = self.transaction_log.replay()

            return resume_state

        # Fallback: replay transaction log
        findings = self.transaction_log.replay()

        if findings:
            resume_state.update(self._restore_from_transaction_log(findings))
            resume_state['recovery_method'] = 'transaction_log'
            resume_state['existing_findings'] = findings

        return resume_state

    def _restore_from_checkpoint(self, checkpoint: Dict) -> Dict:
        """
        Restore state from checkpoint data.

        Args:
            checkpoint: Checkpoint dictionary

        Returns:
            Partial resume state from checkpoint
        """
        state = {}

        checkpoint_type = checkpoint.get('checkpoint_type')
        timestamp = checkpoint.get('timestamp')

        state['checkpoint_timestamp'] = timestamp

        if checkpoint_type == 'file_level':
            # File-level checkpoint: most detailed
            checkpoint_state = checkpoint.get('state', {})

            state['files_scanned'] = checkpoint_state.get('files_scanned', 0)
            state['processed_files'] = set(checkpoint_state.get('processed_files', []))
            state['current_repo'] = checkpoint_state.get('current_repo')
            state['findings_count'] = checkpoint_state.get('findings_count', 0)
            state['repos_completed'] = checkpoint_state.get('repos_completed', [])
            state['start_index'] = checkpoint_state.get('current_file_in_repo', 0)

        elif checkpoint_type == 'repo_level':
            # Repo-level checkpoint: resume from next repo
            checkpoint_state = checkpoint.get('state', {})

            state['files_scanned'] = checkpoint_state.get('total_files_so_far', 0)
            state['repos_completed'] = checkpoint_state.get('repos_completed', [])
            state['findings_count'] = checkpoint_state.get('total_findings_so_far', 0)
            state['processed_files'] = set()  # Will be reconstructed from log
            state['start_index'] = 0  # Start from beginning of next repo

        elif checkpoint_type == 'summary':
            # Summary checkpoint: scan was complete
            summary = checkpoint.get('summary', {})

            state['files_scanned'] = summary.get('total_files', 0)
            state['findings_count'] = summary.get('total_findings', 0)
            state['repos_completed'] = []  # All repos completed
            state['processed_files'] = set()
            state['start_index'] = 0

        return state

    def _restore_from_transaction_log(self, findings: List[Dict]) -> Dict:
        """
        Restore state by analyzing transaction log findings.

        Args:
            findings: List of findings from transaction log replay

        Returns:
            Partial resume state derived from findings
        """
        state = {}

        # Build processed files set
        processed_files = set()
        repos_completed = set()

        for finding in findings:
            repo = finding.get('repo')
            file_path = finding.get('file')

            if repo:
                repos_completed.add(repo)
            if file_path:
                processed_files.add(file_path)

        state['processed_files'] = processed_files
        state['repos_completed'] = list(repos_completed)
        state['files_scanned'] = len(processed_files)
        state['findings_count'] = len(findings)
        state['start_index'] = 0
        state['current_repo'] = None

        return state

    def should_skip_file(self, file_path: str, resume_state: Dict) -> bool:
        """
        Check if file should be skipped during resume.

        Args:
            file_path: Path to file being considered
            resume_state: Resume state from resume_state()

        Returns:
            True if file was already processed
        """
        return file_path in resume_state.get('processed_files', set())

    def should_skip_repo(self, repo_name: str, resume_state: Dict) -> bool:
        """
        Check if repository should be skipped during resume.

        Args:
            repo_name: Name of repository
            resume_state: Resume state from resume_state()

        Returns:
            True if repository was fully processed
        """
        return repo_name in resume_state.get('repos_completed', [])

    def get_recovery_summary(self, resume_state: Dict) -> str:
        """
        Generate human-readable recovery summary.

        Args:
            resume_state: Resume state from resume_state()

        Returns:
            Formatted string describing recovery state
        """
        lines = []

        lines.append("=" * 70)
        lines.append("CRASH RECOVERY SUMMARY")
        lines.append("=" * 70)

        recovery_method = resume_state.get('recovery_method', 'none')
        lines.append(f"Recovery method: {recovery_method}")

        if resume_state.get('checkpoint_timestamp'):
            lines.append(f"Checkpoint time: {resume_state['checkpoint_timestamp']}")

        lines.append("")
        lines.append("Recovered State:")
        lines.append(f"  Files scanned:   {resume_state.get('files_scanned', 0):,}")
        lines.append(f"  Findings found:  {resume_state.get('findings_count', 0):,}")
        lines.append(f"  Repos completed: {len(resume_state.get('repos_completed', []))}")
        lines.append(f"  Files to skip:   {len(resume_state.get('processed_files', set())):,}")

        current_repo = resume_state.get('current_repo')
        if current_repo:
            lines.append(f"  Current repo:    {current_repo}")

        lines.append("")
        lines.append("Resuming scan from last known state...")
        lines.append("=" * 70)

        return "\n".join(lines)

    def validate_recovery_state(self, resume_state: Dict) -> bool:
        """
        Validate that recovery state is consistent and safe.

        Args:
            resume_state: Resume state to validate

        Returns:
            True if state is valid and safe to use
        """
        # Check required fields
        required_fields = [
            'start_index',
            'processed_files',
            'existing_findings',
            'repos_completed',
            'recovery_method'
        ]

        for field in required_fields:
            if field not in resume_state:
                print(f"ERROR: Invalid recovery state - missing field: {field}")
                return False

        # Validate data types
        if not isinstance(resume_state['processed_files'], set):
            print("ERROR: processed_files must be a set")
            return False

        if not isinstance(resume_state['existing_findings'], list):
            print("ERROR: existing_findings must be a list")
            return False

        if not isinstance(resume_state['repos_completed'], list):
            print("ERROR: repos_completed must be a list")
            return False

        # Validate counts match
        findings_count = resume_state.get('findings_count', 0)
        actual_findings = len(resume_state['existing_findings'])

        if findings_count != actual_findings:
            print(f"WARNING: Checkpoint says {findings_count} findings, "
                  f"but log has {actual_findings}")
            # Update to actual count from log (source of truth)
            resume_state['findings_count'] = actual_findings

        return True

    def clear_recovery_state(self) -> None:
        """
        Clear all recovery state (start fresh).

        Removes all checkpoints and transaction log.
        Use when starting a completely new scan.
        """
        self.checkpoint_mgr.clear_checkpoints()
        # Note: Transaction log is append-only, so we don't delete it
        # Instead, new scan will create a new log file
