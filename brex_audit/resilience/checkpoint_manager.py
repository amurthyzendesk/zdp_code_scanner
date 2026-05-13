#!/usr/bin/env python3
"""
Checkpoint Manager - Multi-level checkpointing for crash recovery
==================================================================

Provides atomic checkpoint operations at multiple levels:
- File-level: Every N files (configurable, default 100)
- Repo-level: After each repository completes
- Summary-level: When final summary is generated

Key Features:
- Atomic writes (temp file + rename)
- Multi-level granularity
- Fast recovery after crashes
"""

import os
import json
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime
import tempfile
import shutil


class CheckpointManager:
    """
    Multi-level checkpoint manager for security scanner.

    Checkpoints are saved atomically using the temp-file + rename pattern.
    This ensures that checkpoints are never partially written.
    """

    def __init__(self, checkpoint_dir: Path, file_checkpoint_frequency: int = 100):
        """
        Initialize checkpoint manager.

        Args:
            checkpoint_dir: Directory to store checkpoint files
            file_checkpoint_frequency: Save checkpoint every N files (default: 100)
        """
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        self.file_checkpoint_frequency = file_checkpoint_frequency

        # Checkpoint file paths
        self.file_checkpoint_path = self.checkpoint_dir / 'file_level.json'
        self.repo_checkpoint_path = self.checkpoint_dir / 'repo_level.json'
        self.summary_checkpoint_path = self.checkpoint_dir / 'summary_level.json'
        self.latest_checkpoint_path = self.checkpoint_dir / 'latest.json'

    def save_file_checkpoint(self, state: Dict) -> None:
        """
        Save file-level checkpoint.

        Args:
            state: Current scan state including:
                - files_scanned: Total files processed
                - processed_files: Set/List of file paths
                - current_repo: Current repository being scanned
                - findings_count: Total findings so far
                - current_file_in_repo: Current file index in repo
        """
        checkpoint_data = {
            'checkpoint_type': 'file_level',
            'timestamp': datetime.now().isoformat(),
            'state': {
                'files_scanned': state.get('files_scanned', 0),
                'processed_files': list(state.get('processed_files', [])),
                'current_repo': state.get('current_repo', ''),
                'findings_count': state.get('findings_count', 0),
                'current_file_in_repo': state.get('current_file_in_repo', 0),
                'repos_completed': state.get('repos_completed', [])
            }
        }

        self.atomic_write(self.file_checkpoint_path, checkpoint_data)
        # Also update latest checkpoint
        self.atomic_write(self.latest_checkpoint_path, checkpoint_data)

    def save_repo_checkpoint(self, repo_name: str, state: Dict) -> None:
        """
        Save repository-level checkpoint (after repo completes).

        Args:
            repo_name: Name of completed repository
            state: Repository scan state including:
                - files_scanned: Number of files in this repo
                - findings: Number of findings in this repo
                - duration_seconds: Time taken to scan repo
                - repos_completed: List of all completed repos
        """
        checkpoint_data = {
            'checkpoint_type': 'repo_level',
            'timestamp': datetime.now().isoformat(),
            'repo_name': repo_name,
            'state': {
                'files_scanned': state.get('files_scanned', 0),
                'findings': state.get('findings', 0),
                'duration_seconds': state.get('duration_seconds', 0),
                'repos_completed': state.get('repos_completed', []),
                'total_findings_so_far': state.get('total_findings_so_far', 0),
                'total_files_so_far': state.get('total_files_so_far', 0)
            }
        }

        self.atomic_write(self.repo_checkpoint_path, checkpoint_data)
        # Also update latest checkpoint
        self.atomic_write(self.latest_checkpoint_path, checkpoint_data)

    def save_summary_checkpoint(self, summary_data: Dict) -> None:
        """
        Save summary-level checkpoint (when scan completes).

        Args:
            summary_data: Complete scan summary including:
                - total_repos: Number of repositories scanned
                - total_files: Total files scanned
                - total_findings: Total findings
                - statistics: Detailed statistics dictionary
                - duration_seconds: Total scan duration
        """
        checkpoint_data = {
            'checkpoint_type': 'summary',
            'timestamp': datetime.now().isoformat(),
            'summary': summary_data
        }

        self.atomic_write(self.summary_checkpoint_path, checkpoint_data)
        # Also update latest checkpoint
        self.atomic_write(self.latest_checkpoint_path, checkpoint_data)

    def load_latest_checkpoint(self) -> Optional[Dict]:
        """
        Load the most recent checkpoint of any type.

        Returns:
            Latest checkpoint data, or None if no checkpoint exists

        Checks checkpoints in order of specificity:
        1. File-level (most recent/specific)
        2. Repo-level
        3. Summary-level
        """
        # Try file-level first (most recent)
        if self.latest_checkpoint_path.exists():
            try:
                with open(self.latest_checkpoint_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"WARNING: Failed to load latest checkpoint: {e}")

        # Fallback: try repo-level
        if self.repo_checkpoint_path.exists():
            try:
                with open(self.repo_checkpoint_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"WARNING: Failed to load repo checkpoint: {e}")

        # Fallback: try file-level
        if self.file_checkpoint_path.exists():
            try:
                with open(self.file_checkpoint_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"WARNING: Failed to load file checkpoint: {e}")

        return None

    def load_file_checkpoint(self) -> Optional[Dict]:
        """Load specifically the file-level checkpoint."""
        if not self.file_checkpoint_path.exists():
            return None

        try:
            with open(self.file_checkpoint_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"ERROR: Failed to load file checkpoint: {e}")
            return None

    def load_repo_checkpoint(self) -> Optional[Dict]:
        """Load specifically the repo-level checkpoint."""
        if not self.repo_checkpoint_path.exists():
            return None

        try:
            with open(self.repo_checkpoint_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"ERROR: Failed to load repo checkpoint: {e}")
            return None

    def atomic_write(self, filepath: Path, content: Dict) -> None:
        """
        Atomically write JSON data to file.

        Uses temp file + rename pattern for atomicity:
        1. Write to temporary file in same directory
        2. fsync to ensure data is on disk
        3. Rename temp file to target (atomic on POSIX)

        Args:
            filepath: Target file path
            content: Dictionary to serialize as JSON
        """
        filepath = Path(filepath)

        try:
            # Create temp file in same directory (ensures same filesystem)
            temp_fd, temp_path = tempfile.mkstemp(
                dir=filepath.parent,
                prefix='.tmp_checkpoint_',
                suffix='.json'
            )

            try:
                # Write JSON to temp file
                with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                    json.dump(content, f, indent=2)
                    f.flush()
                    # Force write to disk (critical for crash safety)
                    os.fsync(f.fileno())

                # Atomically rename temp file to target
                # This is atomic on POSIX systems (including macOS, Linux)
                os.rename(temp_path, filepath)

            except Exception:
                # Clean up temp file on error
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass
                raise

        except Exception as e:
            print(f"ERROR: Failed to write checkpoint atomically: {e}")
            # Don't crash - graceful degradation
            # Scanner can continue without checkpoints (just lose recovery ability)

    def clear_checkpoints(self) -> None:
        """
        Clear all checkpoint files (start fresh scan).

        Used when starting a new scan from scratch.
        """
        checkpoints = [
            self.file_checkpoint_path,
            self.repo_checkpoint_path,
            self.summary_checkpoint_path,
            self.latest_checkpoint_path
        ]

        for checkpoint_file in checkpoints:
            if checkpoint_file.exists():
                try:
                    checkpoint_file.unlink()
                except Exception as e:
                    print(f"WARNING: Failed to delete checkpoint {checkpoint_file}: {e}")

    def checkpoint_exists(self) -> bool:
        """
        Check if any checkpoint exists.

        Returns:
            True if at least one checkpoint file exists
        """
        return (
            self.latest_checkpoint_path.exists() or
            self.file_checkpoint_path.exists() or
            self.repo_checkpoint_path.exists()
        )

    def get_checkpoint_info(self) -> Dict:
        """
        Get information about existing checkpoints.

        Returns:
            Dictionary with checkpoint metadata:
                - has_file_checkpoint: bool
                - has_repo_checkpoint: bool
                - has_summary_checkpoint: bool
                - latest_timestamp: ISO timestamp of latest checkpoint
                - latest_type: Type of latest checkpoint
        """
        info = {
            'has_file_checkpoint': self.file_checkpoint_path.exists(),
            'has_repo_checkpoint': self.repo_checkpoint_path.exists(),
            'has_summary_checkpoint': self.summary_checkpoint_path.exists(),
            'latest_timestamp': None,
            'latest_type': None
        }

        latest = self.load_latest_checkpoint()
        if latest:
            info['latest_timestamp'] = latest.get('timestamp')
            info['latest_type'] = latest.get('checkpoint_type')

        return info
