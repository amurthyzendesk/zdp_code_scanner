#!/usr/bin/env python3
"""
Test Suite for Resilience Infrastructure
=========================================

Tests crash recovery, atomic writes, and transaction log durability.
"""

import os
import sys
import json
import tempfile
import signal
import subprocess
import time
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from brex_audit.resilience import TransactionLog, CheckpointManager, RecoveryManager


class TestTransactionLog:
    """Test transaction log crash safety and replay."""

    def test_basic_append_and_replay(self, tmp_path):
        """Test basic append and replay functionality."""
        log_file = tmp_path / "test.jsonl"
        log = TransactionLog(log_file)

        # Append some findings
        for i in range(10):
            log.append_finding({
                'repo': 'test-repo',
                'file': f'file_{i}.py',
                'severity': 'HIGH',
                'category': 'HARDCODED_SECRET',
                'line_number': i * 10,
                'evidence': f'secret_{i}',
                'consensus_level': 3
            })

        # Replay and verify
        findings = log.replay()
        assert len(findings) == 10, f"Expected 10 findings, got {len(findings)}"

        for i, finding in enumerate(findings):
            assert finding['repo'] == 'test-repo'
            assert finding['file'] == f'file_{i}.py'
            assert finding['line_number'] == i * 10

        log.close()

    def test_checkpoint_markers_excluded_from_replay(self, tmp_path):
        """Test that checkpoint markers are not included in replay."""
        log_file = tmp_path / "test.jsonl"
        log = TransactionLog(log_file)

        # Append findings and checkpoints
        for i in range(5):
            log.append_finding({
                'repo': 'test-repo',
                'file': f'file_{i}.py',
                'severity': 'HIGH',
                'line_number': i
            })

        log.append_checkpoint({
            'files_scanned': 5,
            'current_repo': 'test-repo'
        })

        for i in range(5, 10):
            log.append_finding({
                'repo': 'test-repo',
                'file': f'file_{i}.py',
                'severity': 'MEDIUM',
                'line_number': i
            })

        # Replay should only return findings, not checkpoints
        findings = log.replay()
        assert len(findings) == 10, "Should have 10 findings (checkpoints excluded)"

        log.close()

    def test_corrupted_log_continues_reading(self, tmp_path):
        """Test that corrupted lines don't stop replay."""
        log_file = tmp_path / "test.jsonl"
        log = TransactionLog(log_file)

        # Write some valid findings
        for i in range(5):
            log.append_finding({
                'repo': 'test-repo',
                'file': f'file_{i}.py',
                'line_number': i
            })

        # Manually corrupt one line
        with open(log_file, 'a') as f:
            f.write("THIS IS NOT JSON\n")

        # Write more valid findings
        for i in range(5, 10):
            log.append_finding({
                'repo': 'test-repo',
                'file': f'file_{i}.py',
                'line_number': i
            })

        # Should still read valid entries
        findings = log.replay()
        assert len(findings) == 10, "Should skip corrupted line and continue"

        log.close()

    def test_log_stats(self, tmp_path):
        """Test log statistics calculation."""
        log_file = tmp_path / "test.jsonl"
        log = TransactionLog(log_file)

        # Add findings and checkpoints
        for i in range(15):
            log.append_finding({'file': f'file_{i}.py'})

        for i in range(3):
            log.append_checkpoint({'checkpoint': i})

        stats = log.get_stats()
        assert stats['findings_count'] == 15
        assert stats['checkpoint_count'] == 3
        assert stats['total_entries'] == 18
        assert stats['file_size_bytes'] > 0

        log.close()

    def test_last_checkpoint_retrieval(self, tmp_path):
        """Test retrieving the most recent checkpoint."""
        log_file = tmp_path / "test.jsonl"
        log = TransactionLog(log_file)

        # Add findings with checkpoints
        log.append_finding({'file': 'file1.py'})
        log.append_checkpoint({'files_scanned': 1})

        log.append_finding({'file': 'file2.py'})
        log.append_checkpoint({'files_scanned': 2})

        log.append_finding({'file': 'file3.py'})
        log.append_checkpoint({'files_scanned': 3})

        # Get last checkpoint
        last = log.get_last_checkpoint()
        assert last is not None
        assert last['data']['files_scanned'] == 3

        log.close()


class TestCheckpointManager:
    """Test checkpoint manager atomic writes and recovery."""

    def test_atomic_write_creates_file(self, tmp_path):
        """Test that atomic write creates checkpoint file."""
        checkpoint_dir = tmp_path / "checkpoints"
        mgr = CheckpointManager(checkpoint_dir)

        state = {
            'files_scanned': 100,
            'processed_files': ['file1.py', 'file2.py'],
            'current_repo': 'test-repo',
            'findings_count': 42
        }

        mgr.save_file_checkpoint(state)

        # Verify checkpoint was created
        assert mgr.file_checkpoint_path.exists()

        # Verify content
        with open(mgr.file_checkpoint_path) as f:
            data = json.load(f)
            assert data['checkpoint_type'] == 'file_level'
            assert data['state']['files_scanned'] == 100
            assert data['state']['findings_count'] == 42

    def test_latest_checkpoint_updates(self, tmp_path):
        """Test that latest checkpoint is updated."""
        checkpoint_dir = tmp_path / "checkpoints"
        mgr = CheckpointManager(checkpoint_dir)

        # Save file checkpoint
        mgr.save_file_checkpoint({
            'files_scanned': 50,
            'findings_count': 10
        })

        latest = mgr.load_latest_checkpoint()
        assert latest['checkpoint_type'] == 'file_level'
        assert latest['state']['files_scanned'] == 50

        # Save repo checkpoint
        mgr.save_repo_checkpoint('repo1', {
            'files_scanned': 100,
            'findings': 20,
            'repos_completed': ['repo1']
        })

        latest = mgr.load_latest_checkpoint()
        assert latest['checkpoint_type'] == 'repo_level'
        assert latest['state']['files_scanned'] == 100

    def test_checkpoint_frequency(self, tmp_path):
        """Test checkpoint frequency configuration."""
        checkpoint_dir = tmp_path / "checkpoints"
        mgr = CheckpointManager(checkpoint_dir, file_checkpoint_frequency=50)

        assert mgr.file_checkpoint_frequency == 50

    def test_clear_checkpoints(self, tmp_path):
        """Test clearing all checkpoints."""
        checkpoint_dir = tmp_path / "checkpoints"
        mgr = CheckpointManager(checkpoint_dir)

        # Create some checkpoints
        mgr.save_file_checkpoint({'files_scanned': 10})
        mgr.save_repo_checkpoint('repo1', {'files_scanned': 20})

        assert mgr.checkpoint_exists()

        # Clear all
        mgr.clear_checkpoints()

        assert not mgr.checkpoint_exists()

    def test_checkpoint_info(self, tmp_path):
        """Test checkpoint information retrieval."""
        checkpoint_dir = tmp_path / "checkpoints"
        mgr = CheckpointManager(checkpoint_dir)

        # Initially no checkpoints
        info = mgr.get_checkpoint_info()
        assert not info['has_file_checkpoint']
        assert not info['has_repo_checkpoint']
        assert info['latest_timestamp'] is None

        # Add checkpoints
        mgr.save_file_checkpoint({'files_scanned': 10})
        mgr.save_repo_checkpoint('repo1', {'files_scanned': 20})

        info = mgr.get_checkpoint_info()
        assert info['has_file_checkpoint']
        assert info['has_repo_checkpoint']
        assert info['latest_timestamp'] is not None
        assert info['latest_type'] in ['file_level', 'repo_level']


class TestRecoveryManager:
    """Test recovery manager crash detection and state restoration."""

    def test_detect_incomplete_scan_with_checkpoint(self, tmp_path):
        """Test incomplete scan detection via checkpoint."""
        log_file = tmp_path / "test.jsonl"
        checkpoint_dir = tmp_path / "checkpoints"

        log = TransactionLog(log_file)
        checkpoint_mgr = CheckpointManager(checkpoint_dir)
        recovery = RecoveryManager(log, checkpoint_mgr)

        # No checkpoint - not incomplete
        assert not recovery.detect_incomplete_scan()

        # Add checkpoint
        checkpoint_mgr.save_file_checkpoint({
            'files_scanned': 50,
            'findings_count': 10
        })

        # Now incomplete scan detected
        assert recovery.detect_incomplete_scan()

    def test_detect_incomplete_scan_with_log(self, tmp_path):
        """Test incomplete scan detection via transaction log."""
        log_file = tmp_path / "test.jsonl"
        checkpoint_dir = tmp_path / "checkpoints"

        log = TransactionLog(log_file)
        checkpoint_mgr = CheckpointManager(checkpoint_dir)
        recovery = RecoveryManager(log, checkpoint_mgr)

        # Add findings to log
        for i in range(5):
            log.append_finding({'file': f'file_{i}.py'})

        # Should detect incomplete scan
        assert recovery.detect_incomplete_scan()

    def test_resume_from_checkpoint(self, tmp_path):
        """Test resuming from checkpoint."""
        log_file = tmp_path / "test.jsonl"
        checkpoint_dir = tmp_path / "checkpoints"

        log = TransactionLog(log_file)
        checkpoint_mgr = CheckpointManager(checkpoint_dir)
        recovery = RecoveryManager(log, checkpoint_mgr)

        # Create checkpoint
        processed_files = [f'file_{i}.py' for i in range(100)]
        checkpoint_mgr.save_file_checkpoint({
            'files_scanned': 100,
            'processed_files': processed_files,
            'current_repo': 'test-repo',
            'findings_count': 25,
            'repos_completed': ['repo1', 'repo2']
        })

        # Add some findings to log
        for i in range(25):
            log.append_finding({'file': f'file_{i}.py'})

        # Resume
        state = recovery.resume_state()

        assert state['recovery_method'] == 'checkpoint'
        assert state['files_scanned'] == 100
        assert len(state['processed_files']) == 100
        assert state['current_repo'] == 'test-repo'
        assert len(state['existing_findings']) == 25
        assert state['repos_completed'] == ['repo1', 'repo2']

    def test_should_skip_file(self, tmp_path):
        """Test file skip logic during resume."""
        log_file = tmp_path / "test.jsonl"
        checkpoint_dir = tmp_path / "checkpoints"

        log = TransactionLog(log_file)
        checkpoint_mgr = CheckpointManager(checkpoint_dir)
        recovery = RecoveryManager(log, checkpoint_mgr)

        # Create resume state
        resume_state = {
            'processed_files': {'file1.py', 'file2.py', 'file3.py'}
        }

        assert recovery.should_skip_file('file1.py', resume_state)
        assert recovery.should_skip_file('file2.py', resume_state)
        assert not recovery.should_skip_file('file4.py', resume_state)

    def test_should_skip_repo(self, tmp_path):
        """Test repo skip logic during resume."""
        log_file = tmp_path / "test.jsonl"
        checkpoint_dir = tmp_path / "checkpoints"

        log = TransactionLog(log_file)
        checkpoint_mgr = CheckpointManager(checkpoint_dir)
        recovery = RecoveryManager(log, checkpoint_mgr)

        # Create resume state
        resume_state = {
            'repos_completed': ['repo1', 'repo2']
        }

        assert recovery.should_skip_repo('repo1', resume_state)
        assert recovery.should_skip_repo('repo2', resume_state)
        assert not recovery.should_skip_repo('repo3', resume_state)

    def test_validate_recovery_state(self, tmp_path):
        """Test recovery state validation."""
        log_file = tmp_path / "test.jsonl"
        checkpoint_dir = tmp_path / "checkpoints"

        log = TransactionLog(log_file)
        checkpoint_mgr = CheckpointManager(checkpoint_dir)
        recovery = RecoveryManager(log, checkpoint_mgr)

        # Valid state
        valid_state = {
            'start_index': 0,
            'processed_files': set(),
            'existing_findings': [],
            'repos_completed': [],
            'recovery_method': 'checkpoint',
            'findings_count': 0
        }

        assert recovery.validate_recovery_state(valid_state)

        # Invalid state - missing field
        invalid_state = {
            'start_index': 0,
            'processed_files': set()
            # Missing other required fields
        }

        assert not recovery.validate_recovery_state(invalid_state)

    def test_recovery_summary(self, tmp_path):
        """Test recovery summary generation."""
        log_file = tmp_path / "test.jsonl"
        checkpoint_dir = tmp_path / "checkpoints"

        log = TransactionLog(log_file)
        checkpoint_mgr = CheckpointManager(checkpoint_dir)
        recovery = RecoveryManager(log, checkpoint_mgr)

        resume_state = {
            'recovery_method': 'checkpoint',
            'checkpoint_timestamp': '2026-05-13T10:00:00',
            'files_scanned': 500,
            'findings_count': 75,
            'repos_completed': ['repo1', 'repo2', 'repo3'],
            'processed_files': set([f'file_{i}.py' for i in range(500)]),
            'current_repo': 'repo4'
        }

        summary = recovery.get_recovery_summary(resume_state)

        assert 'CRASH RECOVERY SUMMARY' in summary
        assert 'checkpoint' in summary
        assert '500' in summary  # files scanned
        assert '75' in summary   # findings
        assert '3' in summary    # repos completed


def test_integration_crash_recovery(tmp_path):
    """
    Integration test: simulate crash and recovery.

    This test simulates a scanning process that crashes midway,
    then resumes from checkpoint.
    """
    log_file = tmp_path / "scan.jsonl"
    checkpoint_dir = tmp_path / "checkpoints"

    # Phase 1: Initial scan (simulate 50 files)
    log1 = TransactionLog(log_file)
    checkpoint_mgr1 = CheckpointManager(checkpoint_dir)

    processed_files = []
    for i in range(50):
        file_path = f'/repo1/file_{i}.py'
        processed_files.append(file_path)

        # Add finding
        log1.append_finding({
            'repo': 'repo1',
            'file': file_path,
            'severity': 'HIGH',
            'line_number': i * 10
        })

        # Save checkpoint at file 30
        if i == 30:
            checkpoint_mgr1.save_file_checkpoint({
                'files_scanned': 30,
                'processed_files': processed_files[:30],
                'current_repo': 'repo1',
                'findings_count': 30
            })

    # Simulate crash at file 50 (no checkpoint saved)
    log1.close()

    # Phase 2: Resume scan
    log2 = TransactionLog(log_file)
    checkpoint_mgr2 = CheckpointManager(checkpoint_dir)
    recovery2 = RecoveryManager(log2, checkpoint_mgr2)

    # Detect incomplete scan
    assert recovery2.detect_incomplete_scan()

    # Resume from checkpoint
    resume_state = recovery2.resume_state()

    # Should have checkpoint from file 30
    assert resume_state['recovery_method'] == 'checkpoint'
    assert resume_state['files_scanned'] == 30

    # Should have all 50 findings from transaction log
    assert len(resume_state['existing_findings']) == 50

    # Validate state
    assert recovery2.validate_recovery_state(resume_state)

    log2.close()


def test_atomic_write_no_partial_files(tmp_path):
    """
    Test that atomic write never leaves partial checkpoint files.

    This tests the temp-file + rename pattern.
    """
    checkpoint_dir = tmp_path / "checkpoints"
    mgr = CheckpointManager(checkpoint_dir)

    # Save checkpoint
    mgr.save_file_checkpoint({
        'files_scanned': 100,
        'findings_count': 25
    })

    # Verify no temp files left behind
    temp_files = list(checkpoint_dir.glob('.tmp_*'))
    assert len(temp_files) == 0, "No temp files should remain"

    # Verify checkpoint file exists and is valid
    assert mgr.file_checkpoint_path.exists()

    with open(mgr.file_checkpoint_path) as f:
        data = json.load(f)
        assert data['state']['files_scanned'] == 100


# Run tests if executed directly
if __name__ == "__main__":
    import pytest
    pytest.main([__file__, '-v'])
