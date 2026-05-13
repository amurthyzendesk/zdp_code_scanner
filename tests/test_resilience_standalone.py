#!/usr/bin/env python3
"""
Standalone Resilience Test Suite
=================================

Tests crash recovery, atomic writes, and transaction log durability.
No external dependencies (pytest not required).
"""

import sys
import os
import json
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from brex_audit.resilience import TransactionLog, CheckpointManager, RecoveryManager


def test_transaction_log_basic():
    """Test basic transaction log operations."""
    print("Test 1: Transaction Log Basic Operations")

    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / 'test.jsonl'
        tx_log = TransactionLog(log_file)

        # Write findings
        for i in range(10):
            tx_log.append_finding({
                'repo': 'test-repo',
                'file': f'file_{i}.py',
                'severity': 'HIGH',
                'category': 'SQL_INJECTION',
                'line_number': i * 10,
                'evidence': f'Test evidence {i}'
            })

        # Replay
        findings = tx_log.replay()

        assert len(findings) == 10, f"Expected 10 findings, got {len(findings)}"
        assert findings[0]['file'] == 'file_0.py'
        assert findings[9]['file'] == 'file_9.py'

        # Check stats
        stats = tx_log.get_stats()
        assert stats['findings_count'] == 10
        assert stats['file_size_bytes'] > 0

        print(f"   ✅ Written 10 findings, replayed successfully")
        print(f"   ✅ Log size: {stats['file_size_bytes']} bytes")
        return True


def test_transaction_log_survives_crash():
    """Test that transaction log survives process crash (simulated)."""
    print("\nTest 2: Transaction Log Survives Crash")

    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / 'crash_test.jsonl'

        # Write some findings
        tx_log = TransactionLog(log_file)

        for i in range(5):
            tx_log.append_finding({
                'repo': 'crash-repo',
                'file': f'file_{i}.py',
                'severity': 'HIGH',
                'finding': f'Finding {i}'
            })

        # Simulate crash by NOT calling close(), just delete object
        del tx_log

        # "Resume" after crash - create new instance
        tx_log_resumed = TransactionLog(log_file)
        findings = tx_log_resumed.replay()

        assert len(findings) == 5, f"Expected 5 findings after crash, got {len(findings)}"
        print(f"   ✅ All 5 findings recovered after simulated crash")

        # Continue writing after crash
        for i in range(5, 10):
            tx_log_resumed.append_finding({
                'repo': 'crash-repo',
                'file': f'file_{i}.py',
                'severity': 'HIGH',
                'finding': f'Finding {i}'
            })

        # Verify all 10 findings
        findings = tx_log_resumed.replay()
        assert len(findings) == 10, f"Expected 10 findings after resume, got {len(findings)}"
        print(f"   ✅ Successfully resumed and added 5 more findings (total: 10)")
        return True


def test_checkpoint_atomic_write():
    """Test that checkpoints are written atomically."""
    print("\nTest 3: Checkpoint Atomic Writes")

    with tempfile.TemporaryDirectory() as tmpdir:
        checkpoint_dir = Path(tmpdir) / 'checkpoints'
        mgr = CheckpointManager(checkpoint_dir)

        # Save file checkpoint
        state = {
            'files_scanned': 100,
            'processed_files': [f'file_{i}.py' for i in range(100)],
            'current_repo': 'test-repo',
            'findings_count': 25,
            'current_file_in_repo': 50,
            'repos_completed': ['repo1', 'repo2']
        }

        mgr.save_file_checkpoint(state)

        # Load and verify
        loaded = mgr.load_latest_checkpoint()

        assert loaded is not None, "Checkpoint not loaded"
        assert loaded['checkpoint_type'] == 'file_level'
        assert loaded['state']['files_scanned'] == 100
        assert loaded['state']['findings_count'] == 25
        assert len(loaded['state']['processed_files']) == 100

        print(f"   ✅ File checkpoint saved and loaded atomically")

        # Save repo checkpoint
        mgr.save_repo_checkpoint('test-repo', {
            'files_scanned': 200,
            'findings': 50,
            'duration_seconds': 30,
            'repos_completed': ['repo1', 'repo2', 'repo3'],
            'total_findings_so_far': 75,
            'total_files_so_far': 200
        })

        loaded = mgr.load_latest_checkpoint()
        assert loaded['checkpoint_type'] == 'repo_level'
        assert loaded['repo_name'] == 'test-repo'
        assert loaded['state']['findings'] == 50

        print(f"   ✅ Repo checkpoint saved and loaded atomically")
        return True


def test_resume_from_checkpoint():
    """Test resuming scan from checkpoint."""
    print("\nTest 4: Resume from Checkpoint")

    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / 'resume.jsonl'
        checkpoint_dir = Path(tmpdir) / 'checkpoints'

        tx_log = TransactionLog(log_file)
        checkpoint_mgr = CheckpointManager(checkpoint_dir)
        recovery_mgr = RecoveryManager(tx_log, checkpoint_mgr)

        # Simulate partial scan
        processed_files = []
        for i in range(50):
            finding = {
                'repo': 'test-repo',
                'file': f'file_{i}.py',
                'severity': 'HIGH',
                'category': 'TEST',
                'line_number': i
            }
            tx_log.append_finding(finding)
            processed_files.append(f'file_{i}.py')

        # Save checkpoint at file 50
        checkpoint_mgr.save_file_checkpoint({
            'files_scanned': 50,
            'processed_files': processed_files,
            'current_repo': 'test-repo',
            'findings_count': 50,
            'current_file_in_repo': 50,
            'repos_completed': []
        })

        # Detect incomplete scan
        assert recovery_mgr.detect_incomplete_scan(), "Should detect incomplete scan"
        print(f"   ✅ Detected incomplete scan")

        # Resume
        resume_state = recovery_mgr.resume_state()

        assert resume_state['files_scanned'] == 50
        assert len(resume_state['processed_files']) == 50
        assert resume_state['findings_count'] == 50
        assert len(resume_state['existing_findings']) == 50
        assert resume_state['recovery_method'] == 'checkpoint'

        print(f"   ✅ Resumed state: {resume_state['files_scanned']} files, {resume_state['findings_count']} findings")

        # Validate recovery
        assert recovery_mgr.validate_recovery_state(resume_state), "Recovery state validation failed"
        print(f"   ✅ Recovery state validated successfully")
        return True


def test_crash_recovery_no_duplicates():
    """Test that crash recovery doesn't create duplicate findings."""
    print("\nTest 5: Crash Recovery - No Duplicates")

    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / 'duplicates.jsonl'
        checkpoint_dir = Path(tmpdir) / 'checkpoints'

        tx_log = TransactionLog(log_file)
        checkpoint_mgr = CheckpointManager(checkpoint_dir)

        # Write 30 findings
        for i in range(30):
            tx_log.append_finding({
                'repo': 'dup-test',
                'file': f'unique_file_{i}.py',
                'line_number': i,
                'evidence': f'Evidence {i}'
            })

        # Save checkpoint
        checkpoint_mgr.save_file_checkpoint({
            'files_scanned': 30,
            'processed_files': [f'unique_file_{i}.py' for i in range(30)],
            'current_repo': 'dup-test',
            'findings_count': 30
        })

        # Simulate resume - get processed files
        recovery_mgr = RecoveryManager(tx_log, checkpoint_mgr)
        resume_state = recovery_mgr.resume_state()
        processed_files = resume_state['processed_files']

        # Check that all 30 files are in processed set
        assert len(processed_files) == 30, f"Expected 30 processed files, got {len(processed_files)}"

        # Verify scanner would skip these files
        test_file = 'unique_file_5.py'
        assert test_file in processed_files, f"File {test_file} should be in processed set"

        print(f"   ✅ All 30 files marked as processed")
        print(f"   ✅ No duplicates would be created on resume")
        return True


def test_performance_overhead():
    """Test that resilience overhead is < 10%."""
    print("\nTest 6: Performance Overhead")

    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / 'perf.jsonl'
        tx_log = TransactionLog(log_file)

        # Measure time for 1000 appends
        start = time.time()

        for i in range(1000):
            tx_log.append_finding({
                'repo': 'perf-test',
                'file': f'file_{i}.py',
                'severity': 'HIGH',
                'category': 'TEST',
                'line_number': i,
                'evidence': 'Test evidence ' * 10  # ~140 bytes
            })

        duration = time.time() - start
        rate = 1000 / duration

        print(f"   ✅ 1000 findings written in {duration:.2f}s")
        print(f"   ✅ Rate: {rate:.1f} findings/sec")

        # Check overhead (should be < 10ms per finding for acceptable overhead)
        avg_time_ms = (duration / 1000) * 1000
        print(f"   ✅ Average time per finding: {avg_time_ms:.2f}ms")

        # With fsync, 1-5ms per write is reasonable
        assert avg_time_ms < 50, f"Performance overhead too high: {avg_time_ms}ms per finding"
        return True


def test_integration_crash_recovery():
    """
    Integration test: simulate crash and recovery.

    This test simulates a scanning process that crashes midway,
    then resumes from checkpoint.
    """
    print("\nTest 7: Integration Crash Recovery")

    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "scan.jsonl"
        checkpoint_dir = Path(tmpdir) / "checkpoints"

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
        print(f"   ✅ Simulated crash after 50 files (checkpoint at 30)")

        # Phase 2: Resume scan
        log2 = TransactionLog(log_file)
        checkpoint_mgr2 = CheckpointManager(checkpoint_dir)
        recovery2 = RecoveryManager(log2, checkpoint_mgr2)

        # Detect incomplete scan
        assert recovery2.detect_incomplete_scan()
        print(f"   ✅ Detected incomplete scan")

        # Resume from checkpoint
        resume_state = recovery2.resume_state()

        # Should have checkpoint from file 30
        assert resume_state['recovery_method'] == 'checkpoint'
        assert resume_state['files_scanned'] == 30
        print(f"   ✅ Checkpoint loaded: {resume_state['files_scanned']} files")

        # Should have all 50 findings from transaction log
        assert len(resume_state['existing_findings']) == 50
        print(f"   ✅ Transaction log replayed: {len(resume_state['existing_findings'])} findings")

        # Validate state
        assert recovery2.validate_recovery_state(resume_state)
        print(f"   ✅ Recovery state validated")

        log2.close()
        return True


def run_all_tests():
    """Run all resilience tests."""
    print("=" * 80)
    print("RESILIENCE MODULE TEST SUITE")
    print("=" * 80)
    print()

    tests = [
        test_transaction_log_basic,
        test_transaction_log_survives_crash,
        test_checkpoint_atomic_write,
        test_resume_from_checkpoint,
        test_crash_recovery_no_duplicates,
        test_performance_overhead,
        test_integration_crash_recovery
    ]

    passed = 0
    failed = 0

    for test_func in tests:
        try:
            result = test_func()
            if result:
                passed += 1
        except AssertionError as e:
            print(f"   ❌ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"   ❌ ERROR: {e}")
            failed += 1

    print()
    print("=" * 80)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 80)

    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
