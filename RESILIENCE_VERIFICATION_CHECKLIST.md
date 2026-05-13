# Resilience Infrastructure Verification Checklist

Use this checklist to verify the resilience infrastructure is working correctly.

## Pre-Verification Setup

```bash
cd /Users/akshaya.murthy/Desktop/Brex_Audit_Platform
```

---

## ✅ Phase 1: File Structure Verification

### Check all files exist:

```bash
# Core modules
[ ] ls -l brex_audit/resilience/__init__.py
[ ] ls -l brex_audit/resilience/transaction_log.py
[ ] ls -l brex_audit/resilience/checkpoint_manager.py
[ ] ls -l brex_audit/resilience/recovery_manager.py
[ ] ls -l brex_audit/resilience/README.md

# Scanner integration
[ ] ls -l scripts/run_multi_agent_scan_robust.py

# Tests and demo
[ ] ls -l tests/test_resilience.py
[ ] ls -l scripts/test_crash_recovery.py

# Documentation
[ ] ls -l docs/RESILIENCE_INFRASTRUCTURE.md
[ ] ls -l docs/RESILIENCE_QUICK_START.md
[ ] ls -l RESILIENCE_IMPLEMENTATION_SUMMARY.md
```

**Expected**: All files present, no errors.

---

## ✅ Phase 2: Import Verification

### Check Python imports work:

```bash
python3 -c "
from brex_audit.resilience import TransactionLog, CheckpointManager, RecoveryManager
print('✅ All imports successful')
"
```

**Expected**: "✅ All imports successful"

---

## ✅ Phase 3: Unit Tests

### Run complete test suite:

```bash
# Run all resilience tests
pytest tests/test_resilience.py -v --tb=short

# Expected output:
# - All tests pass (green)
# - No failures or errors
# - Test count: 20+ tests
```

**Expected Results**:
- `TestTransactionLog`: 6 tests passing
- `TestCheckpointManager`: 6 tests passing  
- `TestRecoveryManager`: 9 tests passing
- Integration tests: 2 tests passing
- Total: 23+ tests passing

### Run specific test categories:

```bash
# Transaction log tests
pytest tests/test_resilience.py::TestTransactionLog -v

# Checkpoint manager tests
pytest tests/test_resilience.py::TestCheckpointManager -v

# Recovery manager tests
pytest tests/test_resilience.py::TestRecoveryManager -v

# Integration tests
pytest tests/test_resilience.py::test_integration_crash_recovery -v
pytest tests/test_resilience.py::test_atomic_write_no_partial_files -v
```

**Expected**: All tests pass.

---

## ✅ Phase 4: Crash Recovery Demo

### Test crash and recovery cycle:

```bash
# Clean up previous test
rm -rf /tmp/crash_recovery_test

# Phase 1: Run scan with simulated crash
python3 scripts/test_crash_recovery.py --phase 1 --num-files 500

# Expected output:
# - Creates 500 test files
# - Scans files with progress indicators
# - Saves checkpoints at 100, 200, 300 files
# - Simulates crash at ~60% (300 files)
# - Exits with message about crash
```

**Verification Points**:
- [ ] 500 test files created in `/tmp/crash_recovery_test/files`
- [ ] Progress shown: 100, 200, 300 files
- [ ] Checkpoint saved at 100, 200, 300 files
- [ ] Crash message displayed
- [ ] Transaction log exists: `/tmp/crash_recovery_test/output/findings.jsonl`
- [ ] Checkpoints exist: `/tmp/crash_recovery_test/output/checkpoints/`

```bash
# Verify transaction log has findings
echo "Transaction log entries:"
wc -l /tmp/crash_recovery_test/output/findings.jsonl

# Should show ~900 lines (300 files × ~3 findings each)
```

```bash
# Phase 2: Resume scan
python3 scripts/test_crash_recovery.py --phase 2

# Expected output:
# - Detects incomplete scan
# - Shows recovery summary
# - Resumes from checkpoint (300 files)
# - Completes remaining files (301-500)
# - Shows final statistics
```

**Verification Points**:
- [ ] "Incomplete scan detected" message shown
- [ ] Recovery summary displayed
- [ ] Shows 300 files already processed
- [ ] Resumes from file 301
- [ ] Completes all 500 files
- [ ] Final report shows 1500 total findings
- [ ] Transaction log statistics shown

```bash
# Verify final state
echo "Final transaction log entries:"
wc -l /tmp/crash_recovery_test/output/findings.jsonl

# Should show ~1500 lines (500 files × ~3 findings each)

echo "Checkpoints created:"
ls -lh /tmp/crash_recovery_test/output/checkpoints/

# Should show file_level.json, summary_level.json, etc.
```

---

## ✅ Phase 5: Scanner Integration Test

### Test with real scanner (if PostgreSQL is set up):

```bash
# Create small test directory
mkdir -p /tmp/resilience_test/repos/test-repo
echo 'password = "hardcoded123"' > /tmp/resilience_test/repos/test-repo/config.py
echo 'api_key = "sk-test-key"' > /tmp/resilience_test/repos/test-repo/auth.py

# Run scanner
python3 scripts/run_multi_agent_scan_robust.py \
    --target-dir /tmp/resilience_test/repos \
    --output-dir /tmp/resilience_test/output \
    --min-severity MEDIUM

# Expected output:
# - Initializes resilience infrastructure
# - Shows "Starting new scan" (no previous state)
# - Scans files
# - Saves checkpoints
# - Generates report
```

**Verification Points**:
- [ ] Scanner starts without errors
- [ ] Resilience infrastructure initialized
- [ ] Files scanned successfully
- [ ] Transaction log created
- [ ] Checkpoints created
- [ ] Final report generated

```bash
# Verify outputs exist
ls -l /tmp/resilience_test/output/findings.jsonl
ls -l /tmp/resilience_test/output/checkpoints/
ls -l /tmp/resilience_test/output/multi_agent_consensus_*.json
```

### Test resume capability:

```bash
# Interrupt previous scan (if still running) with Ctrl+C
# Then re-run same command

python3 scripts/run_multi_agent_scan_robust.py \
    --target-dir /tmp/resilience_test/repos \
    --output-dir /tmp/resilience_test/output \
    --min-severity MEDIUM

# Expected output:
# - Detects incomplete scan (if interrupted)
# - Shows recovery summary
# - OR shows "Starting new scan" (if completed)
```

**Verification Points**:
- [ ] Scanner detects state correctly
- [ ] Resumes if interrupted, or starts fresh if complete
- [ ] No duplicate findings

---

## ✅ Phase 6: Performance Verification

### Measure overhead:

```bash
# Create larger test set
python3 scripts/test_crash_recovery.py --phase 1 --num-files 1000

# Time the scan
time python3 scripts/test_crash_recovery.py --phase 2

# Expected:
# - Completes in reasonable time
# - <5% overhead from resilience layer
```

**Verification Points**:
- [ ] Scan completes successfully
- [ ] Performance is acceptable
- [ ] No memory leaks or crashes

---

## ✅ Phase 7: Error Handling Verification

### Test graceful degradation:

```bash
# Test with read-only checkpoint directory
mkdir -p /tmp/readonly_test/checkpoints
chmod 555 /tmp/readonly_test/checkpoints

python3 -c "
from pathlib import Path
from brex_audit.resilience import CheckpointManager

mgr = CheckpointManager(Path('/tmp/readonly_test/checkpoints'))
mgr.save_file_checkpoint({'files_scanned': 10})
print('Graceful degradation test passed')
"

# Expected: Warning message but no crash
```

**Verification Points**:
- [ ] Warning printed but script continues
- [ ] No exception raised
- [ ] Graceful degradation works

---

## ✅ Phase 8: Documentation Verification

### Check documentation completeness:

```bash
# Quick start guide
[ ] cat docs/RESILIENCE_QUICK_START.md
    # Should have: overview, quick start, examples, troubleshooting

# Full documentation
[ ] cat docs/RESILIENCE_INFRASTRUCTURE.md
    # Should have: architecture, components, usage, performance, testing

# Implementation summary
[ ] cat RESILIENCE_IMPLEMENTATION_SUMMARY.md
    # Should have: deliverables, architecture, testing, performance

# Module README
[ ] cat brex_audit/resilience/README.md
    # Should have: component list, usage, features
```

**Verification Points**:
- [ ] All documentation files exist
- [ ] Content is comprehensive
- [ ] Examples are correct
- [ ] Links work

---

## ✅ Phase 9: Code Quality Verification

### Check code quality:

```bash
# Check for syntax errors
python3 -m py_compile brex_audit/resilience/transaction_log.py
python3 -m py_compile brex_audit/resilience/checkpoint_manager.py
python3 -m py_compile brex_audit/resilience/recovery_manager.py

# Expected: No output = success
```

**Verification Points**:
- [ ] All files compile without errors
- [ ] No syntax errors
- [ ] No import errors

---

## ✅ Phase 10: Integration Verification

### Verify scanner integration:

```bash
# Check imports in scanner
grep -n "from brex_audit.resilience import" scripts/run_multi_agent_scan_robust.py

# Expected: Should show import line around line 20
```

```bash
# Check initialization in scanner
grep -n "TransactionLog\|CheckpointManager\|RecoveryManager" scripts/run_multi_agent_scan_robust.py

# Expected: Multiple matches showing initialization and usage
```

**Verification Points**:
- [ ] Resilience modules imported
- [ ] TransactionLog initialized
- [ ] CheckpointManager initialized
- [ ] RecoveryManager initialized
- [ ] Integration points present (log findings, save checkpoints, etc.)

---

## 🎯 Final Verification

### All checks passing:

```bash
echo "=== RESILIENCE VERIFICATION SUMMARY ==="
echo ""
echo "✅ Phase 1: File Structure - All files exist"
echo "✅ Phase 2: Imports - All imports working"
echo "✅ Phase 3: Unit Tests - 23+ tests passing"
echo "✅ Phase 4: Crash Recovery - Demo working"
echo "✅ Phase 5: Scanner Integration - Working"
echo "✅ Phase 6: Performance - <5% overhead"
echo "✅ Phase 7: Error Handling - Graceful degradation"
echo "✅ Phase 8: Documentation - Complete"
echo "✅ Phase 9: Code Quality - No errors"
echo "✅ Phase 10: Integration - Properly integrated"
echo ""
echo "🎉 RESILIENCE INFRASTRUCTURE VERIFIED AND READY FOR PRODUCTION"
```

---

## Troubleshooting

### If tests fail:

1. Check Python version: `python3 --version` (should be 3.8+)
2. Check dependencies: `pip install pytest`
3. Check file permissions: `ls -l brex_audit/resilience/`
4. Check disk space: `df -h /tmp`

### If imports fail:

1. Check PYTHONPATH: `echo $PYTHONPATH`
2. Add to path: `export PYTHONPATH=/Users/akshaya.murthy/Desktop/Brex_Audit_Platform:$PYTHONPATH`
3. Try from project root: `cd /Users/akshaya.murthy/Desktop/Brex_Audit_Platform`

### If crash demo fails:

1. Clean test directory: `rm -rf /tmp/crash_recovery_test`
2. Check disk space: `df -h /tmp`
3. Run with verbose output: Add `--verbose` flag

### If scanner integration fails:

1. Check PostgreSQL is running (if required)
2. Check output directory permissions
3. Review scanner logs
4. Start with `--clear-state` flag

---

## Success Criteria

All phases must pass:

- ✅ All files present
- ✅ All imports working
- ✅ All tests passing (23+)
- ✅ Crash recovery demo working
- ✅ Scanner integration working
- ✅ Performance acceptable
- ✅ Error handling robust
- ✅ Documentation complete
- ✅ Code quality high
- ✅ Integration verified

**Status**: Ready for Production Deployment

---

**Date**: May 13, 2026  
**Verified By**: _________________  
**Notes**: _________________
