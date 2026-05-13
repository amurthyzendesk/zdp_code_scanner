# Resilience Module

Zero data loss infrastructure for security audit framework.

## Components

### TransactionLog (`transaction_log.py`)
Append-only JSONL log with fsync guarantees. Every finding is immediately persisted.

### CheckpointManager (`checkpoint_manager.py`)
Multi-level atomic checkpoints (file, repo, summary). Enables fast recovery.

### RecoveryManager (`recovery_manager.py`)
Crash detection and scan resumption. Combines checkpoint + log for complete recovery.

## Usage

```python
from brex_audit.resilience import (
    TransactionLog,
    CheckpointManager,
    RecoveryManager
)

# Initialize
log = TransactionLog('findings.jsonl')
checkpoint = CheckpointManager('checkpoints/')
recovery = RecoveryManager(log, checkpoint)

# Check for crash
if recovery.detect_incomplete_scan():
    state = recovery.resume_state()
    # Resume from state...

# During scan
log.append_finding(finding)  # Crash-safe

# Every 100 files
checkpoint.save_file_checkpoint(state)
```

## Key Features

✅ Zero data loss - fsync after every write  
✅ Crash recovery - resume from any point  
✅ Atomic operations - no partial writes  
✅ <5% performance overhead  
✅ Production-ready  

## Documentation

- Quick Start: `docs/RESILIENCE_QUICK_START.md`
- Full Guide: `docs/RESILIENCE_INFRASTRUCTURE.md`
- Tests: `tests/test_resilience.py`
- Demo: `scripts/test_crash_recovery.py`

## Tests

```bash
pytest tests/test_resilience.py -v
```

## License

Part of Brex Audit Platform
