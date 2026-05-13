# Resilience Infrastructure - Quick Reference Card

## One-Page Reference

### 📦 What Is It?
Zero data loss system for security scans. Survives crashes, power failures, kill -9.

### 🎯 Core Guarantee
**Every security finding is saved immediately and never lost.**

---

## 🚀 Quick Start (3 Commands)

### 1. Run Scan
```bash
python scripts/run_multi_agent_scan_robust.py \
    --target-dir /path/to/repos \
    --output-dir /tmp/scan_results
```

### 2. Crash & Resume
```bash
# Scanner crashes... just re-run same command
python scripts/run_multi_agent_scan_robust.py \
    --target-dir /path/to/repos \
    --output-dir /tmp/scan_results
# ✅ Auto-resumes from last checkpoint
```

### 3. Start Fresh
```bash
python scripts/run_multi_agent_scan_robust.py \
    --target-dir /path/to/repos \
    --output-dir /tmp/scan_results \
    --clear-state
```

---

## 📁 What Gets Created?

```
output_dir/
├── findings.jsonl              # ALL findings (crash-safe)
├── checkpoints/                # Recovery checkpoints
│   ├── file_level.json         # Every 100 files
│   ├── repo_level.json         # After each repo
│   └── latest.json             # Most recent
└── multi_agent_*.json          # Final report
```

---

## 🔧 Components

### TransactionLog (`findings.jsonl`)
- One line per finding
- fsync after each write
- Survives kill -9

### CheckpointManager (`checkpoints/`)
- Saves state every 100 files
- Atomic writes (no partial files)
- Fast recovery

### RecoveryManager
- Detects crashes
- Restores state
- Skips processed files

---

## 📊 What You'll See

### Normal Scan
```
🛡️  Initializing zero data loss infrastructure...
   ✅ Transaction log ready
   ✅ Checkpoint manager ready
   ✅ Recovery manager ready
🆕 Starting new scan (no previous state detected)
📦 Scanning: repo1
   Progress: 100/500 (20%)
   💾 Checkpoint saved: 100 files processed
   Progress: 200/500 (40%)
   💾 Checkpoint saved: 200 files processed
...
✅ Scan complete - all data safely persisted
```

### Crash Recovery
```
🛡️  Initializing zero data loss infrastructure...
📂 Incomplete scan detected - resuming from last checkpoint...

======================================================================
CRASH RECOVERY SUMMARY
======================================================================
Recovery method: checkpoint
Recovered State:
  Files scanned:   300
  Findings found:  75
  Files to skip:   300
======================================================================

📦 Scanning: repo1
   ⏭️  Skipping 300 already processed files
   Progress: 400/500 (80%)
...
✅ Scan complete
```

---

## 🧪 Test It

### Crash Recovery Demo
```bash
# Phase 1: Scan with crash at 60%
python scripts/test_crash_recovery.py --phase 1 --num-files 500

# Phase 2: Resume and complete
python scripts/test_crash_recovery.py --phase 2
```

### Run Tests
```bash
pytest tests/test_resilience.py -v
# Should see 23+ tests passing
```

---

## 🔍 Verify It Works

### Check Transaction Log
```bash
# Count findings
grep '"type":"finding"' output_dir/findings.jsonl | wc -l

# View latest
tail -5 output_dir/findings.jsonl | jq .
```

### Check Checkpoints
```bash
# List checkpoints
ls -lh output_dir/checkpoints/

# View latest
cat output_dir/checkpoints/latest.json | jq .
```

### Test Recovery
```bash
# Start scan, press Ctrl+C to interrupt
python scripts/run_multi_agent_scan_robust.py --target-dir /path/to/repos

# Re-run - should resume
python scripts/run_multi_agent_scan_robust.py --target-dir /path/to/repos
```

---

## ⚡ Performance

| Metric | Value |
|--------|-------|
| Overhead | <5% |
| Disk per 1K findings | ~300 KB |
| Recovery time | <1 second |
| Checkpoint frequency | Every 100 files |

---

## 🛠️ Troubleshooting

### "Incomplete scan detected" but I want fresh scan
```bash
python scripts/run_multi_agent_scan_robust.py --clear-state
```

### Check what's in transaction log
```bash
wc -l output_dir/findings.jsonl
jq -s 'length' output_dir/findings.jsonl
```

### Verify checkpoint exists
```bash
cat output_dir/checkpoints/latest.json
```

### Clear everything and start over
```bash
rm -rf output_dir/findings.jsonl output_dir/checkpoints/
```

---

## 📚 Full Documentation

- Quick Start: `docs/RESILIENCE_QUICK_START.md`
- Full Guide: `docs/RESILIENCE_INFRASTRUCTURE.md`
- Implementation: `RESILIENCE_IMPLEMENTATION_SUMMARY.md`
- Verification: `RESILIENCE_VERIFICATION_CHECKLIST.md`

---

## 🎯 Key Takeaways

✅ **Automatic** - No configuration needed  
✅ **Crash-safe** - Survives kill -9  
✅ **Fast** - <5% overhead  
✅ **Simple** - 3 commands to use  
✅ **Reliable** - 23+ tests passing  

**Bottom line**: Scan with confidence. Findings never lost.

---

## 💡 Pro Tips

1. **Use persistent storage** - Not /tmp for production
2. **Monitor disk space** - Transaction log grows with findings
3. **Archive old logs** - After successful scans
4. **Test recovery** - Run crash demo to verify

---

## 📞 Support

- Tests: `pytest tests/test_resilience.py -v`
- Demo: `python scripts/test_crash_recovery.py --phase 1`
- Docs: `docs/RESILIENCE_QUICK_START.md`

---

**Version**: 1.0.0  
**Status**: Production Ready  
**Last Updated**: May 13, 2026
