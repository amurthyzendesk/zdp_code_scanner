#!/usr/bin/env python3
"""
Robust Multi-Agent Security Scanner with Progress Tracking
===========================================================
"""

import sys
import json
from pathlib import Path
from typing import Dict, List
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from brex_audit.security_reviewer_agent import SecurityReviewerAgent, Severity
from brex_audit.privacy_reviewer_agent import PrivacyReviewerAgent
from brex_audit.permission_reviewer_agent import PermissionReviewerAgent
from brex_audit.database import get_database
from brex_audit.resilience import TransactionLog, CheckpointManager, RecoveryManager
from brex_audit.consensus import CoTMerger
from brex_audit.reporting import RepoSummaryGenerator


SCANNABLE_EXTENSIONS = {
    '.py', '.sql', '.yaml', '.yml', '.tf', '.hcl',
    '.js', '.ts', '.jsx', '.tsx', '.java', '.scala',
    '.rb', '.go', '.sh', '.bash', '.json'
}

SKIP_DIRECTORIES = {
    '.git', 'node_modules', 'venv', '.venv', '__pycache__',
    'dist', 'build', 'target', '.idea', '.vscode', 'vendor', 'tools/vendor'
}


def log(msg):
    """Log with immediate flush."""
    print(msg, flush=True)


class MultiAgentScanner:
    def __init__(self, target_dir: str, min_severity: str = "MEDIUM", output_dir: str = None):
        self.target_dir = Path(target_dir)
        self.min_severity = Severity[min_severity]
        self.progress_file = Path("/tmp/multi_agent_scan_progress.txt")

        # Set output directory
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path("/Users/akshaya.murthy/code/Snowflake data security audit/github_scan/scan_results")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        log("=" * 80)
        log("MULTI-AGENT CONSENSUS SECURITY SCANNER WITH RESILIENCE")
        log("=" * 80)
        log("")

        # Initialize resilience infrastructure
        log("🛡️  Initializing zero data loss infrastructure...")
        self.transaction_log = TransactionLog(self.output_dir / 'findings.jsonl')
        self.checkpoint_mgr = CheckpointManager(self.output_dir / 'checkpoints')
        self.recovery_mgr = RecoveryManager(self.transaction_log, self.checkpoint_mgr)
        log("   ✅ Transaction log ready")
        log("   ✅ Checkpoint manager ready")
        log("   ✅ Recovery manager ready")
        log("")

        # Check for incomplete scan
        self.resume_state = None
        self.processed_files = set()
        self.repos_completed = []

        if self.recovery_mgr.detect_incomplete_scan():
            log("📂 Incomplete scan detected - resuming from last checkpoint...")
            self.resume_state = self.recovery_mgr.resume_state()

            if self.recovery_mgr.validate_recovery_state(self.resume_state):
                self.processed_files = self.resume_state['processed_files']
                self.repos_completed = self.resume_state['repos_completed']
                log("")
                log(self.recovery_mgr.get_recovery_summary(self.resume_state))
                log("")
            else:
                log("⚠️  Invalid recovery state - starting fresh scan")
                self.resume_state = None
        else:
            log("🆕 Starting new scan (no previous state detected)")
            log("")

        log("🔧 Initializing 3 specialized security agents...")
        self.security_agent = SecurityReviewerAgent(enable_ast_analysis=True)
        log("   ✅ SecurityReviewerAgent ready")

        self.privacy_agent = PrivacyReviewerAgent()
        log("   ✅ PrivacyReviewerAgent ready")

        self.permission_agent = PermissionReviewerAgent()
        log("   ✅ PermissionReviewerAgent ready")
        log("")

        log("🔧 Connecting to PostgreSQL...")
        self.db = get_database()
        log("   ✅ Database ready")
        log("")

        log("🔧 Initializing CoT merger and summary generator...")
        self.cot_merger = CoTMerger()
        self.summary_generator = RepoSummaryGenerator(self.output_dir / 'summaries')
        log("   ✅ CoT merger ready")
        log("   ✅ Summary generator ready")
        log("")

        # Initialize or restore stats
        if self.resume_state:
            self.stats = {
                'start_time': datetime.now(),
                'files_scanned': self.resume_state.get('files_scanned', 0),
                'findings_per_agent': {
                    'security': 0,
                    'privacy': 0,
                    'permission': 0
                },
                'consensus_findings': {
                    '3_agents': 0,
                    '2_agents': 0,
                    '1_agent': 0
                },
                'findings_by_severity': defaultdict(int),
                'findings_by_category': defaultdict(int),
                'findings_by_repo': defaultdict(int)
            }
            # Pre-populate with resumed findings count
            log(f"📊 Resuming with {self.resume_state.get('findings_count', 0)} existing findings")
        else:
            self.stats = {
                'start_time': datetime.now(),
                'files_scanned': 0,
                'findings_per_agent': {
                    'security': 0,
                    'privacy': 0,
                    'permission': 0
                },
                'consensus_findings': {
                    '3_agents': 0,
                    '2_agents': 0,
                    '1_agent': 0
                },
                'findings_by_severity': defaultdict(int),
                'findings_by_category': defaultdict(int),
                'findings_by_repo': defaultdict(int)
            }


    def save_checkpoint(self, all_findings):
        """
        Save incremental checkpoint after each repository.
        (Legacy method - kept for backwards compatibility)
        """
        # Now handled by checkpoint_manager in scan_repository()
        pass


    def log_progress(self, msg):
        """Log progress to both stdout and file."""
        log(msg)
        with open(self.progress_file, 'a') as f:
            f.write(f"{datetime.now().isoformat()} - {msg}\n")

    def should_scan_file(self, file_path: Path) -> bool:
        if file_path.suffix not in SCANNABLE_EXTENSIONS:
            return False
        for parent in file_path.parents:
            if parent.name in SKIP_DIRECTORIES:
                return False
        try:
            if file_path.stat().st_size > 1_000_000:
                return False
        except OSError:
            return False
        return True

    def find_consensus(self, security_findings, privacy_findings, permission_findings):
        def create_location_map(findings, agent_name):
            location_map = defaultdict(list)
            for f in findings:
                for line_offset in range(-2, 3):
                    key = f.line_number + line_offset
                    location_map[key].append((agent_name, f))
            return location_map

        security_map = create_location_map(security_findings, 'security')
        privacy_map = create_location_map(privacy_findings, 'privacy')
        permission_map = create_location_map(permission_findings, 'permission')

        all_lines = set(security_map.keys()) | set(privacy_map.keys()) | set(permission_map.keys())

        consensus_findings = []
        processed_findings = set()

        for line in sorted(all_lines):
            agents_agreeing = []
            findings_at_line = []

            for line_map, agent in [(security_map, 'security'), (privacy_map, 'privacy'), (permission_map, 'permission')]:
                if line in line_map:
                    for ag, finding in line_map[line]:
                        finding_id = id(finding)
                        if finding_id not in processed_findings:
                            agents_agreeing.append(ag)
                            findings_at_line.append(finding)
                            processed_findings.add(finding_id)

            if findings_at_line:
                highest_severity = max(findings_at_line, key=lambda f: ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(f.severity.value))
                num_agents = len(set(agents_agreeing))
                highest_severity.consensus_level = num_agents
                highest_severity.agreeing_agents = list(set(agents_agreeing))

                # Merge Chain of Thought if multiple agents agree and have CoT
                if num_agents >= 2:
                    cots_to_merge = [f.chain_of_thought for f in findings_at_line if f.chain_of_thought]
                    if len(cots_to_merge) >= 2:
                        try:
                            merged_cot = self.cot_merger.merge_cots(
                                cots_to_merge,
                                num_agents,
                                list(set(agents_agreeing))
                            )
                            highest_severity.chain_of_thought = merged_cot
                        except Exception as e:
                            # If CoT merge fails, keep original
                            logger.warning(f"CoT merge failed: {e}")

                consensus_findings.append(highest_severity)

        return consensus_findings

    def scan_file(self, file_path: Path, current_repo: str) -> Dict:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return {'findings': [], 'agent_counts': {}}

        security_findings = self.security_agent.review_file(str(file_path), content)
        privacy_findings = self.privacy_agent.review_file(str(file_path), content)
        permission_findings = self.permission_agent.review_file(str(file_path), content)

        self.stats['findings_per_agent']['security'] += len(security_findings)
        self.stats['findings_per_agent']['privacy'] += len(privacy_findings)
        self.stats['findings_per_agent']['permission'] += len(permission_findings)

        all_findings = self.find_consensus(security_findings, privacy_findings, permission_findings)

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        min_level = severity_order[self.min_severity]

        filtered = [
            f for f in all_findings
            if severity_order.get(f.severity, 5) <= min_level
        ]

        # CRITICAL: Immediately log each finding to transaction log
        for finding in filtered:
            consensus_level = getattr(finding, 'consensus_level', 1)
            if consensus_level == 3:
                self.stats['consensus_findings']['3_agents'] += 1
            elif consensus_level == 2:
                self.stats['consensus_findings']['2_agents'] += 1
            else:
                self.stats['consensus_findings']['1_agent'] += 1

            self.stats['findings_by_severity'][finding.severity.value] += 1
            self.stats['findings_by_category'][finding.category.value] += 1

            # Write to transaction log immediately (crash-safe)
            self.transaction_log.append_finding({
                'repo': current_repo,
                'file': str(file_path),
                'severity': finding.severity.value,
                'category': finding.category.value,
                'line_number': finding.line_number,
                'evidence': finding.evidence[:200] if len(finding.evidence) > 200 else finding.evidence,
                'recommendation': finding.recommendation[:200] if len(finding.recommendation) > 200 else finding.recommendation,
                'consensus_level': consensus_level,
                'agreeing_agents': getattr(finding, 'agreeing_agents', [])
            })

        return {
            'findings': filtered,
            'agent_counts': {
                'security': len(security_findings),
                'privacy': len(privacy_findings),
                'permission': len(permission_findings)
            }
        }

    def scan_repository(self, repo_path: Path) -> Dict:
        repo_name = repo_path.name

        # Check if repo was already completed
        if self.recovery_mgr.should_skip_repo(repo_name, self.resume_state or {}):
            self.log_progress(f"⏭️  Skipping completed repo: {repo_name}")
            return {}

        self.log_progress(f"📦 Scanning: {repo_name}")

        findings_by_file = {}
        all_files = [f for f in repo_path.rglob('*') if f.is_file() and self.should_scan_file(f)]

        total = len(all_files)
        self.log_progress(f"   Found {total} files to scan")

        repo_start_time = datetime.now()

        for idx, file_path in enumerate(all_files, 1):
            file_path_str = str(file_path)

            # Skip files already processed
            if file_path_str in self.processed_files:
                continue

            result = self.scan_file(file_path, repo_name)
            if result['findings']:
                relative_path = str(file_path.relative_to(repo_path))
                findings_by_file[relative_path] = result['findings']

            # Mark file as processed
            self.processed_files.add(file_path_str)
            self.stats['files_scanned'] += 1

            # Save checkpoint every 100 files
            if self.stats['files_scanned'] % 100 == 0:
                self.checkpoint_mgr.save_file_checkpoint({
                    'files_scanned': self.stats['files_scanned'],
                    'processed_files': list(self.processed_files),
                    'current_repo': repo_name,
                    'findings_count': sum(self.stats['consensus_findings'].values()),
                    'current_file_in_repo': idx,
                    'repos_completed': self.repos_completed
                })
                self.log_progress(f"   💾 Checkpoint saved: {self.stats['files_scanned']} files processed")

            # Log progress every 100 files
            if idx % 100 == 0:
                pct = idx * 100 // total
                elapsed = (datetime.now() - self.stats['start_time']).total_seconds()
                rate = self.stats['files_scanned'] / elapsed if elapsed > 0 else 0
                self.log_progress(f"   Progress: {idx}/{total} ({pct}%) - {rate:.1f} files/sec")

        # Save repo-level checkpoint after completion
        repo_duration = (datetime.now() - repo_start_time).total_seconds()
        self.repos_completed.append(repo_name)

        findings_in_repo = sum(len(f) for f in findings_by_file.values())
        self.checkpoint_mgr.save_repo_checkpoint(repo_name, {
            'files_scanned': len(all_files),
            'findings': findings_in_repo,
            'duration_seconds': repo_duration,
            'repos_completed': self.repos_completed,
            'total_findings_so_far': sum(self.stats['consensus_findings'].values()),
            'total_files_so_far': self.stats['files_scanned']
        })

        self.log_progress(f"   ✅ Complete: {len(findings_by_file)} files with findings")
        self.log_progress(f"   💾 Repo checkpoint saved")
        self.stats['findings_by_repo'][repo_name] = findings_in_repo

        # Generate per-repo summary
        try:
            self.log_progress(f"   📊 Generating summary report for {repo_name}...")
            summary_path = self.summary_generator.generate_summary(
                repo_name=repo_name,
                findings=findings_by_file,
                stats=self.stats.copy(),
                scan_duration=repo_duration
            )
            self.log_progress(f"   ✅ Summary saved: {summary_path.name}")
        except Exception as e:
            self.log_progress(f"   ⚠️  Summary generation failed: {e}")

        return findings_by_file

    def generate_report(self, all_findings: Dict) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append("MULTI-AGENT CONSENSUS SECURITY REPORT (WITH RESILIENCE)")
        lines.append("=" * 80)
        lines.append("")

        duration = (datetime.now() - self.stats['start_time']).total_seconds()
        lines.append(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Duration: {duration:.1f}s ({duration/60:.1f}m)")
        lines.append(f"Files scanned: {self.stats['files_scanned']}")

        # Add resilience stats
        if self.resume_state:
            lines.append(f"Resumed from: {self.resume_state.get('checkpoint_timestamp', 'N/A')}")
            lines.append(f"Recovery method: {self.resume_state.get('recovery_method', 'N/A')}")

        log_stats = self.transaction_log.get_stats()
        lines.append(f"Transaction log entries: {log_stats['findings_count']}")
        lines.append(f"Checkpoints saved: {log_stats['checkpoint_count']}")
        lines.append("")

        lines.append("AGENT FINDINGS (RAW)")
        lines.append("-" * 80)
        total_raw = 0
        for agent, count in self.stats['findings_per_agent'].items():
            lines.append(f"  {agent:20s}: {count:5d} findings")
            total_raw += count
        lines.append(f"  {'Total raw':20s}: {total_raw:5d} findings")
        lines.append("")

        lines.append("CONSENSUS ANALYSIS")
        lines.append("-" * 80)
        three_agent = self.stats['consensus_findings']['3_agents']
        two_agent = self.stats['consensus_findings']['2_agents']
        one_agent = self.stats['consensus_findings']['1_agent']
        total_consensus = three_agent + two_agent + one_agent

        if total_consensus > 0:
            lines.append(f"  3 agents agreeing (highest confidence):  {three_agent:5d} ({three_agent*100//total_consensus}%)")
            lines.append(f"  2 agents agreeing (high confidence):     {two_agent:5d} ({two_agent*100//total_consensus}%)")
            lines.append(f"  1 agent only (medium confidence):        {one_agent:5d} ({one_agent*100//total_consensus}%)")
            lines.append(f"  Total after consensus:                   {total_consensus:5d}")
            lines.append("")

            if total_raw > 0:
                reduction = total_raw - total_consensus
                reduction_pct = reduction * 100 / total_raw
                lines.append(f"  False positives filtered: ~{reduction:5d} ({reduction_pct:.1f}%)")
                lines.append("")

        lines.append("FINDINGS BY SEVERITY")
        lines.append("-" * 80)
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = self.stats['findings_by_severity'].get(severity, 0)
            lines.append(f"  {severity:12s}: {count:5d}")
        lines.append("")

        lines.append("TOP REPOSITORIES BY FINDINGS")
        lines.append("-" * 80)
        top_repos = sorted(
            self.stats['findings_by_repo'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        for repo, count in top_repos:
            lines.append(f"  {repo:50s}: {count:5d}")
        lines.append("")

        return "\n".join(lines)

    def run(self):
        self.log_progress(f"Target: {self.target_dir}")
        self.log_progress(f"Min severity: {self.min_severity.value}")
        self.log_progress("")

        repos = [d for d in self.target_dir.iterdir() if d.is_dir() and not d.name.startswith('.')]
        self.log_progress(f"📚 Found {len(repos)} repositories to scan")
        self.log_progress("")

        all_findings = {}
        for idx, repo in enumerate(repos, 1):
            self.log_progress(f"\n[{idx}/{len(repos)}] Starting repository: {repo.name}")
            findings = self.scan_repository(repo)
            if findings:
                all_findings[repo.name] = findings
                self.save_checkpoint(all_findings)  # Save after each repo

        self.log_progress("\n📊 Generating reports...")

        # Save final summary checkpoint
        total_findings = sum(self.stats['consensus_findings'].values())
        self.checkpoint_mgr.save_summary_checkpoint({
            'total_repos': len(all_findings),
            'total_files': self.stats['files_scanned'],
            'total_findings': total_findings,
            'statistics': {
                'findings_per_agent': dict(self.stats['findings_per_agent']),
                'consensus_findings': dict(self.stats['consensus_findings']),
                'findings_by_severity': dict(self.stats['findings_by_severity']),
                'findings_by_repo': dict(self.stats['findings_by_repo'])
            },
            'duration_seconds': (datetime.now() - self.stats['start_time']).total_seconds()
        })
        self.log_progress(f"   💾 Final summary checkpoint saved")

        report = self.generate_report(all_findings)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = self.output_dir / f"multi_agent_consensus_{timestamp}.txt"

        with open(report_file, 'w') as f:
            f.write(report)
        self.log_progress(f"   ✅ Text report: {report_file}")

        json_file = self.output_dir / f"multi_agent_consensus_{timestamp}.json"
        json_data = {
            'metadata': {
                'scan_type': 'multi_agent_consensus',
                'agents': ['security', 'privacy', 'permission'],
                'scan_date': datetime.now().isoformat(),
                'duration_seconds': (datetime.now() - self.stats['start_time']).total_seconds(),
                'statistics': dict(self.stats['findings_per_agent'])
            },
            'findings': {
                repo: {
                    file: [
                        {
                            'severity': f.severity.value,
                            'category': f.category.value,
                            'line_number': f.line_number,
                            'evidence': f.evidence,
                            'recommendation': f.recommendation,
                            'consensus_level': getattr(f, 'consensus_level', 1),
                            'agreeing_agents': getattr(f, 'agreeing_agents', [])
                        }
                        for f in findings
                    ]
                    for file, findings in files.items()
                }
                for repo, files in all_findings.items()
            }
        }

        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        self.log_progress(f"   ✅ JSON report: {json_file}")

        # Log transaction log info
        self.log_progress(f"   ✅ Transaction log: {self.transaction_log.log_file}")
        self.log_progress(f"   ✅ Checkpoints dir: {self.checkpoint_mgr.checkpoint_dir}")

        self.log_progress("\n" + report)

        # Close resources
        self.transaction_log.close()
        self.db.close()

        self.log_progress("\n✅ Scan complete - all data safely persisted")
        self.log_progress("   In case of crash, scan can resume from last checkpoint")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Multi-Agent Security Scanner with Crash Recovery"
    )
    parser.add_argument(
        "--target-dir",
        default="/Users/akshaya.murthy/code/Snowflake data security audit/github_scan/repos",
        help="Directory containing repositories to scan"
    )
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="MEDIUM",
        help="Minimum severity level to report"
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory for reports and resilience data (default: scan_results)"
    )
    parser.add_argument(
        "--clear-state",
        action="store_true",
        help="Clear previous state and start fresh scan"
    )

    args = parser.parse_args()

    scanner = MultiAgentScanner(
        args.target_dir,
        args.min_severity,
        args.output_dir
    )

    # Clear state if requested
    if args.clear_state:
        log("🗑️  Clearing previous scan state...")
        scanner.recovery_mgr.clear_recovery_state()
        log("   ✅ State cleared - starting fresh")

    scanner.run()
