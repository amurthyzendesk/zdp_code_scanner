"""
Consensus Module
================

Multi-agent consensus mechanisms for security findings.

Components:
- CoTMerger: Merges Chain of Thought reasoning from multiple agents
"""

from .cot_merger import CoTMerger, merge_chain_of_thoughts

__all__ = ['CoTMerger', 'merge_chain_of_thoughts']
