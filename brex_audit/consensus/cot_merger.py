#!/usr/bin/env python3
"""
Chain of Thought Consensus Merger
==================================

Merges Chain of Thought reasoning from multiple agents when they agree on the same finding.

When 2 or 3 agents detect the same issue at the same location, their individual CoT
reasoning is merged into a comprehensive consensus CoT that represents all perspectives.

Key Features:
- Combines detection reasoning from all agreeing agents
- Aggregates risk analysis from multiple viewpoints
- Merges attack scenarios (union of all steps)
- Synthesizes confidence rationale showing multi-agent agreement
- Combines remediation recommendations
- Shows attribution (which agent contributed what)
"""

from typing import List, Dict, Optional
from dataclasses import dataclass

from brex_audit.models import (
    ChainOfThought,
    DetectionReasoning,
    RiskAnalysis,
    AttackScenario,
    ContextAnalysis,
    FalsePositiveAssessment,
    ConfidenceRationale,
    RemediationReasoning,
    AlternativeExplanations,
    ConfidenceLevel
)


@dataclass
class AgentContribution:
    """Tracks what each agent contributed to the consensus."""
    agent_name: str
    detection_signals: List[str]
    risk_factors: List[str]
    attack_steps: List[str]
    confidence_factors: List[str]
    remediation_alternatives: List[str]


class CoTMerger:
    """
    Merges Chain of Thought reasoning from multiple agents.

    When multiple agents detect the same finding, their CoT reasoning
    is combined to provide a more comprehensive explanation.
    """

    def merge_cots(
        self,
        cots: List[ChainOfThought],
        consensus_level: int,
        agreeing_agents: List[str]
    ) -> ChainOfThought:
        """
        Merge multiple Chain of Thought instances into one consensus CoT.

        Args:
            cots: List of CoT instances from different agents (2-3)
            consensus_level: Number of agents that agreed (2 or 3)
            agreeing_agents: Names of agreeing agents

        Returns:
            Merged ChainOfThought with combined reasoning
        """
        if not cots:
            raise ValueError("Cannot merge empty CoT list")

        if len(cots) == 1:
            # Single agent - just update agreement
            cot = cots[0]
            cot.confidence.agent_agreement = 1
            cot.confidence.agreement_details = f"Single agent detection: {agreeing_agents[0]}"
            return cot

        # Track contributions from each agent
        contributions = self._track_contributions(cots, agreeing_agents)

        # Merge each component
        merged_detection = self._merge_detection(cots, contributions)
        merged_risk = self._merge_risk(cots, contributions)
        merged_attack = self._merge_attack(cots, contributions)
        merged_confidence = self._merge_confidence(cots, consensus_level, agreeing_agents, contributions)
        merged_remediation = self._merge_remediation(cots, contributions)

        # Optional components - merge if present in any CoT
        merged_context = self._merge_context(cots)
        merged_fp = self._merge_false_positive(cots)
        merged_alternatives = self._merge_alternatives(cots)

        # Create consensus CoT
        consensus_cot = ChainOfThought(
            detection=merged_detection,
            risk=merged_risk,
            attack=merged_attack,
            confidence=merged_confidence,
            remediation=merged_remediation,
            context=merged_context,
            false_positive=merged_fp,
            alternatives=merged_alternatives,
            generated_by_agent="ConsensusEngine",
            generated_at=cots[0].generated_at if cots else None
        )

        return consensus_cot

    def _track_contributions(
        self,
        cots: List[ChainOfThought],
        agreeing_agents: List[str]
    ) -> Dict[str, AgentContribution]:
        """Track what each agent contributed."""
        contributions = {}

        for cot, agent_name in zip(cots, agreeing_agents):
            contributions[agent_name] = AgentContribution(
                agent_name=agent_name,
                detection_signals=cot.detection.signals_observed,
                risk_factors=[cot.risk.severity_reasoning],
                attack_steps=cot.attack.attack_steps,
                confidence_factors=cot.confidence.primary_factors,
                remediation_alternatives=cot.remediation.alternative_fixes
            )

        return contributions

    def _merge_detection(
        self,
        cots: List[ChainOfThought],
        contributions: Dict[str, AgentContribution]
    ) -> DetectionReasoning:
        """
        Merge detection reasoning from multiple agents.

        Combines:
        - Pattern descriptions
        - Detection methods
        - Signals observed (union)
        """
        # Use the most specific pattern description
        patterns = [cot.detection.pattern_matched for cot in cots]
        primary_pattern = max(patterns, key=len)  # Longest/most detailed

        # Combine detection methods
        methods = list(set(cot.detection.detection_method for cot in cots))
        combined_method = " + ".join(methods)

        # Union of all signals
        all_signals = []
        for cot in cots:
            all_signals.extend(cot.detection.signals_observed)
        unique_signals = list(dict.fromkeys(all_signals))  # Preserve order, remove duplicates

        # Create evidence summary showing multi-agent agreement
        agent_names = list(contributions.keys())
        evidence = f"{primary_pattern} (detected by {len(agent_names)} agents: {', '.join(agent_names)})"

        return DetectionReasoning(
            pattern_matched=primary_pattern,
            evidence_summary=evidence[:200],
            detection_method=combined_method,
            signals_observed=unique_signals[:10],  # Limit to top 10
            agent_name="ConsensusEngine",
            check_name="multi_agent_consensus"
        )

    def _merge_risk(
        self,
        cots: List[ChainOfThought],
        contributions: Dict[str, AgentContribution]
    ) -> RiskAnalysis:
        """
        Merge risk analysis from multiple agents.

        Aggregates:
        - Severity reasoning from all agents
        - Impact descriptions (combined)
        - Affected assets (union)
        - Compliance impact (union)
        """
        # Combine severity reasoning from all agents
        all_reasoning = []
        for agent_name, contrib in contributions.items():
            for reason in contrib.risk_factors:
                all_reasoning.append(f"[{agent_name}] {reason}")

        severity_reasoning = "; ".join(all_reasoning[:3])  # Top 3 most important

        # Combine impact descriptions
        impacts = [cot.risk.impact_description for cot in cots]
        unique_impacts = list(dict.fromkeys(impacts))
        impact_description = ". ".join(unique_impacts)

        # Union of affected assets
        all_assets = []
        for cot in cots:
            all_assets.extend(cot.risk.affected_assets)
        affected_assets = list(dict.fromkeys(all_assets))

        # Attack surface - use most detailed
        attack_surfaces = [cot.risk.attack_surface for cot in cots]
        attack_surface = max(attack_surfaces, key=len)

        # Union of compliance impacts
        all_compliance = []
        for cot in cots:
            if cot.risk.compliance_impact:
                all_compliance.extend(cot.risk.compliance_impact)
        compliance_impact = list(dict.fromkeys(all_compliance)) if all_compliance else None

        # Data sensitivity - use highest
        sensitivities = [cot.risk.data_sensitivity for cot in cots if cot.risk.data_sensitivity]
        data_sensitivity = sensitivities[0] if sensitivities else None

        return RiskAnalysis(
            severity_reasoning=severity_reasoning,
            impact_description=impact_description[:500],
            affected_assets=affected_assets[:10],
            attack_surface=attack_surface,
            data_sensitivity=data_sensitivity,
            compliance_impact=compliance_impact
        )

    def _merge_attack(
        self,
        cots: List[ChainOfThought],
        contributions: Dict[str, AgentContribution]
    ) -> AttackScenario:
        """
        Merge attack scenarios from multiple agents.

        Combines:
        - Attack vectors (use most specific)
        - Attack steps (union of unique steps)
        - Required access (most restrictive)
        - Exploitability (easiest rating)
        """
        # Use most detailed attack vector
        vectors = [cot.attack.attack_vector for cot in cots]
        attack_vector = max(vectors, key=len)

        # Combine all attack steps (remove duplicates)
        all_steps = []
        for agent_name, contrib in contributions.items():
            for step in contrib.attack_steps:
                if step not in all_steps:
                    all_steps.append(f"{step} ({agent_name})")

        attack_steps = all_steps[:8]  # Limit to 8 steps

        # Required access - most restrictive (highest requirement)
        access_levels = [cot.attack.required_access for cot in cots]
        required_access = ", or ".join(list(dict.fromkeys(access_levels)))

        # Exploitability - use easiest (most concerning)
        exploit_order = {"Easy": 0, "Medium": 1, "Hard": 2, "Very Hard": 3}
        exploitabilities = [cot.attack.exploitability_rating for cot in cots]
        exploitability_rating = min(exploitabilities, key=lambda x: exploit_order.get(x, 99))

        # Union of CVEs
        all_cves = []
        for cot in cots:
            if cot.attack.similar_cves:
                all_cves.extend(cot.attack.similar_cves)
        similar_cves = list(dict.fromkeys(all_cves))[:5] if all_cves else None

        # Exploit examples - use first available
        exploit_examples = None
        for cot in cots:
            if cot.attack.exploit_examples:
                exploit_examples = cot.attack.exploit_examples
                break

        return AttackScenario(
            attack_vector=attack_vector,
            attack_steps=attack_steps,
            required_access=required_access,
            exploitability_rating=exploitability_rating,
            similar_cves=similar_cves,
            exploit_examples=exploit_examples
        )

    def _merge_confidence(
        self,
        cots: List[ChainOfThought],
        consensus_level: int,
        agreeing_agents: List[str],
        contributions: Dict[str, AgentContribution]
    ) -> ConfidenceRationale:
        """
        Merge confidence rationale with multi-agent agreement.

        Key insight: Multiple agents agreeing INCREASES confidence.
        """
        # Confidence boosted by agreement
        if consensus_level == 3:
            confidence_level = ConfidenceLevel.HIGH  # All 3 agree = very confident
        elif consensus_level == 2:
            confidence_level = ConfidenceLevel.HIGH  # 2 agree = confident
        else:
            # Use highest confidence from single agent
            levels = [cot.confidence.confidence_level for cot in cots]
            confidence_level = levels[0]

        # Combine all primary factors
        all_factors = []
        for agent_name, contrib in contributions.items():
            for factor in contrib.confidence_factors:
                all_factors.append(f"[{agent_name}] {factor}")

        primary_factors = all_factors[:5]  # Top 5

        # Add consensus factor
        primary_factors.insert(0, f"{consensus_level} agents independently detected this issue")

        # Union of strong evidence
        all_strong = []
        for cot in cots:
            all_strong.extend(cot.confidence.strong_evidence)
        strong_evidence = list(dict.fromkeys(all_strong))[:10]

        # Union of weak evidence
        all_weak = []
        for cot in cots:
            all_weak.extend(cot.confidence.weak_evidence)
        weak_evidence = list(dict.fromkeys(all_weak))[:5]

        # Agreement details
        agent_list = ", ".join(agreeing_agents)
        agreement_details = f"{consensus_level} agents agree ({agent_list})"

        return ConfidenceRationale(
            confidence_level=confidence_level,
            primary_factors=primary_factors,
            strong_evidence=strong_evidence,
            weak_evidence=weak_evidence,
            agent_agreement=consensus_level,
            agreement_details=agreement_details
        )

    def _merge_remediation(
        self,
        cots: List[ChainOfThought],
        contributions: Dict[str, AgentContribution]
    ) -> RemediationReasoning:
        """
        Merge remediation reasoning from multiple agents.

        Synthesizes:
        - Recommended fix (use most specific)
        - Fix rationale (combine perspectives)
        - Alternative fixes (union)
        """
        # Use most detailed fix recommendation
        fixes = [cot.remediation.recommended_fix for cot in cots]
        recommended_fix = max(fixes, key=len)

        # Combine fix rationales
        rationales = [cot.remediation.fix_rationale for cot in cots]
        unique_rationales = list(dict.fromkeys(rationales))
        fix_rationale = ". ".join(unique_rationales[:2])  # Top 2

        # Union of alternative fixes
        all_alternatives = []
        for agent_name, contrib in contributions.items():
            all_alternatives.extend(contrib.remediation_alternatives)
        alternative_fixes = list(dict.fromkeys(all_alternatives))[:5]

        # Tradeoffs - use first available
        tradeoffs = None
        for cot in cots:
            if cot.remediation.tradeoffs:
                tradeoffs = cot.remediation.tradeoffs
                break

        # Implementation complexity - use highest (most realistic)
        complexity_order = {"Easy": 0, "Medium": 1, "Hard": 2}
        complexities = [cot.remediation.implementation_complexity for cot in cots]
        implementation_complexity = max(complexities, key=lambda x: complexity_order.get(x, 0))

        # Breaking changes - if any agent says yes, it's yes
        breaking_changes = any(cot.remediation.breaking_changes for cot in cots)

        # Testing guidance - combine
        all_testing = [cot.remediation.testing_guidance for cot in cots if cot.remediation.testing_guidance]
        testing_guidance = "; ".join(all_testing[:2]) if all_testing else None

        return RemediationReasoning(
            recommended_fix=recommended_fix,
            fix_rationale=fix_rationale,
            alternative_fixes=alternative_fixes,
            tradeoffs=tradeoffs,
            implementation_complexity=implementation_complexity,
            breaking_changes=breaking_changes,
            testing_guidance=testing_guidance
        )

    def _merge_context(self, cots: List[ChainOfThought]) -> Optional[ContextAnalysis]:
        """Merge context analysis if present."""
        contexts = [cot.context for cot in cots if cot.context]
        if not contexts:
            return None

        # Use most detailed context
        primary = max(contexts, key=lambda c: len(c.function_purpose or ""))

        # Union of missing controls
        all_missing = []
        for ctx in contexts:
            all_missing.extend(ctx.missing_controls)
        missing_controls = list(dict.fromkeys(all_missing))

        # Union of surrounding controls
        all_surrounding = []
        for ctx in contexts:
            all_surrounding.extend(ctx.surrounding_controls)
        surrounding_controls = list(dict.fromkeys(all_surrounding))

        return ContextAnalysis(
            function_purpose=primary.function_purpose,
            data_flow=primary.data_flow,
            surrounding_controls=surrounding_controls,
            missing_controls=missing_controls,
            file_purpose=primary.file_purpose,
            framework_context=primary.framework_context
        )

    def _merge_false_positive(self, cots: List[ChainOfThought]) -> Optional[FalsePositiveAssessment]:
        """Merge false positive assessment."""
        fps = [cot.false_positive for cot in cots if cot.false_positive]
        if not fps:
            return None

        # If ANY agent thinks it's likely FP, flag it
        is_likely_fp = any(fp.is_likely_false_positive for fp in fps)

        # Combine reasoning
        all_reasoning = [fp.reasoning for fp in fps]
        reasoning = "; ".join(all_reasoning[:2])

        # Union of ambiguity factors
        all_ambiguity = []
        for fp in fps:
            all_ambiguity.extend(fp.ambiguity_factors)
        ambiguity_factors = list(dict.fromkeys(all_ambiguity))

        # Boosters and detractors
        all_boosters = []
        all_detractors = []
        for fp in fps:
            all_boosters.extend(fp.confidence_boosters)
            all_detractors.extend(fp.confidence_detractors)

        return FalsePositiveAssessment(
            is_likely_false_positive=is_likely_fp,
            reasoning=reasoning,
            ambiguity_factors=ambiguity_factors,
            confidence_boosters=list(dict.fromkeys(all_boosters))[:5],
            confidence_detractors=list(dict.fromkeys(all_detractors))[:5]
        )

    def _merge_alternatives(self, cots: List[ChainOfThought]) -> Optional[AlternativeExplanations]:
        """Merge alternative explanations."""
        alts = [cot.alternatives for cot in cots if cot.alternatives]
        if not alts:
            return None

        # Union of legitimate uses
        all_uses = []
        for alt in alts:
            all_uses.extend(alt.possible_legitimate_uses)

        # Union of counterarguments
        all_counter = []
        for alt in alts:
            all_counter.extend(alt.counterarguments)

        # If ANY agent says needs human judgment
        requires_judgment = any(alt.requires_human_judgment for alt in alts)

        return AlternativeExplanations(
            possible_legitimate_uses=list(dict.fromkeys(all_uses)),
            counterarguments=list(dict.fromkeys(all_counter)),
            requires_human_judgment=requires_judgment
        )


# Convenience function
def merge_chain_of_thoughts(
    cots: List[ChainOfThought],
    consensus_level: int,
    agreeing_agents: List[str]
) -> ChainOfThought:
    """
    Convenience function to merge CoTs.

    Args:
        cots: List of Chain of Thought instances
        consensus_level: 1, 2, or 3
        agreeing_agents: Agent names that agreed

    Returns:
        Merged ChainOfThought
    """
    merger = CoTMerger()
    return merger.merge_cots(cots, consensus_level, agreeing_agents)
