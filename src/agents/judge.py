"""
Judge Agent - Neutral Risk Assessment
Synthesizes Prosecutor and Defender arguments into practical risk decisions.
Outputs risk_label (critical_risk | medium_risk | low_risk | false_positive) + reasoning.
"""

import json
import re
from typing import List
from core.models import VulnerabilityFinding, DiffHunk, ProsecutorVerdict, DefenderVerdict, JudgeVerdict
from core.llm import get_llm


class JudgeAgent:
    """
    Represents the Judge in the triage layer.
    Synthesizes Prosecutor and Defender arguments into a practical risk label.
    Outputs risk_label (not confidence score) for user decision-making.
    
    Risk Labels:
    - critical_risk: Clear evidence of exploitable vulnerability. User should prioritize fixing.
    - medium_risk: Finding has merit but may have context/mitigations. User should review and evaluate.
    - low_risk: Finding is minor or context suggests low impact. User may defer or document reasoning.
    - false_positive: Unlikely to be real risk. User should close/ignore.
    """

    def __init__(self, temperature: float = 0.0):
        """Initialize with zero temperature for deterministic decisions"""
        self.llm = get_llm(temperature=temperature)

    def _calculate_confidence_gap(self, prosecutor_score: int, defender_score: int) -> dict:
        """
        Analyze the gap between Prosecutor and Defender scores.
        
        Returns:
            dict with agreement_level, gap_magnitude, and who_is_stronger
        """
        gap = prosecutor_score - defender_score
        abs_gap = abs(gap)
        
        if abs_gap <= 10:
            agreement = "high_agreement"
        elif abs_gap <= 25:
            agreement = "moderate_disagreement"
        else:
            agreement = "strong_disagreement"
        
        if prosecutor_score > defender_score:
            stronger = "prosecutor"
        elif defender_score > prosecutor_score:
            stronger = "defender"
        else:
            stronger = "equal"
        
        return {
            "agreement": agreement,
            "gap": gap,
            "magnitude": abs_gap,
            "stronger": stronger
        }

    def _format_findings(self, findings: List[VulnerabilityFinding]) -> str:
        """Format findings for LLM analysis"""
        formatted = []
        for i, finding in enumerate(findings, 1):
            formatted.append(f"""
Finding {i}:
- Category: {finding.category}
- Description: {finding.description}
- Affected Code: {finding.affected_code}
- Initial Confidence: {finding.confidence}
""")
        return "\n".join(formatted)

    def _format_hunks(self, hunks: List[DiffHunk]) -> str:
        """Format diff hunks for LLM analysis"""
        formatted = []
        for i, hunk in enumerate(hunks, 1):
            added_str = "\n".join("  " + line for line in hunk.added_lines)
            removed_str = "\n".join("  " + line for line in hunk.removed_lines)
            formatted.append(f"""
Hunk {i} (File: {hunk.file_path}):
Added Lines:
{added_str}
Removed Lines:
{removed_str}
""")
        return "\n".join(formatted)

    def _build_prompt(
        self,
        category: str,
        findings: List[VulnerabilityFinding],
        hunks: List[DiffHunk],
        prosecutor_verdict: ProsecutorVerdict,
        defender_verdict: DefenderVerdict,
        confidence_analysis: dict
    ) -> str:
        """Build the judge's decision prompt"""
        findings_str = self._format_findings(findings)
        hunks_str = self._format_hunks(hunks)
        
        gap_description = f"""
Prosecutor Confidence: {prosecutor_verdict.confidence_score}/100
Defender Confidence: {defender_verdict.confidence_score}/100
Gap Analysis: {confidence_analysis['magnitude']} point gap ({confidence_analysis['stronger']} is stronger)
Agreement Level: {confidence_analysis['agreement']}
"""
        
        prompt = f"""You are a neutral security judge (JUDGE) tasked with making a practical risk decision.

ATTACK CATEGORY: {category}

FINDINGS IN THIS CATEGORY:
{findings_str}

DIFF HUNKS:
{hunks_str}

CONFIDENCE ANALYSIS:
{gap_description}

PROSECUTOR'S ARGUMENT:
{prosecutor_verdict.reasoning}

DEFENDER'S ARGUMENT:
{defender_verdict.reasoning}

DECISION FRAMEWORK:

1. EVIDENCE WEIGHT
   - Does code evidence strongly support Prosecutor? (specific patterns, clear vulnerability path)
   - Does Defender identify valid, visible mitigations? (validation, authentication, sandboxing)
   - Is vulnerability easily exploitable in real scenario? (public endpoint, direct access, minimal requirements)
   - Are there multiple independent factors pointing to same conclusion?

2. ARGUMENT QUALITY
   - Is Prosecutor citing specific code patterns? (high quality - specific evidence)
   - Is Defender identifying real constraints/validations? (high quality - concrete mitigations)
   - Is either argument speculative or generic? (lower confidence in either direction)
   - Which argument is more grounded in actual code reality?

3. RISK MAGNITUDE (if vulnerability is real)
   - What's the impact if exploited? (data loss, auth bypass, RCE, DoS, information disclosure)
   - How accessible is the attack path? (public endpoint, requires auth, admin-only, internal only)
   - Are there layers of defense even if one fails? (defense in depth vs. single point of failure)
   - How many preconditions must attacker satisfy? (fewer = more critical)

4. FINAL RISK MAPPING

CRITICAL_RISK if:
- Prosecutor's evidence is strong + clear attack path in diff
- Multiple code patterns point to vulnerability
- Exploitability is high (public access, minimal prerequisites)
- Impact is severe (auth bypass, data loss, RCE)
- Defender's counter-arguments are weak or speculative
→ User should prioritize fixing this immediately

MEDIUM_RISK if:
- Evidence is present but mitigations exist or are unclear
- Prosecutor and Defender both have valid points
- Exploitability requires specific conditions or multiple steps
- Impact could be significant in certain contexts
- Gap between Prosecutor/Defender is moderate
→ User should review context and evaluate before deciding

LOW_RISK if:
- Defender's arguments about mitigations/constraints are concrete
- Vulnerability requires rare conditions or multiple failures
- Impact is minimal even if exploited
- Easier workarounds or compensating controls exist
- Prosecutor's evidence is thin
→ User can defer or document reasoning why not fixing

FALSE_POSITIVE if:
- Defender's arguments are compelling and grounded
- Code change doesn't actually introduce vulnerability
- Prosecutor's logic has logical flaws
- Finding is based on detection pattern, not actual risk
- Defender's confidence is high, Prosecutor's is low
→ User should close/ignore finding

YOUR TASK:
1. Weigh both arguments fairly - do not favor Prosecutor by default
2. Decide on ONE risk label based on framework above
3. Explain why this specific label is appropriate
4. Explain which argument was stronger and why
5. Provide actionable guidance for user (what they should do)
6. Keep reasoning to 200-300 words
7. Be decisive and clear for user action

IMPORTANT: You MUST output valid JSON with exactly these fields:
- risk_label: one of ["critical_risk", "medium_risk", "low_risk", "false_positive"]
- reasoning: string of 200-300 words

Respond with ONLY the JSON object, no additional text."""
        return prompt

    def _parse_response(self, response_text: str) -> dict:
        """
        Parse LLM response to extract risk_label and reasoning.
        Handles JSON extraction from potentially malformed responses.
        """
        # Try to extract JSON from the response
        json_match = re.search(r'\{[^{}]*"risk_label"[^{}]*\}', response_text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        
        # Fallback: try to parse entire response as JSON
        try:
            return json.loads(response_text.strip())
        except json.JSONDecodeError:
            pass
        
        # Last resort: extract risk_label from text
        labels = ["critical_risk", "medium_risk", "low_risk", "false_positive"]
        risk_label = "medium_risk"  # default
        for label in labels:
            if label.lower() in response_text.lower():
                risk_label = label
                break
        
        return {
            "risk_label": risk_label,
            "reasoning": response_text[:300] if len(response_text) > 0 else "Unable to parse detailed reasoning."
        }

    def judge(
        self,
        category: str,
        findings: List[VulnerabilityFinding],
        hunks: List[DiffHunk],
        prosecutor_verdict: ProsecutorVerdict,
        defender_verdict: DefenderVerdict
    ) -> JudgeVerdict:
        """
        Generate judge verdict weighing both arguments.
        
        Args:
            category: "A05", "A02", or "A10"
            findings: List of VulnerabilityFinding objects for this category
            hunks: List of DiffHunk objects containing the code in question
            prosecutor_verdict: ProsecutorVerdict with confidence_score and reasoning
            defender_verdict: DefenderVerdict with confidence_score and reasoning
            
        Returns:
            JudgeVerdict with risk_label and reasoning
        """
        if not findings:
            raise ValueError("At least one finding is required")
        if not hunks:
            raise ValueError("At least one diff hunk is required")
        if not prosecutor_verdict or not defender_verdict:
            raise ValueError("Both Prosecutor and Defender verdicts are required")

        # Analyze confidence gap
        confidence_analysis = self._calculate_confidence_gap(
            prosecutor_verdict.confidence_score,
            defender_verdict.confidence_score
        )
        
        prompt_text = self._build_prompt(
            category,
            findings,
            hunks,
            prosecutor_verdict,
            defender_verdict,
            confidence_analysis
        )
        
        # Call LLM directly
        try:
            # Try using HumanMessage if available
            try:
                # Dynamic import inside try-except to avoid import errors
                import langchain_core.messages as lc_messages  # type: ignore
                response = self.llm.invoke([lc_messages.HumanMessage(content=prompt_text)])
                response_text = response.content if hasattr(response, 'content') else str(response)
            except (ImportError, AttributeError):
                # Fallback: invoke directly with string
                response = self.llm.invoke(prompt_text)
                response_text = response.content if hasattr(response, 'content') else str(response)
        except Exception as e:
            response = self.llm.invoke(prompt_text)
            response_text = str(response)
        
        # Ensure response_text is string
        if not isinstance(response_text, str):
            response_text = str(response_text)
        
        # Parse response
        parsed = self._parse_response(response_text)
        
        # Validate risk_label
        valid_labels = ["critical_risk", "medium_risk", "low_risk", "false_positive"]
        risk_label = parsed.get("risk_label", "medium_risk")
        if risk_label not in valid_labels:
            risk_label = "medium_risk"
        
        reasoning = parsed.get("reasoning", "")
        word_count = len(reasoning.split())
        if word_count < 50:
            reasoning += f"\n\n[Extended reasoning: current response ({word_count} words), need 200-300 words]"
        
        return JudgeVerdict(
            risk_label=risk_label,
            reasoning=reasoning
        )


def create_judge() -> JudgeAgent:
    """Factory function to create a JudgeAgent with default settings"""
    return JudgeAgent(temperature=0.0)
