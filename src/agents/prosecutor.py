"""
Prosecutor Agent - Red Team Perspective
Argues that findings ARE real, exploitable vulnerabilities.
Outputs confidence_score (1-100) on how sure the prosecutor is the vulnerability is real.
"""

import json
import re
from typing import List
from core.models import VulnerabilityFinding, DiffHunk, ProsecutorVerdict
from core.llm import get_llm


class ProsecutorAgent:
    """
    Represents the Prosecutor in the triage layer.
    Makes argument that findings ARE real vulnerabilities (red team perspective).
    Outputs confidence_score (1-100) where:
    - 85-100: Definitely exploitable
    - 70-84: Very likely exploitable
    - 50-69: Moderate confidence
    - 30-49: Low confidence
    - 1-29: Very low confidence / likely false positive
    """

    def __init__(self, temperature: float = 0.1):
        """Initialize with deterministic temperature for consistent results"""
        self.llm = get_llm(temperature=temperature)

    def _get_category_guidance(self, category: str) -> str:
        """Get category-specific guidance for scoring"""
        guidance = {
            "A05": """For A05 (Injection):
- Assess: untrusted input sources, dangerous sinks (SQL, subprocess, eval), missing parameterization
- High confidence (85-100) if: f-strings/format in query + user input clearly visible + no params
- Lower confidence (30-49) if: query is read-only, input comes from internal config, or validation visible
- Medium confidence (50-69) if: mixed signals present""",
            
            "A02": """For A02 (Configuration):
- Assess: CORS settings, exposed secrets, debug flags, missing headers
- High confidence (85-100) if: CORS='*' on whole API + public endpoint + could leak data
- Lower confidence (30-49) if: CORS only on staging, keys have limited permissions, debug is internal only
- Medium confidence (50-69) if: some mitigating factors present""",
            
            "A10": """For A10 (Error Handling):
- Assess: sensitive data in errors, uncaught exceptions, null deref, fail-open
- High confidence (85-100) if: stack trace exposed to user endpoint + contains DB paths, or auth failure returns success
- Lower confidence (30-49) if: error logged only (not shown to user), exception caught at higher level
- Medium confidence (50-69) if: partial exposure or uncertain impact"""
        }
        return guidance.get(category, "")

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
        hunks: List[DiffHunk]
    ) -> str:
        """Build the prosecution prompt"""
        guidance = self._get_category_guidance(category)
        findings_str = self._format_findings(findings)
        hunks_str = self._format_hunks(hunks)
        
        prompt = f"""You are a red team security expert (PROSECUTOR) tasked with arguing that findings ARE real, exploitable vulnerabilities.

ATTACK CATEGORY: {category}

FINDINGS IN THIS CATEGORY:
{findings_str}

DIFF HUNKS WITH VULNERABLE CODE:
{hunks_str}

CATEGORY-SPECIFIC SCORING GUIDANCE:
{guidance}

SCORING SCALE:
- 85-100: Definitely exploitable (obvious attack path in diff, clear vulnerability pattern)
- 70-84: Very likely exploitable (strong evidence of vulnerability, high attack probability)
- 50-69: Moderate confidence (real vulnerability but possible mitigations or uncertainties)
- 30-49: Low confidence (could be false positive, significant mitigating factors)
- 1-29: Very low confidence / likely false positive

YOUR TASK:
1. Analyze the findings and code hunks from a RED TEAM perspective
2. Explain how an attacker would exploit these vulnerabilities
3. Reference specific code snippets from the hunks
4. Assess severity and exploitability
5. Output a confidence_score (1-100) based on the scale above
6. Provide reasoning (150-400 words) that explains:
   - Why you scored at this confidence level
   - Specific evidence from the diff
   - Attack methodology and impact
   - Key factors driving your confidence assessment

IMPORTANT: You MUST output valid JSON with exactly these fields:
- confidence_score: integer between 1 and 100
- reasoning: string of 150-400 words

Respond with ONLY the JSON object, no additional text."""
        return prompt

    def _parse_response(self, response_text: str) -> dict:
        """
        Parse LLM response to extract confidence_score and reasoning.
        Handles JSON extraction from potentially malformed responses.
        """
        # Try to extract JSON from the response
        json_match = re.search(r'\{[^{}]*"confidence_score"[^{}]*\}', response_text, re.DOTALL)
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
        
        # Last resort: extract confidence score from text
        score_match = re.search(r'confidence[_\s]*score[:\s]*(\d+)', response_text, re.IGNORECASE)
        confidence_score = int(score_match.group(1)) if score_match else 50
        confidence_score = max(1, min(100, confidence_score))
        
        return {
            "confidence_score": confidence_score,
            "reasoning": response_text[:400] if len(response_text) > 0 else "Unable to parse detailed reasoning."
        }

    def prosecute(
        self,
        category: str,
        findings: List[VulnerabilityFinding],
        hunks: List[DiffHunk]
    ) -> ProsecutorVerdict:
        """
        Generate prosecution verdict with confidence score.
        
        Args:
            category: "A05", "A02", or "A10"
            findings: List of VulnerabilityFinding objects for this category
            hunks: List of DiffHunk objects containing the vulnerable code
            
        Returns:
            ProsecutorVerdict with confidence_score (1-100) and reasoning
        """
        if not findings:
            raise ValueError("At least one finding is required")
        if not hunks:
            raise ValueError("At least one diff hunk is required")

        prompt_text = self._build_prompt(category, findings, hunks)
        
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
        
        # Parse response
        parsed = self._parse_response(response_text)
        
        confidence_score = parsed.get("confidence_score", 50)
        if isinstance(confidence_score, str):
            confidence_score = int(confidence_score)
        confidence_score = max(1, min(100, confidence_score))
        
        reasoning = parsed.get("reasoning", "")
        word_count = len(reasoning.split())
        if word_count < 50:
            reasoning += f"\n\n[Extended analysis: current response ({word_count} words), need 150-400 words]"
        
        return ProsecutorVerdict(
            confidence_score=confidence_score,
            reasoning=reasoning
        )


def create_prosecutor() -> ProsecutorAgent:
    """Factory function to create a ProsecutorAgent with default settings"""
    return ProsecutorAgent(temperature=0.1)
