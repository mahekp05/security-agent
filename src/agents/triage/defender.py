# Written with help of GitHub Copilot
"""
Defender Agent - Devil's Advocate Perspective
Counters Prosecutor's argument and explains why findings may be false positives.
Outputs confidence_score (1-100) on whether it's actually a real risk.
"""

import json
import re
from typing import List
from src.core.models import VulnerabilityFinding, DiffHunk, DefenderVerdict, ProsecutorVerdict
from src.core.llm import get_llm


class DefenderAgent:
    """
    Represents the Defender in the triage layer.
    Counters Prosecutor's argument. Can agree or disagree.
    Outputs confidence_score (1-100) where:
    - 85-100: Yes, it IS a real risk (agrees with Prosecutor)
    - 70-84: Likely IS a real risk (mostly agrees)
    - 50-69: Uncertain / mixed signals (could go either way)
    - 30-49: Likely NOT a real risk (disagrees with Prosecutor)
    - 1-29: Definitely NOT a real risk / false positive (strong disagreement)
    """

    def __init__(self, temperature: float = 0.1):
        """Initialize with deterministic temperature for consistent results"""
        self.llm = get_llm(temperature=temperature)

    def _get_defense_strategies(self, category: str) -> str:
        """Get defense strategies specific to each category"""
        strategies = {
            "A05": """DEFENSE STRATEGIES FOR A05 (Injection):
Question source trustworthiness:
- "Input comes from internal config, not user input"
- "Environment variable with restricted access"
- "This is admin-only setting"

Challenge sink dangerousness:
- "Query is read-only, not admin operations"
- "SQL execution is sandboxed/restricted"
- "This is logging-only, not actual execution"

Identify hidden protections:
- "There's validation in the calling function"
- "Input is sanitized by middleware before reaching this code"
- "Type checking prevents injection at runtime"

Highlight limitations:
- "This code path requires elevated permissions"
- "Impact is limited even if injected"
- "Injection requires authentication first"
""",
            
            "A02": """DEFENSE STRATEGIES FOR A02 (Configuration):
Question source trustworthiness:
- "CORS policy is only for staging, not production"
- "Exposed endpoint has rate limiting"
- "Secret has limited permissions despite exposure"

Challenge sink dangerousness:
- "Debug flag doesn't actually expose sensitive data"
- "Headers are set by proxy/reverse proxy, not here"
- "Configuration is internal-only"

Identify hidden protections:
- "Authentication is required before accessing this endpoint"
- "Data returned is already public/non-sensitive"
- "API key has minimal scope"

Highlight limitations:
- "Configuration change requires deployment"
- "Production has different settings than code"
- "Actual exposure window is minimal"
""",
            
            "A10": """DEFENSE STRATEGIES FOR A10 (Error Handling):
Question source trustworthiness:
- "Error is only logged, not shown to users"
- "Stack trace only visible in development"
- "Exception is caught at higher level"

Challenge sink dangerousness:
- "Sensitive data is already redacted"
- "Null dereference is impossible here"
- "Fail-open only happens in non-production"

Identify hidden protections:
- "Error handling middleware strips sensitive info"
- "Authentication prevents unauthorized error access"
- "Logging is protected from external access"

Highlight limitations:
- "Error exposure requires specific conditions"
- "Impact of exposed error is minimal"
- "This code path is rarely reached"
"""
        }
        return strategies.get(category, "")

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
        prosecutor_argument: str,
        prosecutor_score: int
    ) -> str:
        """Build the defense prompt"""
        strategies = self._get_defense_strategies(category)
        findings_str = self._format_findings(findings)
        hunks_str = self._format_hunks(hunks)
        
        prompt = f"""You are a skilled security defense expert (DEFENDER) tasked with countering claims that findings ARE vulnerabilities.

ATTACK CATEGORY: {category}

FINDINGS IN THIS CATEGORY:
{findings_str}

DIFF HUNKS WITH CODE IN QUESTION:
{hunks_str}

PROSECUTOR'S ARGUMENT (what you are countering):
{prosecutor_argument}

PROSECUTOR'S CONFIDENCE SCORE: {prosecutor_score}/100

AVAILABLE DEFENSE STRATEGIES:
{strategies}

CONFIDENCE SCORING SCALE (Your perspective - whether it's ACTUALLY a real risk):
- 85-100: Yes, it IS a real risk (you AGREE with Prosecutor, even if imperfect)
- 70-84: Likely IS a real risk (you mostly agree, minor concerns)
- 50-69: Uncertain / mixed signals (valid arguments on both sides)
- 30-49: Likely NOT a real risk (you DISAGREE with Prosecutor, probably FP)
- 1-29: Definitely NOT a real risk / false positive (strong disagreement)

YOUR TASK:
1. Review the Prosecutor's argument line by line
2. Apply defense strategies specific to {category} if applicable
3. Identify weaknesses in the Prosecutor's logic
4. Challenge assumptions about input sources, sinks, protections
5. Output a confidence_score (1-100) that reflects YOUR assessment
6. Provide reasoning (150-400 words) that:
   - DIRECTLY addresses the Prosecutor's claims (reference specific parts)
   - Explains where you agree and where you disagree
   - Highlights hidden protections or mitigating factors
   - Justifies why your score differs from the Prosecutor's score
   - If you're close to Prosecutor's score: explain what would need to change your mind
   - If you strongly disagree: provide specific evidence why it's likely FP

IMPORTANT NOTES:
- You can AGREE with Prosecutor (score 50-100) if the evidence is strong
- You can DISAGREE with Prosecutor (score 1-49) if you find flaws in their logic
- Explain confidence delta: If Prosecutor=85 and you=35, explain the disagreement
- This is NOT adversarial - find the TRUTH, not just contrarian argument
- Balance skepticism with fairness to Prosecutor's analysis

CRITICAL: You MUST output valid JSON with exactly these fields:
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

    def defend(
        self,
        category: str,
        findings: List[VulnerabilityFinding],
        hunks: List[DiffHunk],
        prosecutor_verdict: ProsecutorVerdict
    ) -> DefenderVerdict:
        """
        Generate defense verdict countering Prosecutor's argument.
        
        Args:
            category: "A05", "A02", or "A10"
            findings: List of VulnerabilityFinding objects for this category
            hunks: List of DiffHunk objects containing the code in question
            prosecutor_verdict: ProsecutorVerdict with confidence_score and reasoning
            
        Returns:
            DefenderVerdict with confidence_score (1-100) and reasoning
        """
        if not findings:
            raise ValueError("At least one finding is required")
        if not hunks:
            raise ValueError("At least one diff hunk is required")
        if not prosecutor_verdict:
            raise ValueError("Prosecutor verdict is required")

        prompt_text = self._build_prompt(
            category,
            findings,
            hunks,
            prosecutor_verdict.reasoning,
            prosecutor_verdict.confidence_score
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
        
        agrees = abs(confidence_score - prosecutor_verdict.confidence_score) <= 25

        return DefenderVerdict(
            confidence_score=confidence_score,
            reasoning=reasoning,           # ← the text reasoning (150-400 words)
            agrees_with_prosecutor=agrees   # ← the boolean (True/False)
        )

def create_defender() -> DefenderAgent:
    """Factory function to create a DefenderAgent with default settings"""
    return DefenderAgent(temperature=0.1)
