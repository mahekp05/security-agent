from pydantic import BaseModel, Field
from typing import List, Optional, Literal

class DiffHunk(BaseModel):
    file_path: str
    added_lines: List[str]
    removed_lines: List[str]

class ParsedDiff(BaseModel):
    hunks: List[DiffHunk] = Field(description="List of security-relevant code hunks extracted from the diff.")

class VulnerabilityFinding(BaseModel):
    category: str = Field(description="A05, A02, or A10")
    description: str
    affected_code: str
    confidence: str = Field(description="High, Medium, or Low")

class ProsecutorVerdict(BaseModel):
    """Prosecutor's argument that findings ARE real vulnerabilities"""
    category: str = Field(description="A05, A02, or A10")
    confidence_score: int = Field(ge=1, le=100, description="1-100: confidence it's a real vulnerability")
    reasoning: str = Field(description="150-400 words explaining the confidence score and attack perspective")

class DefenderVerdict(BaseModel):
    """Defender's argument that findings may be false positives"""
    confidence_score: int = Field(ge=1, le=100, description="1-100: confidence it's NOT a real vulnerability")
    reasoning: str = Field(description="150-400 words explaining counterarguments and mitigations")
    agrees_with_prosecutor: bool = Field(description="True if Defender agrees with Prosecutor's assessment")

class JudgeVerdict(BaseModel):
    """Judge's final assessment and risk label"""
    risk_label: Literal["critical_risk", "medium_risk", "low_risk", "false_positive"] = Field(
        description="Final risk classification"
    )
    reasoning: str = Field(description="150-400 words explaining risk assessment and actionable guidance")
    confidence_score: int = Field(ge=1, le=100, description="1-100: confidence in the final risk label")

class CategoryTriageVerdict(BaseModel):
    """Final verdict for all findings in one attack category"""
    category: str = Field(description="A05, A02, or A10")
    findings: List[VulnerabilityFinding]
    diff_hunks: List[DiffHunk]
    prosecutor: ProsecutorVerdict
    defender: DefenderVerdict
    judge: JudgeVerdict
    
    @property
    def risk_label(self) -> str:
        """Shortcut to judge's risk_label"""
        return self.judge.risk_label
    
    @property
    def reasoning(self) -> str:
        """Shortcut to judge's reasoning"""
        return self.judge.reasoning
    
    @property
    def confidence_score(self) -> int:
        """Shortcut to prosecutor's confidence_score"""
        return self.prosecutor.confidence_score

class TriageVerdict(BaseModel):
    finding: VulnerabilityFinding
    prosecutor_argument: str
    defender_argument: str
    is_real_risk: bool
    final_severity: int = Field(ge=1, le=10)
    judge_reasoning: str

class SecurityReport(BaseModel):
    """Final security assessment report for a code diff"""
    verdicts: List[CategoryTriageVerdict] = Field(description="Verdicts for each attack category found")
    total_findings: int = Field(description="Total vulnerabilities found across all categories")
    summary: Optional[str] = Field(default=None, description="Executive summary of security posture")