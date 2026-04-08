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
    confidence_score: int = Field(ge=1, le=100, description="1-100: confidence it's a real vulnerability")
    reasoning: str = Field(description="150-400 words explaining the confidence score and attack perspective")

class DefenderVerdict(BaseModel):
    """Defender's argument that findings may be false positives"""
    confidence_score: int = Field(ge=1, le=100, description="1-100: confidence it's NOT a real vulnerability")
    reasoning: str = Field(description="150-400 words explaining counterarguments and mitigations")

class JudgeVerdict(BaseModel):
    """Judge's final assessment and risk label"""
    risk_label: Literal["critical_risk", "medium_risk", "low_risk", "false_positive"] = Field(
        description="Final risk classification"
    )
    reasoning: str = Field(description="150-400 words explaining risk assessment and actionable guidance")

class CategoryTriageVerdict(BaseModel):
    """Final verdict for all findings in one attack category"""
    category: str = Field(description="A05, A02, or A10")
    findings: List[VulnerabilityFinding]
    diff_hunks: List[DiffHunk]
    prosecutor: ProsecutorVerdict
    defender: DefenderVerdict
    judge: JudgeVerdict

class TriageVerdict(BaseModel):
    finding: VulnerabilityFinding
    prosecutor_argument: str
    defender_argument: str
    is_real_risk: bool
    final_severity: int = Field(ge=1, le=10)
    judge_reasoning: str