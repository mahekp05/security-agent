from pydantic import BaseModel, Field
from typing import List, Optional

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

class TriageVerdict(BaseModel):
    finding: VulnerabilityFinding
    prosecutor_argument: str
    defender_argument: str
    is_real_risk: bool
    final_severity: int = Field(ge=1, le=10)
    judge_reasoning: str