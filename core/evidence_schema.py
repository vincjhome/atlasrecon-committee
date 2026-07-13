"""Shared evidence schema for AtlasRecon Committee.

Defines the structured finding format produced by every recon agent and
consumed by the report agent. Standard library only — no network access.
"""

import json
import os
from dataclasses import dataclass, asdict


@dataclass
class ReconFinding:
    agent_name: str
    atlas_tactic: str
    atlas_technique_id: str
    atlas_technique_name: str
    finding_title: str
    severity: str
    confidence: str
    summary: str
    evidence: list[str]
    source_files: list[str]
    adversary_value: str
    defensive_recommendation: str


def finding_to_dict(finding: ReconFinding) -> dict:
    """Convert a ReconFinding into a plain dict suitable for JSON output."""
    return asdict(finding)


def save_findings(agent_name: str, findings: list[ReconFinding], output_dir="outputs/agent_findings") -> str:
    """Write a list of ReconFinding objects to a JSON file named after the agent.

    Returns the path to the written file.
    """
    os.makedirs(output_dir, exist_ok=True)

    output_path = os.path.join(output_dir, f"{agent_name}.json")
    payload = [finding_to_dict(finding) for finding in findings]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return output_path


def load_all_findings(input_dir="outputs/agent_findings") -> list[dict]:
    """Load and combine all findings JSON files in input_dir.

    Skips README.md. Returns an empty list if the directory does not exist.
    """
    if not os.path.isdir(input_dir):
        return []

    combined = []
    for filename in sorted(os.listdir(input_dir)):
        if filename.lower() == "readme.md":
            continue
        if not filename.lower().endswith(".json"):
            continue

        path = os.path.join(input_dir, filename)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, list):
            combined.extend(data)
        else:
            combined.append(data)

    return combined


def print_findings_summary(findings: list[ReconFinding]) -> None:
    """Print a short terminal-friendly summary of each finding."""
    for finding in findings:
        print(
            f"[{finding.agent_name}] "
            f"{finding.atlas_technique_id} {finding.atlas_technique_name} | "
            f"{finding.finding_title} | "
            f"severity={finding.severity} confidence={finding.confidence}"
        )
