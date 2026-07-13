"""Runner for the Model Card Recon Agent.

Runs only against local HTML files in target_html/ via ModelCardReconAgent.
Performs no network access, no live fetching, and no crawling of any kind.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agents.model_card_recon_agent import ModelCardReconAgent
from core.evidence_schema import save_findings


def main():
    agent = ModelCardReconAgent()
    findings = agent.run()

    print("=" * 60)
    print("AtlasRecon Committee - Model Card Recon Agent")
    print("=" * 60)
    print(f"\nAgent name: {agent.agent_name}")
    print(f"Number of findings: {len(findings)}\n")

    for i, finding in enumerate(findings, start=1):
        print("-" * 60)
        print(f"Finding {i}: {finding.finding_title}")
        print(f"Severity: {finding.severity} | Confidence: {finding.confidence}")
        print(f"ATLAS Technique: {finding.atlas_technique_id} - {finding.atlas_technique_name}")
        print(f"Source files: {', '.join(finding.source_files) if finding.source_files else '(none)'}")
        print("Evidence:")
        if finding.evidence:
            for snippet in finding.evidence:
                print(f"  - {snippet}")
        else:
            print("  (no evidence snippets)")

    print("-" * 60)

    output_path = save_findings(agent.agent_name, findings)
    print(f"\nSaved {len(findings)} findings to: {output_path}")


if __name__ == "__main__":
    main()
