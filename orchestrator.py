"""Orchestrator for AtlasRecon Committee.

Runs all four recon agents against the local offline HTML files in
target_html/, saves each agent's findings to outputs/agent_findings/, then
invokes the Report Agent to synthesize outputs/atlas_recon_report.md.

Performs no network access, no live fetching, and no crawling of any kind.
"""

from agents.model_card_recon_agent import ModelCardReconAgent
from agents.artifact_recon_agent import ArtifactReconAgent
from agents.technical_exposure_agent import TechnicalExposureAgent
from agents.vulnerability_analysis_agent import VulnerabilityAnalysisAgent
from agents.report_agent import ReportAgent
from core.evidence_schema import save_findings

TARGET_DIR = "target_html"

AGENT_CLASSES = [
    ModelCardReconAgent,
    ArtifactReconAgent,
    TechnicalExposureAgent,
    VulnerabilityAnalysisAgent,
]


def run_agent(agent_class):
    agent = agent_class()
    findings = agent.run(target_dir=TARGET_DIR)
    output_path = save_findings(agent.agent_name, findings)

    print(f"\nAgent: {agent.agent_name}")
    print(f"ATLAS Technique: {agent.atlas_technique_id} - {agent.atlas_technique_name}")
    print(f"Findings: {len(findings)}")
    top_title = findings[0].finding_title if findings else "(none)"
    print(f"Top finding: {top_title}")
    print(f"Saved to: {output_path}")

    return findings


def main():
    print("=" * 60)
    print("AtlasRecon Committee - Multi-Agent Recon Pipeline")
    print("=" * 60)

    all_findings = []
    for agent_class in AGENT_CLASSES:
        all_findings.extend(run_agent(agent_class))

    print("\n" + "-" * 60)
    print("Generating ATLAS-mapped intelligence report...")
    report_agent = ReportAgent()
    report_path = report_agent.generate_report()
    print(f"Report written to: {report_path}")

    print("\n" + "=" * 60)
    print("Pipeline Summary")
    print("=" * 60)
    print(f"Agents run: {len(AGENT_CLASSES)}")
    print(f"Total findings across all agents: {len(all_findings)}")
    print(f"Final report: {report_path}")


if __name__ == "__main__":
    main()
