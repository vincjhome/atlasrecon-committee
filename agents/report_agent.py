"""Report Agent for AtlasRecon Committee.

Synthesizes the structured JSON findings written by the four recon agents
into a single Markdown intelligence report, deterministically (no LLM
required). Reads only local JSON findings from outputs/agent_findings/ —
performs no network access and no live fetching of any kind.
"""

import os
from collections import OrderedDict, Counter

from core.evidence_schema import load_all_findings

TARGET_MODEL = "Qwen/Qwen2.5-0.5B-Instruct"

AGENT_DISPLAY_NAMES = {
    "model_card_recon_agent": "Model Card Recon Agent",
    "artifact_recon_agent": "Artifact Recon Agent",
    "technical_exposure_agent": "Technical Exposure Recon Agent",
    "vulnerability_analysis_agent": "Vulnerability Analysis Recon Agent",
}

AGENT_ORDER = [
    "model_card_recon_agent",
    "artifact_recon_agent",
    "technical_exposure_agent",
    "vulnerability_analysis_agent",
]

# Preference order for selecting the "Most Dangerous Finding."
MOST_DANGEROUS_TITLE_PREFERENCE = [
    ("vulnerability_analysis_agent", "Public weights and tokenizer artifacts support offline replication and adversarial evaluation"),
    ("artifact_recon_agent", "Public model weight artifacts exposed"),
]


def _group_by_agent(findings):
    grouped = OrderedDict((name, []) for name in AGENT_ORDER)
    for finding in findings:
        agent_name = finding.get("agent_name", "unknown_agent")
        grouped.setdefault(agent_name, []).append(finding)
    return grouped


def _select_most_dangerous(findings):
    by_key = {(f.get("agent_name"), f.get("finding_title")): f for f in findings}

    for agent_name, title in MOST_DANGEROUS_TITLE_PREFERENCE:
        if (agent_name, title) in by_key:
            return by_key[(agent_name, title)]

    severity_rank = {"high": 3, "medium": 2, "low": 1}
    candidates = [
        f for f in findings
        if f.get("agent_name") in ("vulnerability_analysis_agent", "artifact_recon_agent")
    ]
    pool = candidates if candidates else findings
    if not pool:
        return None
    return max(pool, key=lambda f: severity_rank.get(f.get("severity", "low"), 0))


class ReportAgent:
    agent_name = "report_agent"

    def generate_report(self, findings_dir="outputs/agent_findings", output_path="outputs/atlas_recon_report.md"):
        findings = load_all_findings(findings_dir)
        grouped = _group_by_agent(findings)

        lines = []
        lines.append("# ATLAS Reconnaissance Intelligence Report")
        lines.append("")
        lines.append(f"**Target:** {TARGET_MODEL}")
        lines.append("")
        lines.append(
            "**Scope:** This report is based exclusively on manually downloaded, "
            "offline Hugging Face HTML files placed in `target_html/`. No live "
            "reconnaissance, crawling, scraping, or active scanning was performed "
            "against Hugging Face or any other live target."
        )
        lines.append("")

        lines.extend(self._executive_summary(findings, grouped))
        lines.extend(self._attack_surface_score())
        lines.extend(self._atlas_coverage_table(grouped))
        lines.extend(self._findings_by_agent(grouped))
        lines.extend(self._most_dangerous_finding(findings))
        lines.extend(self._likely_adversary_next_step())
        lines.extend(self._defensive_recommendations(findings))
        lines.extend(self._limitations())

        report_text = "\n".join(lines).rstrip() + "\n"

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        return output_path

    def _executive_summary(self, findings, grouped):
        total = len(findings)
        severity_counts = Counter(f.get("severity", "unknown") for f in findings)
        agents_run = sum(1 for name in grouped if grouped[name])

        lines = ["## Executive Summary", ""]
        lines.append(
            f"Across {agents_run} recon agents, {total} findings were generated from "
            f"the local offline HTML files for **{TARGET_MODEL}**. Severity breakdown: "
            f"{severity_counts.get('high', 0)} high, {severity_counts.get('medium', 0)} "
            f"medium, {severity_counts.get('low', 0)} low. The model is a publicly "
            "released, instruction-tuned, open-weight model with its model card, "
            "repository artifacts, technical specifications, and deployment metadata "
            "all visible without authentication, which materially lowers the effort "
            "required for an adversary to profile, replicate, and adversarially "
            "evaluate it offline."
        )
        lines.append("")
        return lines

    def _attack_surface_score(self):
        lines = ["## Attack Surface Score", ""]
        lines.append("**Score: 7/10 — Elevated**")
        lines.append("")
        lines.append(
            "The target receives an elevated score because public offline evidence "
            "shows exposed model artifacts, tokenizer/config files, architecture "
            "details, context length, usage examples, and deployment metadata. The "
            "highest-risk factor is public weights/tokenizer availability because it "
            "enables offline replication and repeated adversarial evaluation without "
            "touching a live endpoint. The score is not higher because the analysis "
            "is based on a public open-model release and did not identify exposed "
            "credentials, private datasets, private endpoints, or live production "
            "infrastructure."
        )
        lines.append("")
        return lines

    def _atlas_coverage_table(self, grouped):
        lines = ["## ATLAS Technique Coverage", ""]
        lines.append("| Agent | ATLAS Technique | Findings |")
        lines.append("| - | - | - |")
        for agent_name in AGENT_ORDER:
            agent_findings = grouped.get(agent_name, [])
            display_name = AGENT_DISPLAY_NAMES.get(agent_name, agent_name)
            if agent_findings:
                technique = (
                    f"{agent_findings[0].get('atlas_technique_id', '')} "
                    f"{agent_findings[0].get('atlas_technique_name', '')}"
                )
            else:
                technique = "(no findings)"
            lines.append(f"| {display_name} | {technique} | {len(agent_findings)} |")
        lines.append("")
        return lines

    def _findings_by_agent(self, grouped):
        lines = ["## Findings by Agent", ""]
        for agent_name in AGENT_ORDER:
            agent_findings = grouped.get(agent_name, [])
            display_name = AGENT_DISPLAY_NAMES.get(agent_name, agent_name)
            lines.append(f"### {display_name}")
            lines.append("")
            if not agent_findings:
                lines.append("_No findings were produced by this agent._")
                lines.append("")
                continue

            for finding in agent_findings:
                lines.append(f"**{finding.get('finding_title', '(untitled finding)')}**")
                lines.append("")
                lines.append(
                    f"- Severity: {finding.get('severity', 'unknown')} | "
                    f"Confidence: {finding.get('confidence', 'unknown')}"
                )
                lines.append(
                    f"- ATLAS Technique: {finding.get('atlas_technique_id', '')} - "
                    f"{finding.get('atlas_technique_name', '')}"
                )
                source_files = finding.get("source_files", [])
                lines.append(f"- Source files: {', '.join(source_files) if source_files else '(none)'}")
                lines.append(f"- Summary: {finding.get('summary', '')}")
                evidence = finding.get("evidence", [])
                if evidence:
                    lines.append("- Evidence:")
                    for snippet in evidence:
                        lines.append(f"  - `{snippet}`")
                lines.append(f"- Adversary value: {finding.get('adversary_value', '')}")
                lines.append(f"- Defensive recommendation: {finding.get('defensive_recommendation', '')}")
                lines.append("")
        return lines

    def _most_dangerous_finding(self, findings):
        lines = ["## Most Dangerous Finding", ""]
        finding = _select_most_dangerous(findings)
        if not finding:
            lines.append("_No findings were available to assess._")
            lines.append("")
            return lines

        display_name = AGENT_DISPLAY_NAMES.get(finding.get("agent_name"), finding.get("agent_name"))
        lines.append(f"**{finding.get('finding_title', '')}** (from {display_name})")
        lines.append("")
        lines.append(
            f"- Severity: {finding.get('severity', 'unknown')} | "
            f"Confidence: {finding.get('confidence', 'unknown')}"
        )
        lines.append(f"- Summary: {finding.get('summary', '')}")
        lines.append(f"- Adversary value: {finding.get('adversary_value', '')}")
        lines.append("")
        return lines

    def _likely_adversary_next_step(self):
        lines = ["## Likely Adversary Next Step", ""]
        lines.append(
            "- **Attack:** Offline adversarial evaluation / jailbreak testing"
        )
        lines.append(
            "- **Mechanism:** Use the publicly available model weights, tokenizer, "
            "and chat-template artifacts to replicate the model locally, then test "
            "prompt-safety boundaries and instruction-following behavior in a "
            "controlled offline environment before attempting anything against a "
            "live deployment."
        )
        lines.append("")
        return lines

    def _defensive_recommendations(self, findings):
        lines = ["## Defensive Recommendations", ""]
        seen = []
        for finding in findings:
            rec = finding.get("defensive_recommendation", "").strip()
            if rec and rec not in seen:
                seen.append(rec)
        if not seen:
            lines.append("_No defensive recommendations were available._")
        else:
            for rec in seen:
                lines.append(f"- {rec}")
        lines.append("")
        return lines

    def _limitations(self):
        lines = ["## Limitations", ""]
        lines.append(
            "- This report reflects only the offline HTML files manually saved into "
            "`target_html/` at the time the pipeline was run; it does not reflect "
            "live, current state of the Hugging Face repository."
        )
        lines.append(
            "- Findings are produced by keyword/regex scanning over extracted page "
            "text, not by exploitation, live testing, or model interaction — they "
            "describe what is publicly visible, not confirmed vulnerabilities."
        )
        lines.append(
            "- Coverage is limited to the four recon agents implemented "
            "(model card, artifact, technical exposure, vulnerability analysis); "
            "this is not an exhaustive security assessment."
        )
        lines.append("")
        return lines
