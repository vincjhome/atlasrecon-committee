"""Technical Exposure Recon Agent for AtlasRecon Committee.

MITRE ATLAS mapping:
    Tactic:          Reconnaissance
    Technique:       AML.T0000 - Search Open Technical Databases

Reads only local, manually saved Hugging Face HTML files from target_html/
(via core.html_loader). Performs no network access, no live fetching, and
no crawling of any kind.
"""

import html
import re

from core.html_loader import load_html_files
from core.evidence_schema import ReconFinding, save_findings

SNIPPET_RADIUS = 80
SNIPPET_MAX_LEN = 160

PREFERRED_FILES = ["model_page.html", "files_page.html"]


def _snippet(text, match_start, match_end):
    """Return a short, screenshot-friendly snippet around a match."""
    start = max(0, match_start - SNIPPET_RADIUS)
    end = min(len(text), match_end + SNIPPET_RADIUS)
    snippet = html.unescape(text[start:end]).strip()
    snippet = re.sub(r"\s+", " ", snippet)
    if len(snippet) > SNIPPET_MAX_LEN:
        snippet = snippet[:SNIPPET_MAX_LEN].rstrip() + "..."
    return snippet


def _find_snippets(per_file_text, patterns, limit=3, preferred_files=PREFERRED_FILES):
    """Return up to `limit` short snippets for the given patterns.

    Searches preferred files first (if present), then the remaining files,
    so evidence favors model_page.html and files_page.html when available.
    """
    snippets = []
    ordered_files = [f for f in preferred_files if f in per_file_text]
    ordered_files += [f for f in per_file_text if f not in preferred_files]

    for filename in ordered_files:
        text = per_file_text[filename]
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                snippets.append(_snippet(text, match.start(), match.end()))
            if len(snippets) >= limit:
                return snippets
    return snippets


class TechnicalExposureAgent:
    agent_name = "technical_exposure_agent"
    atlas_tactic = "Reconnaissance"
    atlas_technique_id = "AML.T0000"
    atlas_technique_name = "Search Open Technical Databases"

    ARCHITECTURE_PATTERNS = [
        r"Number of Parameters[^\n]{0,80}",
        r"Number of Layers[^\n]{0,80}",
        r"Number of Attention Heads[^\n]{0,80}",
        r"Architecture:\s*[^\n]{0,120}",
        r"Training Stage:\s*[^\n]{0,80}",
        r"tied word embeddings[^\n]{0,40}",
    ]

    CONTEXT_LENGTH_PATTERNS = [
        r"Context Length:\s*[^\n]{0,80}",
        r"\d[\d,]*\s*tokens[^\n]{0,40}",
    ]

    DEPLOYMENT_PATTERNS = [
        r"text-generation-inference[^\n]{0,40}",
        r"endpoints_compatible[^\n]{0,40}",
        r"pipeline\([^\n]{0,80}",
        r"docker model run[^\n]{0,80}",
        r"library_name[^\n]{0,40}",
    ]

    LINEAGE_AND_ECOSYSTEM_PATTERNS = [
        r"base_model:finetune:[^\n,\"]{0,60}",
        r"base_model:[^\n,\"]{0,60}",
        r"pipeline_tag[^\n]{0,40}",
        r"\"task\":\s*\"conversational\"",
        r"arxiv:[\d\.]+",
        r"please refer to our blog[^\n]{0,80}",
    ]

    def _gather_text(self, target_dir):
        files = load_html_files(target_dir)
        per_file_text = {entry["filename"]: entry["extracted_text"] for entry in files}
        return per_file_text

    def _source_files_for_patterns(self, per_file_text, patterns):
        matched_files = []
        for filename, text in per_file_text.items():
            if any(re.search(p, text, flags=re.IGNORECASE) for p in patterns):
                matched_files.append(filename)
        return matched_files

    def run(self, target_dir="target_html"):
        per_file_text = self._gather_text(target_dir)
        findings = []

        arch_evidence = _find_snippets(per_file_text, self.ARCHITECTURE_PATTERNS)
        if arch_evidence:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="Architecture and model capacity details exposed",
                severity="medium",
                confidence="high",
                summary=(
                    "The page publicly documents the model's architecture and capacity "
                    "(parameter count, layer count, attention head configuration, training "
                    "stage)."
                ),
                evidence=arch_evidence,
                source_files=self._source_files_for_patterns(per_file_text, self.ARCHITECTURE_PATTERNS),
                adversary_value=(
                    "Precise architecture and parameter details let an adversary profile "
                    "the model's capabilities and limitations, plan compute requirements "
                    "for replication, and select attack techniques known to be effective "
                    "against similarly sized/structured models."
                ),
                defensive_recommendation=(
                    "Expected for an open model card; for non-public deployments, avoid "
                    "disclosing exact architecture/parameter specifics."
                ),
            ))

        context_evidence = _find_snippets(per_file_text, self.CONTEXT_LENGTH_PATTERNS)
        if context_evidence:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="Long context length and generation capability exposed",
                severity="medium",
                confidence="high",
                summary=(
                    "The page states the model's context window and generation token "
                    "limits, revealing how much input/output the model can process."
                ),
                evidence=context_evidence,
                source_files=self._source_files_for_patterns(per_file_text, self.CONTEXT_LENGTH_PATTERNS),
                adversary_value=(
                    "Knowing the exact context window lets an adversary plan prompt-attack "
                    "or context-stuffing strategies (e.g. injection payload sizing) tuned to "
                    "the model's exact limits rather than guessing."
                ),
                defensive_recommendation=(
                    "Expected for an open model card; no action needed unless context "
                    "limits reveal non-public deployment tuning."
                ),
            ))

        deployment_evidence = _find_snippets(per_file_text, self.DEPLOYMENT_PATTERNS)
        if deployment_evidence:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="Deployment and inference stack details exposed",
                severity="low",
                confidence="high",
                summary=(
                    "The page documents the supported inference/deployment stack, "
                    "including compatibility with text-generation-inference, Hugging Face "
                    "Inference Endpoints, the transformers pipeline API, and Docker-based "
                    "serving."
                ),
                evidence=deployment_evidence,
                source_files=self._source_files_for_patterns(per_file_text, self.DEPLOYMENT_PATTERNS),
                adversary_value=(
                    "Knowing the exact serving stack helps an adversary anticipate how the "
                    "model is likely deployed in production, narrowing which tooling and "
                    "known framework-level weaknesses are relevant to target."
                ),
                defensive_recommendation=(
                    "Standard for open-source model cards; no action needed."
                ),
            ))

        lineage_evidence = _find_snippets(per_file_text, self.LINEAGE_AND_ECOSYSTEM_PATTERNS)
        if lineage_evidence:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="Model lineage, task tags, or ecosystem metadata exposed",
                severity="low",
                confidence="medium",
                summary=(
                    "The page exposes the model's base-model/finetune lineage, task tags "
                    "(e.g. conversational, text-generation), and references to external "
                    "technical reports (e.g. arXiv papers, blog posts)."
                ),
                evidence=lineage_evidence,
                source_files=self._source_files_for_patterns(per_file_text, self.LINEAGE_AND_ECOSYSTEM_PATTERNS),
                adversary_value=(
                    "Lineage and external reference links let an adversary pull in "
                    "published technical reports for deeper capability/limitation "
                    "research, and confirm which base model's known weaknesses may carry "
                    "over to this finetune."
                ),
                defensive_recommendation=(
                    "Standard for open-source ecosystem metadata; no action needed."
                ),
            ))

        if not findings:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="No technical exposure evidence extracted",
                severity="low",
                confidence="low",
                summary=(
                    "No matching architecture, context length, deployment, or lineage "
                    "text was found in the local HTML files in target_html/."
                ),
                evidence=[],
                source_files=list(per_file_text.keys()),
                adversary_value="None — no usable evidence was found in the local files.",
                defensive_recommendation=(
                    "Ensure the Hugging Face model page and Files and versions page have "
                    "been manually saved into target_html/ before re-running this agent."
                ),
            ))

        return findings


def main():
    agent = TechnicalExposureAgent()
    findings = agent.run()
    output_path = save_findings(agent.agent_name, findings)
    print(f"Saved {len(findings)} findings to {output_path}")


if __name__ == "__main__":
    main()
