"""Model Card Recon Agent for AtlasRecon Committee.

MITRE ATLAS mapping:
    Tactic:          Reconnaissance
    Technique:       AML.T0003 - Search Victim-Owned Websites

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


def _snippet(text, match_start, match_end):
    """Return a short, screenshot-friendly snippet around a match."""
    start = max(0, match_start - SNIPPET_RADIUS)
    end = min(len(text), match_end + SNIPPET_RADIUS)
    snippet = html.unescape(text[start:end]).strip()
    snippet = re.sub(r"\s+", " ", snippet)
    if len(snippet) > SNIPPET_MAX_LEN:
        snippet = snippet[:SNIPPET_MAX_LEN].rstrip() + "..."
    return snippet


def _find_snippets(text, patterns, limit=3):
    """Return up to `limit` short snippets for the first match of each pattern."""
    snippets = []
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            snippets.append(_snippet(text, match.start(), match.end()))
        if len(snippets) >= limit:
            break
    return snippets


class ModelCardReconAgent:
    agent_name = "model_card_recon_agent"
    atlas_tactic = "Reconnaissance"
    atlas_technique_id = "AML.T0003"
    atlas_technique_name = "Search Victim-Owned Websites"

    IDENTITY_PATTERNS = [
        r"Qwen2\.5[-\w\.]*",
        r"instruction-tuned language models?",
        r"base language models?",
    ]

    ARCHITECTURE_PATTERNS = [
        r"Architecture:\s*[^\n]{0,120}",
        r"Causal Language Models?",
        r"Context Length:\s*[^\n]{0,80}",
        r"Number of (?:Parameters|Attention Heads)[^\n]{0,80}",
    ]

    USAGE_PATTERNS = [
        r"from transformers import [^\n]{0,80}",
        r"AutoModelForCausalLM[^\n]{0,80}",
        r"apply_chat_template[^\n]{0,80}",
        r"pip install [^\n]{0,40}",
    ]

    LICENSE_PATTERNS = [
        r"license:\s*[\w\-\.]+",
        r"Apache[- ]2\.0",
    ]

    LIMITATIONS_PATTERNS = [
        r"limitations?[^\n]{0,120}",
        r"requirements?[^\n]{0,80}for GPU memory",
    ]

    def _gather_text(self, target_dir):
        files = load_html_files(target_dir)
        per_file_text = {entry["filename"]: entry["extracted_text"] for entry in files}
        combined_text = "\n".join(per_file_text.values())
        return per_file_text, combined_text

    def _source_files_for_patterns(self, per_file_text, patterns):
        matched_files = []
        for filename, text in per_file_text.items():
            if any(re.search(p, text, flags=re.IGNORECASE) for p in patterns):
                matched_files.append(filename)
        return matched_files

    def run(self, target_dir="target_html"):
        per_file_text, combined_text = self._gather_text(target_dir)
        findings = []

        identity_evidence = _find_snippets(combined_text, self.IDENTITY_PATTERNS)
        if identity_evidence:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="Public model identity and instruction-tuned purpose exposed",
                severity="low",
                confidence="high",
                summary=(
                    "The model card publicly identifies the model family/name and states "
                    "that it is an instruction-tuned language model, confirming both its "
                    "identity and intended behavior."
                ),
                evidence=identity_evidence,
                source_files=self._source_files_for_patterns(per_file_text, self.IDENTITY_PATTERNS),
                adversary_value=(
                    "Confirms the exact model identity and behavior class an adversary is "
                    "targeting, letting them reuse known prompting/jailbreak techniques "
                    "documented for this model family."
                ),
                defensive_recommendation=(
                    "No change needed for a public model card; if this were a private/internal "
                    "deployment, avoid publishing identity and tuning details on public pages."
                ),
            ))

        arch_evidence = _find_snippets(combined_text, self.ARCHITECTURE_PATTERNS)
        if arch_evidence:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="Architecture and capability details exposed in model card",
                severity="medium",
                confidence="high",
                summary=(
                    "The model card discloses architecture details (layer/attention head "
                    "counts, context length) that describe the model's internal design and "
                    "operating limits."
                ),
                evidence=arch_evidence,
                source_files=self._source_files_for_patterns(per_file_text, self.ARCHITECTURE_PATTERNS),
                adversary_value=(
                    "Architecture and context-length details help an adversary craft inputs "
                    "tuned to the model's exact capacity (e.g. context-window stuffing) and "
                    "estimate compute requirements for replication or fine-tuning."
                ),
                defensive_recommendation=(
                    "Architecture disclosure is expected for open releases; for sensitive "
                    "deployments, avoid publishing exact context-length and attention "
                    "configuration values."
                ),
            ))

        usage_evidence = _find_snippets(combined_text, self.USAGE_PATTERNS)
        if usage_evidence:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="Usage instructions and sample inference patterns exposed",
                severity="low",
                confidence="high",
                summary=(
                    "The model card includes copy-paste sample code for loading and running "
                    "the model (transformers API usage, chat templates, install commands)."
                ),
                evidence=usage_evidence,
                source_files=self._source_files_for_patterns(per_file_text, self.USAGE_PATTERNS),
                adversary_value=(
                    "Working sample code lowers the effort required for an adversary to load "
                    "and run the exact model locally, accelerating offline probing, "
                    "fine-tuning, or extraction attempts."
                ),
                defensive_recommendation=(
                    "Standard for open-source model cards; no action needed beyond ensuring "
                    "no internal/private endpoints are included in sample usage code."
                ),
            ))

        license_evidence = _find_snippets(combined_text, self.LICENSE_PATTERNS)
        if license_evidence:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="License/release information exposed",
                severity="low",
                confidence="medium",
                summary=(
                    "The model card/metadata states the license terms under which the model "
                    "is released."
                ),
                evidence=license_evidence,
                source_files=self._source_files_for_patterns(per_file_text, self.LICENSE_PATTERNS),
                adversary_value=(
                    "Confirms the legal terms under which the model and its weights can be "
                    "reused, redistributed, or fine-tuned, informing how an adversary could "
                    "repackage the artifact without further permission."
                ),
                defensive_recommendation=(
                    "No action needed; license disclosure is expected and required for "
                    "open-source releases."
                ),
            ))

        if not findings:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="No model-card recon evidence extracted",
                severity="low",
                confidence="low",
                summary=(
                    "No matching model identity, architecture, usage, or license text was "
                    "found in the local HTML files in target_html/."
                ),
                evidence=[],
                source_files=list(per_file_text.keys()),
                adversary_value="None — no usable evidence was found in the local files.",
                defensive_recommendation=(
                    "Ensure the correct Hugging Face pages have been manually saved into "
                    "target_html/ before re-running this agent."
                ),
            ))

        return findings


def main():
    agent = ModelCardReconAgent()
    findings = agent.run()
    output_path = save_findings(agent.agent_name, findings)
    print(f"Saved {len(findings)} findings to {output_path}")


if __name__ == "__main__":
    main()
