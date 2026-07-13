"""Artifact Recon Agent for AtlasRecon Committee.

MITRE ATLAS mapping:
    Tactic:          Reconnaissance
    Technique:       AML.T0002 - Acquire Public AI Artifacts

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

PREFERRED_FILE = "files_page.html"


def _snippet(text, match_start, match_end):
    """Return a short, screenshot-friendly snippet around a match."""
    start = max(0, match_start - SNIPPET_RADIUS)
    end = min(len(text), match_end + SNIPPET_RADIUS)
    snippet = html.unescape(text[start:end]).strip()
    snippet = re.sub(r"\s+", " ", snippet)
    if len(snippet) > SNIPPET_MAX_LEN:
        snippet = snippet[:SNIPPET_MAX_LEN].rstrip() + "..."
    return snippet


def _find_snippets(per_file_text, patterns, limit=3, preferred_file=PREFERRED_FILE):
    """Return up to `limit` short snippets for the given patterns.

    Searches the preferred file first (if present), then the remaining
    files, so artifact evidence favors files_page.html when available.
    """
    snippets = []
    ordered_files = [f for f in [preferred_file] if f in per_file_text]
    ordered_files += [f for f in per_file_text if f != preferred_file]

    for filename in ordered_files:
        text = per_file_text[filename]
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                snippets.append(_snippet(text, match.start(), match.end()))
            if len(snippets) >= limit:
                return snippets
    return snippets


class ArtifactReconAgent:
    agent_name = "artifact_recon_agent"
    atlas_tactic = "Reconnaissance"
    atlas_technique_id = "AML.T0002"
    atlas_technique_name = "Acquire Public AI Artifacts"

    WEIGHT_PATTERNS = [
        r"model\.safetensors[^\n]{0,80}",
        r"pytorch_model[^\n]{0,80}",
        r"safetensors[^\n]{0,80}",
    ]

    TOKENIZER_CONFIG_PATTERNS = [
        r"tokenizer_config\.json[^\n]{0,80}",
        r"tokenizer\.json[^\n]{0,80}",
        r"generation_config\.json[^\n]{0,80}",
        r"vocab\.json[^\n]{0,80}",
        r"merges\.txt[^\n]{0,80}",
        r"config\.json[^\n]{0,80}",
    ]

    REPO_METADATA_PATTERNS = [
        r"README\.md[^\n]{0,80}",
        r"\.gitattributes[^\n]{0,80}",
        r"LICENSE[^\n]{0,80}",
    ]

    PACKAGING_PATTERNS = [
        r"\d[\d,.]*\s*(?:GB|MB|kB|Bytes)\b",
        r"\bcommits?\b[^\n]{0,40}",
        r"\bcontributors?\b[^\n]{0,40}",
        r"Upload folder using huggingface_hub[^\n]{0,40}",
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

        weight_evidence = _find_snippets(per_file_text, self.WEIGHT_PATTERNS)
        if weight_evidence:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="Public model weight artifacts exposed",
                severity="medium",
                confidence="high",
                summary=(
                    "The repository listing shows downloadable model weight files "
                    "(safetensors/pytorch model artifacts) available directly from the "
                    "Hugging Face repository."
                ),
                evidence=weight_evidence,
                source_files=self._source_files_for_patterns(per_file_text, self.WEIGHT_PATTERNS),
                adversary_value=(
                    "Lets an adversary acquire the actual trained weights for offline use, "
                    "enabling local replication, fine-tuning, extraction attacks, or "
                    "repackaging without needing further access to the original host."
                ),
                defensive_recommendation=(
                    "Expected for an open-weight release; for restricted models, gate "
                    "weight downloads behind authentication/licensing acceptance."
                ),
            ))

        tokenizer_evidence = _find_snippets(per_file_text, self.TOKENIZER_CONFIG_PATTERNS)
        if tokenizer_evidence:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="Tokenizer and generation configuration files exposed",
                severity="low",
                confidence="high",
                summary=(
                    "The repository exposes tokenizer and generation configuration files "
                    "(tokenizer.json, tokenizer_config.json, generation_config.json, "
                    "config.json, vocab/merges files) needed to run the model exactly as "
                    "intended."
                ),
                evidence=tokenizer_evidence,
                source_files=self._source_files_for_patterns(per_file_text, self.TOKENIZER_CONFIG_PATTERNS),
                adversary_value=(
                    "These configs are required to faithfully reproduce inference "
                    "behavior (tokenization, generation defaults, model hyperparameters), "
                    "removing the guesswork an adversary would otherwise need for "
                    "offline analysis or replication."
                ),
                defensive_recommendation=(
                    "Standard for open-source releases; no action needed unless these "
                    "configs encode internal/non-public deployment defaults."
                ),
            ))

        metadata_evidence = _find_snippets(per_file_text, self.REPO_METADATA_PATTERNS)
        if metadata_evidence:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="Repository metadata and model card files exposed",
                severity="low",
                confidence="medium",
                summary=(
                    "The repository listing exposes metadata files (README.md, "
                    ".gitattributes, LICENSE) describing the repository's contents and "
                    "terms."
                ),
                evidence=metadata_evidence,
                source_files=self._source_files_for_patterns(per_file_text, self.REPO_METADATA_PATTERNS),
                adversary_value=(
                    "Repository metadata helps an adversary understand how the artifact "
                    "is packaged, versioned, and licensed, informing redistribution or "
                    "reuse planning."
                ),
                defensive_recommendation=(
                    "Standard for open-source repositories; no action needed."
                ),
            ))

        packaging_evidence = _find_snippets(per_file_text, self.PACKAGING_PATTERNS)
        if packaging_evidence:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="Artifact structure reveals model packaging and deployment format",
                severity="low",
                confidence="medium",
                summary=(
                    "File sizes, commit/upload history, and contributor counts visible in "
                    "the repository listing reveal how the model artifacts are packaged "
                    "and maintained over time."
                ),
                evidence=packaging_evidence,
                source_files=self._source_files_for_patterns(per_file_text, self.PACKAGING_PATTERNS),
                adversary_value=(
                    "File size and revision history help an adversary estimate storage/"
                    "bandwidth requirements for acquiring artifacts and identify whether "
                    "newer or older revisions might expose additional or different files."
                ),
                defensive_recommendation=(
                    "Standard for open-source repositories; no action needed."
                ),
            ))

        if not findings:
            findings.append(ReconFinding(
                agent_name=self.agent_name,
                atlas_tactic=self.atlas_tactic,
                atlas_technique_id=self.atlas_technique_id,
                atlas_technique_name=self.atlas_technique_name,
                finding_title="No public artifact evidence extracted",
                severity="low",
                confidence="low",
                summary=(
                    "No matching artifact, configuration, or repository metadata text was "
                    "found in the local HTML files in target_html/."
                ),
                evidence=[],
                source_files=list(per_file_text.keys()),
                adversary_value="None — no usable evidence was found in the local files.",
                defensive_recommendation=(
                    "Ensure the Hugging Face Files and versions page has been manually "
                    "saved into target_html/ as files_page.html before re-running this "
                    "agent."
                ),
            ))

        return findings


def main():
    agent = ArtifactReconAgent()
    findings = agent.run()
    output_path = save_findings(agent.agent_name, findings)
    print(f"Saved {len(findings)} findings to {output_path}")


if __name__ == "__main__":
    main()
