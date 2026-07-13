# ATLAS Mapping

Initial mapping between each recon agent and its corresponding MITRE ATLAS technique. This mapping guides what each agent looks for in the offline Hugging Face HTML files in `target_html/` and how those findings should be framed in the final report.

| Agent | ATLAS Technique | What the Agent Looks For | Why It Matters to an Adversary | Example Evidence (offline HF page) |
| - | - | - | - | - |
| **Model Card Recon Agent** | AML.T0003 — Search Victim-Owned Websites | Organization name, authorship, intended use/limitations text, contact info, links to related projects or internal docs referenced in the model card | Reveals who owns/maintains the model and what it's used for, helping an adversary build a profile of the victim organization and identify follow-on targets | Model card text on `model_page.html` stating the publishing org, intended use cases, and any linked internal/external resources |
| **Artifact Recon Agent** | AML.T0002 — Acquire Public AI Artifacts | Listed files (weights, tokenizer, config.json, checkpoints), file sizes, formats, and version history | Lets an adversary obtain the actual model artifacts for offline analysis, fine-tuning, extraction attacks, or repackaging without needing further access | File listing on `files_page.html` showing `model.safetensors`, `tokenizer.json`, `config.json`, and prior revision tags |
| **Technical Exposure Recon Agent** | AML.T0000 — Search Open Technical Databases | Framework/library versions, dependency requirements, config parameters (context length, architecture details), hardware/runtime hints | Exposes the technical stack and configuration, which helps an adversary identify known weaknesses in specific library/framework versions or plan compatible attack tooling | `config.json` contents or model card snippets referencing `transformers` version, model architecture (`Qwen2ForCausalLM`), and parameter counts on `model_page.html`/`files_page.html` |
| **Vulnerability Analysis Recon Agent** | AML.T0001 — Search Open AI Vulnerability Analysis | Reported bugs, security concerns, jailbreak/prompt-injection discussions, known failure modes raised in community threads | Surfaces publicly discussed weaknesses an adversary could exploit directly, saving them the effort of discovering vulnerabilities themselves | Comment threads on `discussions_page.html`/`community_page.html` describing a prompt-injection bypass or unexpected model behavior |

## Notes

- All evidence is sourced exclusively from local, manually downloaded HTML files in `target_html/` — no live querying of Hugging Face is performed.
- This table will be referenced by the Report Agent when synthesizing `outputs/agent_findings/*.json` into `outputs/atlas_recon_report.md`.
