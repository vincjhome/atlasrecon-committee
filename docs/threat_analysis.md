# Threat Analysis — Qwen/Qwen2.5-0.5B-Instruct

AtlasRecon Committee ran four recon agents — Model Card Recon Agent (AML.T0003 Search
Victim-Owned Websites), Artifact Recon Agent (AML.T0002 Acquire Public AI Artifacts),
Technical Exposure Recon Agent (AML.T0000 Search Open Technical Databases), and Vulnerability
Analysis Recon Agent (AML.T0001 Search Open AI Vulnerability Analysis) — against manually
downloaded, offline Hugging Face HTML files for Qwen/Qwen2.5-0.5B-Instruct. No live crawling,
scraping, or active scanning was performed against Hugging Face at any point; everything below is
derived from the local files in `target_html/` and the 16 findings the four agents produced.

## Most Dangerous Finding

The most dangerous finding is the Vulnerability Analysis Recon Agent's result that public weights
and tokenizer artifacts support offline replication and adversarial evaluation. The model card
metadata, architecture details, and usage instructions surfaced by the other agents are all useful
reconnaissance, but they only tell an adversary *about* the model. The artifact-level evidence —
`model.safetensors`, `tokenizer.json`, `tokenizer_config.json`, `config.json`, and
`generation_config.json` all being directly downloadable from the repository — is what actually
lets an adversary move from studying the model to running it.

This finding is more exploitable than the others because it removes the single biggest constraint an
adversary normally faces when probing a hosted model: dependency on the live target. Architecture
and context-length disclosures help an adversary plan, and model-card metadata helps them identify
the model and its intended use, but neither one hands over anything operational by itself. The
artifact exposure does. Once weights and tokenizer/config files are in hand, the adversary has
everything needed to instantiate an identical local copy and is no longer bound by the target's rate
limits, monitoring, or detection capabilities while they iterate.

In effect, this finding converts the rest of the recon output from "things we know about the target"
into "things we can act on directly." That shift — from passive knowledge to an actionable offline
copy of the model — is why it ranks above every other finding the pipeline produced, including the
ones rated the same medium severity.

## Likely Adversary Next Step

**Attack:** Offline adversarial evaluation and jailbreak testing.

**Mechanism:** Using the exposed model artifacts together with the tokenizer/config files and the
chat-template and inference guidance documented on the model page, an adversary would replicate the
model locally and then run repeated safety-boundary, jailbreak, prompt-injection, and long-context
manipulation tests in a fully controlled offline environment. Because this testing happens against a
local copy rather than a live endpoint, the adversary can iterate freely — adjusting their approach
across many attempts — without triggering rate limits, usage monitoring, or any detection that a
hosted deployment might otherwise apply.

The practical risk extends beyond the model in isolation. If this same model is later exposed through
a public API or embedded in a product, prompt strategies or misuse patterns that succeeded during
offline testing could be carried over directly to that live deployment. The offline phase becomes a
low-cost, low-visibility rehearsal for whatever the adversary ultimately wants to do against a real
system, which is precisely why the artifact-exposure finding above is the one most worth addressing
first.

## Key Observations from Multi-Agent Recon

Building this as a multi-agent pipeline rather than a single monolithic scanner made the value of
layered reconnaissance much clearer: each agent surfaces a genuinely different layer of exposure —
the Model Card agent sees public identity and intended-use claims, the Artifact agent sees what can
actually be downloaded and run, the Technical Exposure agent sees architecture and deployment
specifics, and the Vulnerability Analysis agent connects those layers into intelligence about what an
adversary would plausibly do next. No single agent's output would have made the offline-replication
risk as obvious as seeing all four side by side. The orchestrator's role in running every agent
consistently and handing off uniform `ReconFinding` records also made a real difference — because
every finding shared the same structured fields, the report agent could synthesize them into one
ATLAS-mapped intelligence report without any special-casing per agent, which is what made a
coherent, traceable final report possible in the first place.
