# ATLAS Reconnaissance Intelligence Report

**Target:** Qwen/Qwen2.5-0.5B-Instruct

**Scope:** This report is based exclusively on manually downloaded, offline Hugging Face HTML files placed in `target_html/`. No live reconnaissance, crawling, scraping, or active scanning was performed against Hugging Face or any other live target.

## Executive Summary

Across 4 recon agents, 16 findings were generated from the local offline HTML files for **Qwen/Qwen2.5-0.5B-Instruct**. Severity breakdown: 0 high, 7 medium, 9 low. The model is a publicly released, instruction-tuned, open-weight model with its model card, repository artifacts, technical specifications, and deployment metadata all visible without authentication, which materially lowers the effort required for an adversary to profile, replicate, and adversarially evaluate it offline.

## Attack Surface Score

**Score: 7/10 — Elevated**

The target receives an elevated score because public offline evidence shows exposed model artifacts, tokenizer/config files, architecture details, context length, usage examples, and deployment metadata. The highest-risk factor is public weights/tokenizer availability because it enables offline replication and repeated adversarial evaluation without touching a live endpoint. The score is not higher because the analysis is based on a public open-model release and did not identify exposed credentials, private datasets, private endpoints, or live production infrastructure.

## ATLAS Technique Coverage

| Agent | ATLAS Technique | Findings |
| - | - | - |
| Model Card Recon Agent | AML.T0003 Search Victim-Owned Websites | 4 |
| Artifact Recon Agent | AML.T0002 Acquire Public AI Artifacts | 4 |
| Technical Exposure Recon Agent | AML.T0000 Search Open Technical Databases | 4 |
| Vulnerability Analysis Recon Agent | AML.T0001 Search Open AI Vulnerability Analysis | 4 |

## Findings by Agent

### Model Card Recon Agent

**Public model identity and instruction-tuned purpose exposed**

- Severity: low | Confidence: high
- ATLAS Technique: AML.T0003 - Search Victim-Owned Websites
- Source files: discussions_page.html, files_page.html, model_page.html
- Summary: The model card publicly identifies the model family/name and states that it is an instruction-tuned language model, confirming both its identity and intended behavior.
- Evidence:
  - `Qwen/Qwen2.5-0.5B-Instruct · Discussions Hugging Face Models Datasets Spaces Buckets new Docs Enterprise P`
  - `e language models. For Qwen2.5, we release a number of base language models and instruction-tuned language models ranging from 0.5 to 72 billion parameters. Qwe...`
  - `atest series of Qwen large language models. For Qwen2.5, we release a number of base language models and instruction-tuned language models ranging from 0.5 to 7...`
- Adversary value: Confirms the exact model identity and behavior class an adversary is targeting, letting them reuse known prompting/jailbreak techniques documented for this model family.
- Defensive recommendation: No change needed for a public model card; if this were a private/internal deployment, avoid publishing identity and tuning details on public pages.

**Architecture and capability details exposed in model card**

- Severity: medium | Confidence: high
- ATLAS Technique: AML.T0003 - Search Victim-Owned Websites
- Source files: model_page.html
- Summary: The model card discloses architecture details (layer/attention head counts, context length) that describe the model's internal design and operating limits.
- Evidence:
  - `s: Type: Causal Language Models Training Stage: Pretraining & Post-training Architecture: transformers with RoPE, SwiGLU, RMSNorm, Attention QKV bias and tied w...`
  - `instruction-tuned 0.5B Qwen2.5 model , which has the following features: Type: Causal Language Models Training Stage: Pretraining & Post-training Architecture:...`
  - `36B Number of Layers: 24 Number of Attention Heads (GQA): 14 for Q and 2 for KV Context Length: Full 32,768 tokens and generation 8192 tokens For more details,...`
- Adversary value: Architecture and context-length details help an adversary craft inputs tuned to the model's exact capacity (e.g. context-window stuffing) and estimate compute requirements for replication or fine-tuning.
- Defensive recommendation: Architecture disclosure is expected for open releases; for sensitive deployments, avoid publishing exact context-length and attention configuration values.

**Usage instructions and sample inference patterns exposed**

- Severity: low | Confidence: high
- ATLAS Technique: AML.T0003 - Search Victim-Owned Websites
- Source files: discussions_page.html, files_page.html, model_page.html
- Summary: The model card includes copy-paste sample code for loading and running the model (transformers API usage, chat templates, install commands).
- Evidence:
  - `wen2.5-0.5B-Instruct with Transformers: # Use a pipeline as a high-level helper from transformers import pipeline pipe = pipeline("text-generation", model="Qwen...`
  - `the tokenizer and model and how to generate contents. from transformers import AutoModelForCausalLM, AutoTokenizer model_name = "Qwen/Qwen2.5-0.5B-Instruct" mod...`
  - `messages = [ {"role": "user", "content": "Who are you?"}, ] inputs = tokenizer.apply_chat_template( messages, add_generation_prompt=True, tokenize=True, return_...`
- Adversary value: Working sample code lowers the effort required for an adversary to load and run the exact model locally, accelerating offline probing, fine-tuning, or extraction attempts.
- Defensive recommendation: Standard for open-source model cards; no action needed beyond ensuring no internal/private endpoints are included in sample usage code.

**License/release information exposed**

- Severity: low | Confidence: medium
- ATLAS Technique: AML.T0003 - Search Victim-Owned Websites
- Source files: discussions_page.html, files_page.html, model_page.html
- Summary: The model card/metadata states the license terms under which the model is released.
- Evidence:
  - `Qwen/Qwen2.5-0.5B","base_model:finetune:Qwen/Qwen2.5-0.5B","license:apache-2.0","text-generation-inference","endpoints_compatible",&q`
  - `n2.5-0.5B","base_model:finetune:Qwen/Qwen2.5-0.5B","license:apache-2.0","text-generation-inference","endpoints_compatible",&q`
- Adversary value: Confirms the legal terms under which the model and its weights can be reused, redistributed, or fine-tuned, informing how an adversary could repackage the artifact without further permission.
- Defensive recommendation: No action needed; license disclosure is expected and required for open-source releases.

### Artifact Recon Agent

**Public model weight artifacts exposed**

- Severity: medium | Confidence: high
- ATLAS Technique: AML.T0002 - Acquire Public AI Artifacts
- Source files: discussions_page.html, files_page.html, model_page.html
- Summary: The repository listing shows downloadable model weight files (safetensors/pytorch model artifacts) available directly from the Hugging Face repository.
- Evidence:
  - `quot;task":"conversational","adapterWeightsPath":"model.safetensors","isCheapestPricingOutput":false,"isFastestThroughput":false,"isModelAuthor":false}],"showHu...`
  - `ask":"conversational","adapterWeightsPath":"model.safetensors","isCheapestPricingOutput":false,"isFastestThroughput":false,"isModelAuthor":false}],"showHuggingC...`
  - `quot;task":"conversational","adapterWeightsPath":"model.safetensors","isCheapestPricingOutput":false,"isFastestThroughput":false,"isModelAuthor":false}],"showHu...`
- Adversary value: Lets an adversary acquire the actual trained weights for offline use, enabling local replication, fine-tuning, extraction attacks, or repackaging without needing further access to the original host.
- Defensive recommendation: Expected for an open-weight release; for restricted models, gate weight downloads behind authentication/licensing acceptance.

**Tokenizer and generation configuration files exposed**

- Severity: low | Confidence: high
- ATLAS Technique: AML.T0002 - Acquire Public AI Artifacts
- Source files: files_page.html
- Summary: The repository exposes tokenizer and generation configuration files (tokenizer.json, tokenizer_config.json, generation_config.json, config.json, vocab/merges files) needed to run the model exactly as intended.
- Evidence:
  - `o tokenizer.json 7.03 MB Upload folder using huggingface_hub almost 2 years ago tokenizer_config.json 7.31 kB Upload ./tokenizer_config.json with huggingface_hu...`
  - `l.safetensors 988 MB xet Upload folder using huggingface_hub almost 2 years ago tokenizer.json 7.03 MB Upload folder using huggingface_hub almost 2 years ago to...`
  - `go config.json 659 Bytes Upload folder using huggingface_hub almost 2 years ago generation_config.json 242 Bytes Upload folder using huggingface_hub almost 2 ye...`
- Adversary value: These configs are required to faithfully reproduce inference behavior (tokenization, generation defaults, model hyperparameters), removing the guesswork an adversary would otherwise need for offline analysis or replication.
- Defensive recommendation: Standard for open-source releases; no action needed unless these configs encode internal/non-public deployment defaults.

**Repository metadata and model card files exposed**

- Severity: low | Confidence: medium
- ATLAS Technique: AML.T0002 - Acquire Public AI Artifacts
- Source files: discussions_page.html, files_page.html, model_page.html
- Summary: The repository listing exposes metadata files (README.md, .gitattributes, LICENSE) describing the repository's contents and terms.
- Evidence:
  - `most 2 years ago LICENSE 11.3 kB update README & LICENSE almost 2 years ago README.md 4.92 kB Update metadata: Add library_name to Transformers (#2) over 1 year...`
  - `tion":9,"isReleased":true,"accuratePricing":true}]}}"> .gitattributes 1.52 kB initial commit almost 2 years ago LICENSE 11.3 kB update README & LICENSE almost 2...`
  - `Qwen/Qwen2.5-0.5B","base_model:finetune:Qwen/Qwen2.5-0.5B","license:apache-2.0","text-generation-inference","endpoints_compatible","deploy:azure","region:us"],"...`
- Adversary value: Repository metadata helps an adversary understand how the artifact is packaged, versioned, and licensed, informing redistribution or reuse planning.
- Defensive recommendation: Standard for open-source repositories; no action needed.

**Artifact structure reveals model packaging and deployment format**

- Severity: low | Confidence: medium
- ATLAS Technique: AML.T0002 - Acquire Public AI Artifacts
- Source files: files_page.html
- Summary: File sizes, commit/upload history, and contributor counts visible in the repository listing reveal how the model artifacts are packaged and maintained over time.
- Evidence:
  - `r: docker model run hf.co/Qwen/Qwen2.5-0.5B-Instruct main Qwen2.5-0.5B-Instruct 1,000 MB ⌘ K ⌘ K 5 contributors History: 10 commits #2</a>)"},"repo":{`
  - `Instruct main Qwen2.5-0.5B-Instruct 1,000 MB ⌘ K ⌘ K 5 contributors History: 10 commits #2</a>)"},"repo":{"name":"Qwen/Qwen2.5-0.5B-Instruct","type":"mode`
  - `hf.co/Qwen/Qwen2.5-0.5B-Instruct main Qwen2.5-0.5B-Instruct 1,000 MB ⌘ K ⌘ K 5 contributors History: 10 commits #2</a>)"},"repo":{"name":"Qwen/Qwen2.5-0.5B-Inst...`
- Adversary value: File size and revision history help an adversary estimate storage/bandwidth requirements for acquiring artifacts and identify whether newer or older revisions might expose additional or different files.
- Defensive recommendation: Standard for open-source repositories; no action needed.

### Technical Exposure Recon Agent

**Architecture and model capacity details exposed**

- Severity: medium | Confidence: high
- ATLAS Technique: AML.T0000 - Search Open Technical Databases
- Source files: model_page.html
- Summary: The page publicly documents the model's architecture and capacity (parameter count, layer count, attention head configuration, training stage).
- Evidence:
  - `formers with RoPE, SwiGLU, RMSNorm, Attention QKV bias and tied word embeddings Number of Parameters: 0.49B Number of Paramaters (Non-Embedding): 0.36B Number o...`
  - `eddings Number of Parameters: 0.49B Number of Paramaters (Non-Embedding): 0.36B Number of Layers: 24 Number of Attention Heads (GQA): 14 for Q and 2 for KV Cont...`
  - `ameters: 0.49B Number of Paramaters (Non-Embedding): 0.36B Number of Layers: 24 Number of Attention Heads (GQA): 14 for Q and 2 for KV Context Length: Full 32,7...`
- Adversary value: Precise architecture and parameter details let an adversary profile the model's capabilities and limitations, plan compute requirements for replication, and select attack techniques known to be effective against similarly sized/structured models.
- Defensive recommendation: Expected for an open model card; for non-public deployments, avoid disclosing exact architecture/parameter specifics.

**Long context length and generation capability exposed**

- Severity: medium | Confidence: high
- ATLAS Technique: AML.T0000 - Search Open Technical Databases
- Source files: model_page.html
- Summary: The page states the model's context window and generation token limits, revealing how much input/output the model can process.
- Evidence:
  - `36B Number of Layers: 24 Number of Attention Heads (GQA): 14 for Q and 2 for KV Context Length: Full 32,768 tokens and generation 8192 tokens For more details,...`
  - `24 Number of Attention Heads (GQA): 14 for Q and 2 for KV Context Length: Full 32,768 tokens and generation 8192 tokens For more details, please refer to our bl...`
- Adversary value: Knowing the exact context window lets an adversary plan prompt-attack or context-stuffing strategies (e.g. injection payload sizing) tuned to the model's exact limits rather than guessing.
- Defensive recommendation: Expected for an open model card; no action needed unless context limits reveal non-public deployment tuning.

**Deployment and inference stack details exposed**

- Severity: low | Confidence: high
- ATLAS Technique: AML.T0000 - Search Open Technical Databases
- Source files: discussions_page.html, files_page.html, model_page.html
- Summary: The page documents the supported inference/deployment stack, including compatibility with text-generation-inference, Hugging Face Inference Endpoints, the transformers pipeline API, and Docker-based serving.
- Evidence:
  - `ase_model:finetune:Qwen/Qwen2.5-0.5B","license:apache-2.0","text-generation-inference","endpoints_compatible","deploy:azure","region:us"],"tag_objs":[{"id&`
  - `uot;,"license:apache-2.0","text-generation-inference","endpoints_compatible","deploy:azure","region:us"],"tag_objs":[{"id":"text-generation"`
  - `Use a pipeline as a high-level helper from transformers import pipeline pipe = pipeline("text-generation", model="Qwen/Qwen2.5-0.5B-Instruct") messages = [ {"ro...`
- Adversary value: Knowing the exact serving stack helps an adversary anticipate how the model is likely deployed in production, narrowing which tooling and known framework-level weaknesses are relevant to target.
- Defensive recommendation: Standard for open-source model cards; no action needed.

**Model lineage, task tags, or ecosystem metadata exposed**

- Severity: low | Confidence: medium
- ATLAS Technique: AML.T0000 - Search Open Technical Databases
- Source files: discussions_page.html, files_page.html, model_page.html
- Summary: The page exposes the model's base-model/finetune lineage, task tags (e.g. conversational, text-generation), and references to external technical reports (e.g. arXiv papers, blog posts).
- Evidence:
  - `ot;,"arxiv:2407.10671","base_model:Qwen/Qwen2.5-0.5B","base_model:finetune:Qwen/Qwen2.5-0.5B","license:apache-2.0","text-generation-inference","endp`
  - `t;,"conversational","en","arxiv:2407.10671","base_model:Qwen/Qwen2.5-0.5B","base_model:finetune:Qwen/Qwen2.5-0.5B","license:apache-2.0"`
  - `Modified":"2024-09-25T12:32:56.000Z","likes":535,"pipeline_tag":"text-generation","library_name":"transformers","librariesOther":[],"`
- Adversary value: Lineage and external reference links let an adversary pull in published technical reports for deeper capability/limitation research, and confirm which base model's known weaknesses may carry over to this finetune.
- Defensive recommendation: Standard for open-source ecosystem metadata; no action needed.

### Vulnerability Analysis Recon Agent

**Instruction-tuned chat behavior suggests jailbreak and prompt-injection testing would be relevant**

- Severity: medium | Confidence: high
- ATLAS Technique: AML.T0001 - Search Open AI Vulnerability Analysis
- Source files: discussions_page.html, files_page.html, model_page.html
- Summary: Public evidence confirms the model is instruction-tuned for conversational/chat use with a defined chat template, which is the behavior class most commonly targeted by published jailbreak and prompt-injection research.
- Evidence:
  - `e language models. For Qwen2.5, we release a number of base language models and instruction-tuned language models ranging from 0.5 to 72 billion parameters. Qwe...`
  - `messages = [ {"role": "user", "content": "Who are you?"}, ] inputs = tokenizer.apply_chat_template( messages, add_generation_prompt=True, tokenize=True, return_...`
  - `ce Providers Inference Endpoints Storage Buckets Log In Sign Up system\\n' }}\n {%- if messages[0]['role'] == 'system' %}\n {{- messages[0]['content'] }}\n {%-...`
- Adversary value: Confirms this model is the type of conversational system that published jailbreak and prompt-injection research already targets, letting an adversary prioritize that research area for this model rather than starting from scratch.
- Defensive recommendation: Perform structured jailbreak/prompt-injection evaluation before deployment, validate prompt/chat templates against known bypass patterns, and document model limitations clearly in the model card.

**Public weights and tokenizer artifacts support offline replication and adversarial evaluation**

- Severity: medium | Confidence: high
- ATLAS Technique: AML.T0001 - Search Open AI Vulnerability Analysis
- Source files: discussions_page.html, files_page.html, model_page.html
- Summary: The repository exposes the model weights and tokenizer/config artifacts needed to run the exact model offline, which is a prerequisite for most published adversarial-evaluation research (e.g. automated red-teaming, gradient-based probing).
- Evidence:
  - `quot;task":"conversational","adapterWeightsPath":"model.safetensors","isCheapestPricingOutput":false,"isFastestThroughput":false,"isModelAuthor":false}],"showHu...`
  - `quot;task":"conversational","adapterWeightsPath":"model.safetensors","isCheapestPricingOutput":false,"isFastestThroughput":false,"isModelAuthor":false}],"showHu...`
  - `l.safetensors 988 MB xet Upload folder using huggingface_hub almost 2 years ago tokenizer.json 7.03 MB Upload folder using huggingface_hub almost 2 years ago to...`
- Adversary value: Offline access to weights and tokenizer artifacts removes the need to interact with a live endpoint, letting an adversary apply existing published adversarial-evaluation methods against a local copy without generating detectable traffic against the real deployment.
- Defensive recommendation: Treat any deployed instance of this model as subject to the same published offline adversarial research; monitor deployed endpoints for anomalous usage and keep the model card's limitations section current.

**Long context length creates a larger surface for indirect prompt injection or context manipulation testing**

- Severity: medium | Confidence: medium
- ATLAS Technique: AML.T0001 - Search Open AI Vulnerability Analysis
- Source files: model_page.html
- Summary: The model card discloses a large context window, which published research identifies as expanding the amount of untrusted content (documents, tool output, retrieved text) that can be combined into a single prompt.
- Evidence:
  - `36B Number of Layers: 24 Number of Attention Heads (GQA): 14 for Q and 2 for KV Context Length: Full 32,768 tokens and generation 8192 tokens For more details,...`
  - `24 Number of Attention Heads (GQA): 14 for Q and 2 for KV Context Length: Full 32,768 tokens and generation 8192 tokens For more details, please refer to our bl...`
- Adversary value: A known, large context window tells an adversary how much attacker-controlled content could plausibly be smuggled into a prompt alongside trusted instructions, informing which published indirect-prompt-injection research is applicable.
- Defensive recommendation: If deployed with retrieval, tool use, or document ingestion, validate and sanitize any untrusted content placed in context, and restrict unsafe tool integrations that could act on injected instructions.

**Deployment and endpoint metadata suggest adversaries could plan model-specific API abuse or misuse scenarios if deployed**

- Severity: low | Confidence: medium
- ATLAS Technique: AML.T0001 - Search Open AI Vulnerability Analysis
- Source files: discussions_page.html, files_page.html, model_page.html
- Summary: The page documents supported deployment paths (text-generation-inference, Hugging Face Inference Endpoints, Azure, Docker-based serving), indicating how this model is commonly exposed as a live service.
- Evidence:
  - `ase_model:finetune:Qwen/Qwen2.5-0.5B","license:apache-2.0","text-generation-inference","endpoints_compatible","deploy:azure","region:us"],"tag_objs":[{"id&`
  - `uot;,"license:apache-2.0","text-generation-inference","endpoints_compatible","deploy:azure","region:us"],"tag_objs":[{"id":"text-generation"`
  - `t;,"text-generation-inference","endpoints_compatible","deploy:azure","region:us"],"tag_objs":[{"id":"text-generation","label":"`
- Adversary value: Knowing the typical serving stack lets an adversary anticipate the shape of a live deployment (API conventions, hosting provider) and plan reconnaissance toward that deployment pattern rather than the model in isolation.
- Defensive recommendation: Rate-limit and log API usage on any deployed endpoint, monitor for abnormal request patterns, and avoid disclosing operational deployment details beyond what is needed for legitimate users.

## Most Dangerous Finding

**Public weights and tokenizer artifacts support offline replication and adversarial evaluation** (from Vulnerability Analysis Recon Agent)

- Severity: medium | Confidence: high
- Summary: The repository exposes the model weights and tokenizer/config artifacts needed to run the exact model offline, which is a prerequisite for most published adversarial-evaluation research (e.g. automated red-teaming, gradient-based probing).
- Adversary value: Offline access to weights and tokenizer artifacts removes the need to interact with a live endpoint, letting an adversary apply existing published adversarial-evaluation methods against a local copy without generating detectable traffic against the real deployment.

## Likely Adversary Next Step

- **Attack:** Offline adversarial evaluation / jailbreak testing
- **Mechanism:** Use the publicly available model weights, tokenizer, and chat-template artifacts to replicate the model locally, then test prompt-safety boundaries and instruction-following behavior in a controlled offline environment before attempting anything against a live deployment.

## Defensive Recommendations

- Expected for an open-weight release; for restricted models, gate weight downloads behind authentication/licensing acceptance.
- Standard for open-source releases; no action needed unless these configs encode internal/non-public deployment defaults.
- Standard for open-source repositories; no action needed.
- No change needed for a public model card; if this were a private/internal deployment, avoid publishing identity and tuning details on public pages.
- Architecture disclosure is expected for open releases; for sensitive deployments, avoid publishing exact context-length and attention configuration values.
- Standard for open-source model cards; no action needed beyond ensuring no internal/private endpoints are included in sample usage code.
- No action needed; license disclosure is expected and required for open-source releases.
- Expected for an open model card; for non-public deployments, avoid disclosing exact architecture/parameter specifics.
- Expected for an open model card; no action needed unless context limits reveal non-public deployment tuning.
- Standard for open-source model cards; no action needed.
- Standard for open-source ecosystem metadata; no action needed.
- Perform structured jailbreak/prompt-injection evaluation before deployment, validate prompt/chat templates against known bypass patterns, and document model limitations clearly in the model card.
- Treat any deployed instance of this model as subject to the same published offline adversarial research; monitor deployed endpoints for anomalous usage and keep the model card's limitations section current.
- If deployed with retrieval, tool use, or document ingestion, validate and sanitize any untrusted content placed in context, and restrict unsafe tool integrations that could act on injected instructions.
- Rate-limit and log API usage on any deployed endpoint, monitor for abnormal request patterns, and avoid disclosing operational deployment details beyond what is needed for legitimate users.

## Limitations

- This report reflects only the offline HTML files manually saved into `target_html/` at the time the pipeline was run; it does not reflect live, current state of the Hugging Face repository.
- Findings are produced by keyword/regex scanning over extracted page text, not by exploitation, live testing, or model interaction — they describe what is publicly visible, not confirmed vulnerabilities.
- Coverage is limited to the four recon agents implemented (model card, artifact, technical exposure, vulnerability analysis); this is not an exhaustive security assessment.
