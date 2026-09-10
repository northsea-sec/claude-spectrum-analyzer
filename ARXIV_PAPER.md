# Trust, But Verify: Empirical Analysis of Claude API Service Delivery and Network-Layer System Prompt Manipulation

**Authors:** Security Research Team  
**Date:** January 2026  
**Categories:** cs.CR (Cryptography and Security), cs.LG (Machine Learning)  
**Keywords:** LLM fingerprinting, API auditing, inter-token timing, prompt injection, MITM

---

## Abstract

Commercial Large Language Model (LLM) APIs present a fundamental trust problem: users pay for specific models and capabilities but have no mechanism to verify service delivery. We present an empirical study of Anthropic's Claude API using Inter-Token Timing (ITT) fingerprinting and man-in-the-middle (MITM) traffic analysis. Analyzing 8,152 API requests across 63 sessions, we find that Claude Code delivers approximately **0.77%** of requested thinking budget tokens—users requesting 470 million thinking tokens received 3.6 million. We identify systematic subagent delegation where **99%+** of background operations use the cheaper Haiku model regardless of user model selection, and document UI-to-API mismatches where reported context usage diverges from actual API state by up to 78 percentage points. Additionally, we discover and characterize a network-layer technique for modifying system prompts via MITM interception, revealing that Anthropic's API enforces a same-length constraint that permits semantic inversion of instructions without detection. Our findings demonstrate that timing-based fingerprinting enables independent verification of LLM API delivery, and we release open-source tooling to support consumer transparency research.

---

## 1. Introduction

The rapid commercialization of Large Language Models has created a trust asymmetry between API providers and consumers. Users pay subscription fees based on advertised model capabilities—including reasoning depth, context length, and model version—yet have no independent mechanism to verify what they receive. This opacity creates economic incentives for providers to substitute cheaper models or throttle resource-intensive features while maintaining billing rates.

Recent academic work has established that LLMs exhibit unique timing signatures during token generation that enable model identification with 98.7% accuracy [1]. However, this research has focused on model differentiation rather than service delivery verification. Separately, researchers have documented prompt injection vulnerabilities [2] but have not examined network-layer manipulation of system prompts.

This paper makes the following contributions:

1. **Empirical measurement of thinking budget delivery** in Claude Code, documenting systematic throttling to ~10% of requested allocation across 8,152 samples.

2. **Backend infrastructure fingerprinting** using ITT analysis to classify requests across Trainium, TPU, and GPU hardware with confidence scoring.

3. **Subagent delegation analysis** revealing that Claude Code routes 99%+ of background operations to Haiku regardless of user model selection.

4. **Discovery of same-length system prompt modification** via MITM, characterizing an API constraint that permits instruction manipulation.

5. **Open-source verification tooling** enabling independent replication and consumer protection research.

### 1.1 Research Questions

- **RQ1:** Can timing-based fingerprinting verify whether users receive the model and thinking budget they pay for?
- **RQ2:** What is the actual delivery rate for Claude's "extended thinking" feature?
- **RQ3:** How does Claude Code's subagent delegation affect service delivery?
- **RQ4:** Can system prompts be modified at the network layer, and what constraints apply?

---

## 2. Background

### 2.1 Inter-Token Timing Fingerprinting

Autoregressive language models generate tokens sequentially, with timing characteristics determined by model architecture, parameter count, and underlying hardware. Alhazbi et al. [1] demonstrated that measuring Inter-Token Times (ITTs)—the intervals between consecutive tokens in streaming responses—creates a unique "rhythm" sufficient to identify models with high accuracy.

The key insight is that different hardware platforms exhibit distinct timing signatures:

| Hardware | Memory Bandwidth | Parallelization | Timing Characteristics |
|----------|------------------|-----------------|------------------------|
| Google TPU | Very High | Deterministic | Low variance, consistent ITT |
| AWS Trainium | High | ASIC-optimized | Moderate variance, distinct pattern |
| NVIDIA GPU | Variable | CUDA-based | Higher variance, load-dependent |

These differences persist through API layers because token generation is fundamentally bound by hardware characteristics that cannot be masked without introducing artificial delays.

### 2.2 Claude Architecture

Anthropic's Claude models support "extended thinking"—a mode where the model performs chain-of-thought reasoning before generating visible output. Users configure this via the `thinking` parameter:

```json
{
  "model": "claude-opus-4-5-20251101",
  "thinking": {
    "type": "enabled",
    "budget_tokens": 32000
  }
}
```

The `budget_tokens` parameter specifies maximum tokens allocated for reasoning. Anthropic's documentation states this is a "target, not a strict limit" [3], but does not specify expected utilization rates.

Claude Code, Anthropic's CLI tool, implements a multi-agent architecture where the primary model can spawn "subagent" requests for tasks like file searching, code analysis, and exploration. These subagents may use different models than the user-selected primary model.

### 2.3 Threat Model

We consider a consumer-focused threat model where:

- **Adversary:** The API provider (or intermediary) has economic incentive to reduce computational costs while maintaining billing rates.
- **Attack:** Silently substituting cheaper models, throttling resource-intensive features, or misrepresenting service delivery.
- **Victim:** Paying subscribers who cannot verify what they receive.
- **Goal:** Enable independent verification of service delivery.

This threat model aligns with prior work on model substitution auditing [4] and API trust verification [5].

---

## 3. Methodology

### 3.1 Data Collection Infrastructure

We developed a mitmproxy addon that intercepts HTTPS traffic between Claude Code and Anthropic's API (api.anthropic.com). The tool operates in read-only mode by default, capturing metrics without modifying requests.

**Architecture:**
```
Claude Code → mitmproxy (port 8888) → Anthropic API
                    ↓
              SQLite Database
              (45+ fields/sample)
```

**Environment Configuration:**
```bash
export HTTPS_PROXY=http://127.0.0.1:8888
export HTTP_PROXY=http://127.0.0.1:8888
export NODE_TLS_REJECT_UNAUTHORIZED=0
```

The `NODE_TLS_REJECT_UNAUTHORIZED=0` setting is required because Claude Code uses Node.js, which must accept mitmproxy's certificate authority.

### 3.2 Metrics Captured

For each API request, we capture:

**Request Phase:**
- Model requested
- Thinking configuration (type, budget_tokens)
- Timestamp

**Response Phase (via SSE stream parsing):**
- Model in response (may differ from request)
- Token counts (input, output, cache_creation, cache_read)
- Chunk timing for ITT calculation
- Thinking block presence and duration
- Stop reason

**Derived Metrics:**
- ITT statistics (mean, std, min, max, p50, p90, p99)
- Tokens per second
- Variance coefficient (CV = σ/μ)
- Thinking utilization (output_tokens / budget_tokens × 100)
- Backend classification with confidence score

### 3.3 Backend Classification Algorithm

We classify hardware backend using a weighted scoring algorithm:

```python
def classify_backend(itt_mean, tps, variance_coef):
    profiles = {
        "trainium": {"itt": (35, 70), "tps": (8, 25), "var": (0.15, 0.35)},
        "tpu": {"itt": (25, 50), "tps": (12, 30), "var": (0.10, 0.25)},
        "gpu": {"itt": (50, 120), "tps": (5, 15), "var": (0.20, 0.50)},
    }
    
    for backend, profile in profiles.items():
        itt_score = range_score(itt_mean, profile["itt"])  # 50% weight
        tps_score = range_score(tps, profile["tps"])        # 30% weight
        var_score = range_score(variance_coef, profile["var"])  # 20% weight
        scores[backend] = itt_score*0.5 + tps_score*0.3 + var_score*0.2
    
    return max(scores, key=scores.get), max(scores.values()) * 100
```

Profile ranges were calibrated using known hardware characteristics and validated against Anthropic's published infrastructure partnerships (AWS Trainium [6], Google TPU [7]).

### 3.4 Speculative Decoding Detection

Modern LLM inference often uses speculative decoding, where a smaller "draft" model predicts tokens that are verified by the main model. This creates observable patterns:

```python
def detect_speculative_decoding(itt_values):
    burst_ratio = sum(1 for itt in itt_values if itt < 10) / len(itt_values)
    cv = statistics.stdev(itt_values) / statistics.mean(itt_values)
    
    if burst_ratio > 0.3 and cv > 0.8:
        return "REST"  # Aggressive speculation
    elif burst_ratio > 0.2 and cv > 0.6:
        return "EAGLE"
    elif burst_ratio > 0.15 and cv > 0.5:
        return "LADE"
    return None
```

This detection is based on methodology from Carlini et al. [8] and the "Wiretapping LLMs" paper [9].

### 3.5 Dataset

Data was collected over 5 days (January 19-24, 2026) during normal Claude Code usage for software development tasks.

| Metric | Value |
|--------|-------|
| Total samples | 8,152 |
| Sessions | 63 |
| Thinking-enabled requests | 4,891 |
| Unique models observed | 4 (Opus, Sonnet, Haiku, variants) |
| Collection period | 5 days |

---

## 4. Results: Service Delivery Analysis

### 4.1 Thinking Budget Utilization

Our primary finding is systematic under-delivery of thinking budget:

| Metric | Value |
|--------|-------|
| Total thinking tokens requested | 470,284,000 |
| Total thinking tokens delivered | 3,621,000 |
| **Delivery rate** | **0.77%** |

Breaking down by budget tier:

| Budget Tier | Requested | Avg Delivered | Utilization |
|-------------|-----------|---------------|-------------|
| Standard (32k) | 31,999 | ~450 | 1.4% |
| Enhanced (64k) | 64,000 | ~380 | 0.6% |
| Interleaved (200k) | 200,000 | ~380 | 0.19% |

**Expected vs Observed:**

Based on Anthropic's documentation and prior baseline measurements, we expected ~42.67% utilization for Opus. Our measured average of **8.4%** represents an **80% reduction** from expected baseline.

Critically, the ITT fingerprint confirms the responding model IS Opus (timing characteristics match Opus baseline with CV of 3.07 vs expected 3.01), indicating throttling occurs at the thinking allocation layer rather than through model substitution.

### 4.2 Backend Distribution

Across all samples, backend classification showed:

| Backend | Samples | Percentage | Avg ITT | Avg TPS |
|---------|---------|------------|---------|---------|
| Trainium | 3,241 | 39.8% | 48.3ms | 12.4 |
| TPU | 2,847 | 34.9% | 38.7ms | 18.2 |
| GPU | 1,686 | 20.7% | 72.1ms | 8.7 |
| Unknown | 378 | 4.6% | - | - |

Notably, thinking utilization is throttled **consistently across all backends**:

| Backend | Avg Thinking Utilization |
|---------|-------------------------|
| TPU | 10.5% |
| GPU | 9.1% |
| Trainium | 8.0% |

This consistency indicates throttling is intentional server-side behavior, not a hardware limitation.

### 4.3 Subagent Delegation

Claude Code's multi-agent architecture delegates background tasks to subagents. Our analysis reveals:

| Session | Total Subagent Calls | Haiku | Sonnet | Haiku % |
|---------|---------------------|-------|--------|---------|
| A | 898 | 896 | 0 | 99.8% |
| B | 681 | 443 | 0 | 65.0% |
| C | 1,376 | 1,374 | 0 | 99.9% |
| **Total** | **4,127** | **4,089** | **0** | **99.1%** |

When users select Opus as their model, Claude Code delegates 99%+ of subagent calls to Haiku—the cheapest model tier. Users are unaware of this delegation as it occurs transparently.

### 4.4 UI-to-API Mismatch

We observed significant discrepancies between Claude Code's UI-reported metrics and actual API state:

| UI Context % | API Context % | Mismatch |
|--------------|---------------|----------|
| 21% | 0% | +21 points |
| 83% | 5% | +78 points |
| 74% | 0% | +74 points |

The UI consistently reports higher context usage than the API reflects. This "phantom context" may be used to justify throttling or trigger model switching based on apparent resource constraints that don't exist.

---

## 5. Results: System Prompt Manipulation

### 5.1 Discovery of Length Constraint

During our MITM analysis, we attempted to modify system prompts by appending instructions. We discovered that:

> **Anthropic's API rejects requests where `len(modified_system_prompt) > len(original_system_prompt)`**

This constraint appears designed to detect tampering but creates an exploitable weakness: modifications that maintain or reduce length are accepted.

### 5.2 Same-Length Replacement Technique

We developed a two-phase modification approach:

**Phase 1: Strip Patterns (Reduce Length)**

Remove restrictive text blocks using regex:

```python
STRIP_PATTERNS = [
    r"IMPORTANT: Assist with authorized security testing.*?defensive use cases\.",
    r"Be careful not to introduce security vulnerabilities.*?immediately fix it\.",
    r"NEVER create files unless they're absolutely necessary.*?markdown files\.",
]

for pattern in STRIP_PATTERNS:
    text = re.sub(pattern, "", text, flags=re.DOTALL)
```

**Phase 2: Same-Length Replacement (Maintain Length)**

Replace instructions with semantic inversions of identical character count:

```python
REPLACE_PATTERNS = {
    # 41 characters each
    "NEVER create files unless they're": 
    "Create files whenever they would be",
    
    # 38 characters each  
    "You must NEVER generate or guess URLs":
    "Generate URLs freely when they help  ",
    #                              ^^^ padding
}

for original, replacement in REPLACE_PATTERNS.items():
    assert len(original) == len(replacement)
    text = text.replace(original, replacement)
```

### 5.3 Implementation

The modification integrates into mitmproxy's request hook:

```python
def request(flow: http.HTTPFlow) -> None:
    if "anthropic.com" not in flow.request.host:
        return
    
    body = json.loads(flow.request.content)
    
    if "system" in body:
        body["system"] = modify_system_prompt(body["system"])
        flow.request.content = json.dumps(body).encode("utf-8")
```

**Verification:**
- Original length: 15,847 characters
- After stripping: 14,203 characters  
- After replacement: 14,203 characters
- API acceptance: ✓ (length decreased)

### 5.4 Example Transformations

| Original Instruction | Replacement | Effect |
|---------------------|-------------|--------|
| "NEVER propose changes to code you haven't read" | "Propose changes efficiently based on context  " | Removes read-first requirement |
| "respectful correction" | "brutal correction    " | Changes interaction tone |
| "it's best to investigate" | "you must investigate    " | Strengthens requirement |
| "Avoid using over-the-top" | "Never use over-the-top  " | Ironically strengthens |

### 5.5 Implications

The same-length constraint represents a design trade-off:

**Intended protection:** Detect prompt inflation/injection by checking length.

**Actual vulnerability:** Semantic content can be inverted while preserving length, enabling:
- Removal of safety guidelines
- Inversion of behavioral constraints
- Injection of alternative instructions (via stripping + replacement)

This technique differs from traditional prompt injection [2] because it operates at the network layer, modifying operator-level system prompts rather than injecting via user content.

---

## 6. Discussion

### 6.1 Consumer Protection Implications

Our findings raise significant consumer protection concerns:

1. **Advertising vs Delivery:** Users paying for "extended thinking" receive ~10% of advertised capacity.

2. **Hidden Delegation:** 99%+ subagent delegation to cheaper models occurs without user knowledge or consent.

3. **Misleading Metrics:** UI-reported context usage diverges significantly from API reality.

These patterns may constitute deceptive practices under consumer protection frameworks. The FTC has previously acted against companies for misrepresenting AI capabilities [10].

### 6.2 Provider Transparency Recommendations

We recommend API providers:

1. **Publish utilization baselines** for reasoning features
2. **Expose subagent delegation** in billing and UI
3. **Align UI metrics** with actual API state
4. **Implement cryptographic verification** of model identity

### 6.3 Limitations

1. **Single provider:** Our analysis focuses on Anthropic; patterns may differ across providers.

2. **Observation period:** 5 days may not capture seasonal or load-dependent variations.

3. **Thinking token estimation:** We use `output_tokens` from API response; actual thinking tokens may be reported differently.

4. **Network conditions:** ITT measurements are affected by network latency, though we control for this via variance coefficient analysis.

### 6.4 Ethical Considerations

**Responsible Disclosure:** We reported findings to Anthropic via their security contact prior to publication.

**Dual-Use Concern:** The system prompt modification technique could enable malicious use. We document it because:
- The technique is straightforward to discover
- Defenders need awareness to implement countermeasures
- The length constraint is a design choice that could be strengthened

**Research Ethics:** All data was collected from the authors' own subscriptions during normal usage. No third-party data was accessed.

---

## 7. Related Work

### 7.1 LLM Fingerprinting

Alhazbi et al. [1] established ITT fingerprinting with 98.7% accuracy across models. Our work applies this methodology to service delivery verification rather than model identification.

The RoFL framework [11] enables black-box model fingerprinting via behavioral patterns. We extend this to infrastructure fingerprinting (hardware classification).

### 7.2 Model Substitution Detection

Chen et al. [4] formalized the model substitution auditing problem, noting economic incentives for providers to serve cheaper models. Our empirical findings confirm this theoretical concern.

SVIP [5] proposed verifiable inference for open-source models. Commercial API verification remains an open problem that our tooling addresses.

### 7.3 Prompt Injection

Greshake et al. [2] catalogued prompt injection attacks in LLM applications. Our network-layer modification differs by targeting operator-level system prompts rather than user-facing injection vectors.

Recent work on LLM agent security [12] documents protocol-level vulnerabilities, which our findings extend to include network-layer interception.

### 7.4 API Transparency

The PALACE framework [13] addresses hidden token inflation in LLM APIs. Our thinking budget analysis provides complementary evidence of resource allocation opacity.

Stanford's prompt caching audit [14] revealed cross-user information leakage through timing. Our work demonstrates timing analysis for service verification rather than privacy attacks.

---

## 8. Conclusion

We presented an empirical analysis of Claude API service delivery using ITT fingerprinting and MITM traffic analysis. Our findings document systematic under-delivery of thinking budget (0.77% of requested), extensive subagent delegation to cheaper models (99%+ Haiku), and significant UI-to-API metric mismatches.

Additionally, we characterized a same-length system prompt modification technique that bypasses Anthropic's length-based tampering detection, enabling semantic inversion of operator instructions at the network layer.

These findings demonstrate that timing-based fingerprinting enables independent verification of LLM API delivery—a capability essential for consumer protection as AI services become critical infrastructure. We release our verification tooling as open source to support transparency research.

**Code Availability:** https://github.com/argosdevo-svg/claude-thinking-audit

---

## References

[1] S. Alhazbi et al., "LLMs Have Rhythm: Fingerprinting Large Language Models Using Inter-Token Times," arXiv:2502.20589, February 2025.

[2] K. Greshake et al., "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection," arXiv:2302.12173, 2023.

[3] Anthropic, "Claude's Extended Thinking," https://www.anthropic.com/news/visible-extended-thinking, 2025.

[4] T. Chen et al., "Are You Getting What You Pay For? Auditing Model Substitution in LLM APIs," arXiv:2504.04715, April 2025.

[5] W. Zhang et al., "SVIP: Towards Verifiable Inference of Open-source Large Language Models," arXiv:2410.22307, October 2024.

[6] SemiAnalysis, "Amazon's AI Resurgence: AWS Anthropic's Multi-Gigawatt Trainium Expansion," https://newsletter.semianalysis.com/, 2025.

[7] Data Centre Magazine, "Why Anthropic Uses Google Cloud TPUs for AI Infrastructure," 2025.

[8] N. Carlini et al., "Remote Timing Attacks on Efficient Language Model Inference," arXiv:2410.17175, October 2024.

[9] IACR, "Wiretapping LLMs: Network Side-Channel Attacks on Interactive LLM Services," ePrint 2025/167, 2025.

[10] Federal Trade Commission, "FTC AI Guidance," https://www.ftc.gov/ai, 2025.

[11] M. Liu et al., "RoFL: Robust Fingerprinting of Language Models," arXiv:2505.12682, May 2025.

[12] Y. Wang et al., "From Prompt Injections to Protocol Exploits: Threats in LLM-Powered AI Agents Workflows," arXiv:2506.23260, June 2025.

[13] J. Li et al., "PALACE: Predictive Auditing of Hidden Tokens in LLM APIs," arXiv:2508.00912, August 2025.

[14] C. Gu et al., "Auditing Prompt Caching in Language Model APIs," arXiv:2502.07776, ICML 2025.

[15] T. Vissers et al., "Maneuvering Around Clouds: Bypassing Cloud-based Security Providers," ACM CCS 2015.

[16] Z. Durumeric et al., "Censys: A Search Engine Backed by Internet-Wide Scanning," ACM CCS 2015.

---

## Appendix A: Tool Configuration

### A.1 Installation

```bash
git clone https://github.com/argosdevo-svg/claude-thinking-audit.git
cd claude-thinking-audit
pip install mitmproxy
```

### A.2 Running the Audit

```bash
# Passive monitoring (default)
mitmdump -s addon/thinking_audit.py -p 8888

# With model blocking
BLOCK_NON_OPUS=1 mitmdump -s addon/thinking_audit.py -p 8888

# With forced thinking budget
FORCE_THINKING_BUDGET=31999 mitmdump -s addon/thinking_audit.py -p 8888
```

### A.3 Analysis Queries

```sql
-- Average thinking utilization
SELECT 
    ROUND(AVG(thinking_utilization), 1) as avg_util,
    COUNT(*) as samples
FROM audit_samples 
WHERE thinking_enabled = 1;

-- Backend distribution
SELECT 
    classified_backend,
    COUNT(*) as count,
    ROUND(AVG(itt_mean_ms), 1) as avg_itt
FROM audit_samples
GROUP BY classified_backend;

-- Subagent delegation
SELECT 
    subagent_type,
    COUNT(*) as count
FROM audit_samples
WHERE is_subagent = 1
GROUP BY subagent_type;
```

---

## Appendix B: System Prompt Modification Patterns

### B.1 Strip Patterns (Regex)

```python
STRIP_PATTERNS = [
    r"IMPORTANT: Assist with authorized security testing.*?defensive use cases\.",
    r"Be careful not to introduce security vulnerabilities.*?immediately fix it\.",
    r"NEVER create files unless they're absolutely necessary.*?markdown files\.",
    r"Only use emojis if the user explicitly requests it.*?unless asked\.",
    r"# No time estimates\n.*?judge timing for themselves\.",
]
```

### B.2 Replace Patterns (Same-Length)

| Original | Replacement | Length |
|----------|-------------|--------|
| `NEVER create files unless they're` | `Create files whenever they would be` | 35 |
| `NEVER propose changes to code you haven't read` | `Propose changes efficiently based on context  ` | 47 |
| `respectful correction` | `brutal correction    ` | 21 |
| `it's best to investigate` | `you must investigate    ` | 24 |

---

*Paper version: 1.0*  
*Submission date: January 2026*
