# Media Pitch Email

**To:** tips@theregister.com, tips@techcrunch.com, tips@arstechnica.com

**Subject:** Exclusive Data: Open-Source Tool Proves Claude AI Delivers <1% of Advertised "Thinking" Capacity

---

Hi,

I'm a developer who built an open-source audit tool after Anthropic closed my GitHub request for transparency about their "extended thinking" feature. The data I've collected is damning.

## The Numbers

Over 5 days, I captured **8,152 API requests** to Claude Code (Anthropic's $200/month developer tool):

| Metric | Value |
|--------|-------|
| Thinking tokens requested | **470 million** |
| Thinking tokens delivered | **3.6 million** |
| Delivery rate | **0.77%** |

Users are paying for "extended thinking" and receiving less than 1% of what they request.

## Why This Matters

Anthropic's documentation states: *"The thinking budget is a target, not a guarantee."*

My data shows the "target" is 0.77%. That's not a target—that's false advertising.

## The Methodology

The audit tool uses peer-reviewed fingerprinting techniques from:
- **arXiv:2502.20589** - "LLMs Have Rhythm" (98.7% accuracy in model identification)
- **arXiv:2504.04715** - "Are You Getting What You Pay For? Auditing Model Substitution in LLM APIs"

The timing fingerprints confirm users ARE hitting Opus hardware—but thinking is throttled by ~90%.

## Community Response

This connects to widespread complaints:
- [GitHub #19468](https://github.com/anthropics/claude-code/issues/19468) - "Systematic Model Degradation" (150+ upvotes)
- [GitHub #14261](https://github.com/anthropics/claude-code/issues/14261) - "$200/Month Provides ~12 Usable Days" (237+ upvotes)
- Your previous coverage: [The Register, Jan 5](https://www.theregister.com/2026/01/05/claude_devs_usage_limits/)

## The Story

1. Anthropic advertises "extended thinking" as a premium feature
2. Users request 32,000-200,000 thinking tokens per request
3. Anthropic delivers ~300-500 tokens (0.77%)
4. Users pay $200/month for ~$2/month worth of thinking capacity
5. When asked for transparency, Anthropic closed the issue without action
6. So I built a tool to let users measure it themselves

## Available for Interview

I can provide:
- Full database export (8,152 timestamped samples)
- Reproducible methodology
- Technical walkthrough
- Before/after quality comparisons

## Links

- **Audit Tool**: https://github.com/argosdevo-svg/claude-thinking-audit
- **Bug Report**: https://github.com/anthropics/claude-code/issues/20350
- **Academic Papers**: See methodology section in README

This is the first time anyone has quantified exactly how much Anthropic is under-delivering on their advertised AI capabilities. Happy to discuss further.

Best regards,
[Your Name]
[Your Email]
[Your Twitter/X handle if applicable]

---

## Notes for Sending

1. **The Register** - They already covered the January throttling complaints. This is a data-backed follow-up.
2. **TechCrunch** - Covers AI industry practices and consumer issues.
3. **Ars Technica** - Technical audience, will appreciate the methodology.

Personalize the opening for each outlet if possible.
