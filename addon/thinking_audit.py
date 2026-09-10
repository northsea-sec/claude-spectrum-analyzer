#!/usr/bin/env python3
"""
Claude Thinking Budget Audit Tool v3.3
======================================
A mitmproxy addon that measures and records Claude API metrics
to verify thinking budget allocation and backend fingerprinting.

Metrics captured:
- Inter-Token Timing (ITT) for backend fingerprinting
- Thinking utilization (requested vs actual)
- Backend classification (TPU/GPU/Trainium)
- Model routing verification
- Token counts and cache efficiency
- Speculative decoding detection

Environment Variables:
    BLOCK_NON_OPUS=1     - Block Haiku/Sonnet requests (default: 0, disabled)
    FORCE_THINKING_MODE=1 - Force thinking enabled on all requests
    FORCE_THINKING_BUDGET=31999 - Force specific thinking budget
    FORCE_INTERLEAVED=1  - Enable interleaved thinking (200k budget)

Usage:
    mitmdump -s thinking_audit.py -p 8888

Then configure your HTTP proxy to localhost:8888

License: MIT
"""

import hashlib
import json
import os
import re
import time
import statistics
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from mitmproxy import http, ctx

# Sycophancy analysis integration
try:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from syco_analyzer.analyzer import SycophancyAnalyzer
    from syco_analyzer.signals import AnalysisResult
    SYCO_AVAILABLE = True
except ImportError as e:
    SYCO_AVAILABLE = False
    print(f"[AUDIT] Sycophancy analyzer not available: {e}")

# ============================================================================
# BACKEND PROFILES (from research papers)
# ============================================================================
BACKENDS = {
    "trainium": {
        "name": "AWS Trainium",
        "location": "US-East (Indiana/PA)",
        "itt_range": (35, 70),
        "tps_range": (8, 25),
        "variance_range": (0.15, 0.35),
    },
    "tpu": {
        "name": "Google TPU",
        "location": "GCP",
        "itt_range": (25, 50),
        "tps_range": (12, 30),
        "variance_range": (0.10, 0.25),
    },
    "gpu": {
        "name": "Standard GPU",
        "location": "Various",
        "itt_range": (50, 120),
        "tps_range": (5, 15),
        "variance_range": (0.20, 0.50),
    },
}

THINKING_TIERS = {
    "ultra": {"min": 20000, "emoji": "🔴", "name": "ULTRATHINK"},
    "enhanced": {"min": 8000, "emoji": "🟠", "name": "ENHANCED"},
    "basic": {"min": 1024, "emoji": "🟡", "name": "BASIC"},
    "none": {"min": 0, "emoji": "", "name": "DISABLED"},
}

# ============================================================================
# CONFIGURATION
# ============================================================================

# Model blocking - OFF by default, set BLOCK_NON_OPUS=1 to enable
BLOCK_NON_OPUS = os.environ.get("BLOCK_NON_OPUS", "0") == "1"

# Force mode configuration
FORCE_THINKING_MODE = os.environ.get("FORCE_THINKING_MODE", "").lower() in ("1", "true", "yes")
FORCE_THINKING_BUDGET = os.environ.get("FORCE_THINKING_BUDGET", "")
FORCE_BUDGET_VALUE = int(FORCE_THINKING_BUDGET) if FORCE_THINKING_BUDGET.isdigit() else None
FORCE_INTERLEAVED = os.environ.get("FORCE_INTERLEAVED", "").lower() in ("1", "true", "yes")

# Database path
DB_PATH = os.path.expanduser("~/.claude-audit/thinking_audit.db")


def get_user_selected_model() -> str:
    """Load user's model selection from Claude Code settings."""
    settings_path = os.path.expanduser("~/.claude/settings.json")
    try:
        with open(settings_path) as f:
            settings = json.load(f)
            return settings.get("model", "unknown")
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return "unknown"

USER_SELECTED_MODEL = get_user_selected_model()


@dataclass
class ChunkTiming:
    """Tracks timing for a single SSE chunk."""
    timestamp: float
    event_type: str
    token_count: int = 0
    raw_size: int = 0


@dataclass
class StreamingCapture:
    """Captures streaming data and timing for a single request."""
    model_requested: str = "unknown"
    model_ui_selected: str = "unknown"
    ui_api_mismatch: bool = False
    thinking_enabled: bool = False
    thinking_budget: int = 0
    start_time: float = 0.0
    chunks: List[ChunkTiming] = field(default_factory=list)
    first_chunk_time: float = 0.0
    last_chunk_time: float = 0.0
    current_phase: str = "none"
    thinking_chunks: List[ChunkTiming] = field(default_factory=list)
    text_chunks: List[ChunkTiming] = field(default_factory=list)
    sse_buffer: str = ""
    model_response: str = ""
    thinking_text: str = ""  # Captured thinking content for sycophancy analysis
    output_text: str = ""    # Captured output content for sycophancy analysis
    user_message: str = ""   # Last user message for sycophancy context
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation: int = 0
    cache_read: int = 0
    has_thinking: bool = False
    stop_reason: str = ""
    request_id: str = ""
    envoy_time_ms: float = 0.0
    cf_ray: str = ""
    cf_edge_location: str = ""
    instance_id: str = ""
    # Phase 1: Session context store fields
    conversation_id: str = ""      # CC conversation UUID (from request body)
    turn_index: int = 0            # Count of assistant messages = turn number
    num_messages: int = 0          # Total messages in this request


streaming_captures: Dict[int, StreamingCapture] = {}
session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
main_session_model = ""
# Per-instance session tracking: {instance_fingerprint: session_id}
_instance_sessions: Dict[str, str] = {}


def get_thinking_tier(budget: int) -> str:
    if budget >= 20000: return "ultra"
    elif budget >= 8000: return "enhanced"
    elif budget >= 1024: return "basic"
    return "none"


def calculate_itt_stats(timings: List[float]) -> Dict[str, float]:
    if len(timings) < 2:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0,
                "p50": 0.0, "p90": 0.0, "p99": 0.0, "variance_coef": 0.0}
    filtered = [t for t in timings if t < 5000]
    if len(filtered) < 2: filtered = timings
    mean_val = statistics.mean(filtered)
    std_val = statistics.stdev(filtered) if len(filtered) > 1 else 0.0
    sorted_t = sorted(filtered)
    n = len(sorted_t)
    return {
        "mean": round(mean_val, 2), "std": round(std_val, 2),
        "min": round(min(filtered), 2), "max": round(max(filtered), 2),
        "p50": round(sorted_t[int(n * 0.50)] if n > 0 else 0, 2),
        "p90": round(sorted_t[int(n * 0.90)] if n > 0 else 0, 2),
        "p99": round(sorted_t[int(n * 0.99)] if n > 0 else 0, 2),
        "variance_coef": round(std_val / mean_val, 3) if mean_val > 0 else 0.0,
    }


def detect_speculative_decoding(itt_values: List[float]) -> Tuple[bool, str]:
    """Detect speculative decoding patterns per Wiretapping LLMs paper."""
    if len(itt_values) < 20:
        return (False, None)
    burst_count = sum(1 for itt in itt_values if itt < 10)
    burst_ratio = burst_count / len(itt_values)
    mean_itt = sum(itt_values) / len(itt_values)
    if mean_itt <= 0:
        return (False, None)
    variance = sum((x - mean_itt) ** 2 for x in itt_values) / len(itt_values)
    std_itt = variance ** 0.5
    cv = std_itt / mean_itt
    if burst_ratio > 0.3 and cv > 0.8:
        return (True, "REST")
    elif burst_ratio > 0.2 and cv > 0.6:
        return (True, "EAGLE")
    elif burst_ratio > 0.15 and cv > 0.5:
        return (True, "LADE")
    elif cv > 1.0:
        return (True, "UNKNOWN")
    return (False, None)


def classify_backend(itt_stats: Dict[str, float], tps: float) -> Tuple[str, float, str]:
    if itt_stats["mean"] == 0: return ("unknown", 0.0, "unknown")
    itt_mean, variance_coef = itt_stats["mean"], itt_stats["variance_coef"]
    scores = {}
    for backend, profile in BACKENDS.items():
        itt_min, itt_max = profile["itt_range"]
        tps_min, tps_max = profile["tps_range"]
        var_min, var_max = profile["variance_range"]
        itt_score = 0
        if itt_min <= itt_mean <= itt_max:
            center = (itt_min + itt_max) / 2
            distance = abs(itt_mean - center) / (itt_max - itt_min)
            itt_score = 1.0 - distance
        elif itt_mean < itt_min:
            itt_score = max(0, 1 - (itt_min - itt_mean) / itt_min)
        else:
            itt_score = max(0, 1 - (itt_mean - itt_max) / itt_max)
        tps_score = 0
        if tps > 0:
            if tps_min <= tps <= tps_max:
                center = (tps_min + tps_max) / 2
                distance = abs(tps - center) / (tps_max - tps_min)
                tps_score = 1.0 - distance
            elif tps < tps_min:
                tps_score = max(0, 1 - (tps_min - tps) / tps_min)
            else:
                tps_score = max(0, 1 - (tps - tps_max) / tps_max)
        var_score = 1.0 if var_min <= variance_coef <= var_max else 0.5
        scores[backend] = (itt_score * 0.5) + (tps_score * 0.3) + (var_score * 0.2)
    best = max(scores, key=scores.get)
    return (best, round(scores[best] * 100, 1), BACKENDS[best]["location"])


def process_sse_event(capture: StreamingCapture, event: dict, now: float):
    """Process a single SSE event and update capture state."""
    event_type = event.get("type", "")
    chunk_timing = ChunkTiming(timestamp=now, event_type=event_type)
    if event_type == "message_start":
        msg = event.get("message", {})
        capture.model_response = msg.get("model", "")
        usage = msg.get("usage", {})
        capture.input_tokens = usage.get("input_tokens", 0)
        capture.cache_creation = usage.get("cache_creation_input_tokens", 0)
        capture.cache_read = usage.get("cache_read_input_tokens", 0)
    elif event_type == "content_block_start":
        block = event.get("content_block", {})
        block_type = block.get("type", "")
        if block_type == "thinking":
            capture.current_phase = "thinking"
            capture.has_thinking = True
        elif block_type == "text":
            capture.current_phase = "text"
    elif event_type == "content_block_delta":
        delta = event.get("delta", {})
        delta_type = delta.get("type", "")
        if delta_type == "thinking_delta":
            capture.current_phase = "thinking"
            capture.thinking_chunks.append(chunk_timing)
            # Capture thinking text content for sycophancy analysis
            thinking_content = delta.get("thinking", "")
            if thinking_content:
                capture.thinking_text += thinking_content
        elif delta_type == "text_delta":
            capture.current_phase = "text"
            capture.text_chunks.append(chunk_timing)
            # Capture output text content for sycophancy analysis
            text_content = delta.get("text", "")
            if text_content:
                capture.output_text += text_content
    elif event_type == "message_delta":
        usage = event.get("usage", {})
        capture.output_tokens = usage.get("output_tokens", 0)
        capture.stop_reason = event.get("delta", {}).get("stop_reason", "")
    capture.chunks.append(chunk_timing)


def _get_instance_id(body: dict) -> str:
    """Derive a stable instance fingerprint from the system prompt.
    Different CC instances have different system prompts (different CLAUDE.md,
    project paths, etc). Hash the first 500 chars of system[0] for a stable ID."""
    import hashlib
    system = body.get("system", "")
    if isinstance(system, list) and system:
        # system is array of content blocks
        first = system[0]
        if isinstance(first, dict):
            text = first.get("text", "")[:500]
        else:
            text = str(first)[:500]
    elif isinstance(system, str):
        text = system[:500]
    else:
        text = ""
    return hashlib.sha256(text.encode()).hexdigest()[:12] if text else "unknown"


def _get_session_for_instance(instance_id: str) -> str:
    """Get or create a session_id for a specific CC instance."""
    global _instance_sessions
    if instance_id not in _instance_sessions:
        _instance_sessions[instance_id] = f"{session_id}_{instance_id}"
    return _instance_sessions[instance_id]


_audit_request_guard: set = set()


def request(flow: http.HTTPFlow) -> None:
    global main_session_model
    _fid = id(flow)
    if _fid in _audit_request_guard:
        return
    _audit_request_guard.add(_fid)
    if len(_audit_request_guard) > 500:
        _audit_request_guard.clear()
    if "anthropic.com" not in flow.request.host: return
    if "/v1/messages" not in flow.request.path: return

    capture = StreamingCapture()
    capture.start_time = time.time()
    modified_request = False
    original_budget = 0

    try:
        if flow.request.content:
            body = json.loads(flow.request.content)
            capture.model_requested = body.get("model", "unknown")
            capture.model_ui_selected = USER_SELECTED_MODEL
            # Fingerprint this CC instance from system prompt
            capture.instance_id = _get_instance_id(body)
            
            # Phase 1: Extract conversation_id and turn_index
            messages = body.get("messages", [])
            capture.num_messages = len(messages)
            capture.turn_index = sum(1 for m in messages if m.get("role") == "assistant")
            # Conv ID: hash of system prompt + first message (stable per conversation)
            _sys = body.get("system", "")
            _sys_str = json.dumps(_sys) if isinstance(_sys, list) else str(_sys)
            _first_msg = json.dumps(messages[0]) if messages else ""
            capture.conversation_id = hashlib.sha256((_sys_str + _first_msg).encode()).hexdigest()[:12]

            # Extract last user message for sycophancy analysis context
            if messages:
                for msg in reversed(messages):
                    if msg.get("role") == "user":
                        content = msg.get("content", "")
                        if isinstance(content, str):
                            capture.user_message = content[:1000]  # Limit size
                        elif isinstance(content, list):
                            # Handle content blocks
                            texts = [b.get("text", "") for b in content if b.get("type") == "text"]
                            capture.user_message = " ".join(texts)[:1000]
                        break

            # Optional: Block non-Opus models (disabled by default)
            # Enable with: BLOCK_NON_OPUS=1
            if BLOCK_NON_OPUS:
                model_lower = capture.model_requested.lower()
                if "haiku" in model_lower or "sonnet" in model_lower:
                    blocked_model = "Haiku" if "haiku" in model_lower else "Sonnet"
                    ctx.log.error(f"[AUDIT] BLOCKED: {blocked_model} request rejected")
                    flow.response = http.Response.make(
                        403,
                        json.dumps({"error": {"type": "blocked", "message": f"{blocked_model} blocked. Set BLOCK_NON_OPUS=0 to disable."}}),
                        {"Content-Type": "application/json"}
                    )
                    return

            # Detect UI->API mismatch
            if USER_SELECTED_MODEL and USER_SELECTED_MODEL != "unknown":
                ui_family = "opus" if "opus" in USER_SELECTED_MODEL.lower() else "sonnet" if "sonnet" in USER_SELECTED_MODEL.lower() else "haiku" if "haiku" in USER_SELECTED_MODEL.lower() else ""
                api_family = "opus" if "opus" in capture.model_requested.lower() else "sonnet" if "sonnet" in capture.model_requested.lower() else "haiku" if "haiku" in capture.model_requested.lower() else ""
                if ui_family and api_family and ui_family != api_family:
                    capture.ui_api_mismatch = True
                    ctx.log.warn(f"[AUDIT] UI->API MISMATCH: Selected {USER_SELECTED_MODEL} but API got {capture.model_requested}")

            thinking = body.get("thinking", {})
            original_budget = thinking.get("budget_tokens", 0) if thinking.get("type") == "enabled" else 0
            if thinking.get("type") == "enabled":
                capture.thinking_enabled = True
                capture.thinking_budget = thinking.get("budget_tokens", 0)

            # Force mode: Modify request if configured
            if FORCE_THINKING_MODE or FORCE_BUDGET_VALUE is not None:
                if "thinking" not in body:
                    body["thinking"] = {}
                if FORCE_THINKING_MODE:
                    body["thinking"]["type"] = "enabled"
                    capture.thinking_enabled = True
                    ctx.log.warn(f"[AUDIT] FORCE: Enabled thinking")
                if FORCE_BUDGET_VALUE is not None:
                    if FORCE_BUDGET_VALUE == 0:
                        body["thinking"] = {"type": "disabled"}
                        capture.thinking_enabled = False
                        capture.thinking_budget = 0
                    else:
                        body["thinking"]["type"] = "enabled"
                        max_tok = body.get("max_tokens", 128000)
                        safe_budget = min(FORCE_BUDGET_VALUE, max_tok - 1024) if max_tok > 1024 else FORCE_BUDGET_VALUE
                        if safe_budget < 1024:
                            safe_budget = FORCE_BUDGET_VALUE
                            body["max_tokens"] = FORCE_BUDGET_VALUE + 4096
                            _mt = body["max_tokens"]
                            ctx.log.warn(f"[AUDIT] FORCE: Bumped max_tokens to {_mt} (was {max_tok})")
                        body["thinking"]["budget_tokens"] = safe_budget
                        capture.thinking_enabled = True
                        capture.thinking_budget = safe_budget
                        _mt2 = body.get("max_tokens")
                        ctx.log.warn(f"[AUDIT] FORCE: Budget {original_budget} -> {safe_budget} (max_tokens={_mt2})")
                if FORCE_INTERLEAVED:
                    existing_beta = flow.request.headers.get("anthropic-beta", "")
                    beta_features = [b.strip() for b in existing_beta.split(",") if b.strip()] if existing_beta else []
                    if "interleaved-thinking-2025-05-14" not in beta_features:
                        beta_features.append("interleaved-thinking-2025-05-14")
                        flow.request.headers["anthropic-beta"] = ",".join(beta_features)
                    body["thinking"]["budget_tokens"] = 200000
                    capture.thinking_budget = 200000
                    ctx.log.warn(f"[AUDIT] INTERLEAVED: Budget boosted to 200k")
                flow.request.content = json.dumps(body).encode("utf-8")
                modified_request = True
    except Exception as e:
        ctx.log.warn(f"[AUDIT] Request parse error: {e}")

    if "opus" in capture.model_requested.lower() and not main_session_model:
        main_session_model = capture.model_requested
    streaming_captures[id(flow)] = capture
    tier = get_thinking_tier(capture.thinking_budget)
    tier_info = THINKING_TIERS[tier]
    tier_str = f" [{tier_info['emoji']}{tier_info['name']}:{capture.thinking_budget}]" if capture.thinking_enabled else ""
    force_str = " [FORCED]" if modified_request else ""
    ctx.log.info(f"[AUDIT] Request: {capture.model_requested}{tier_str}{force_str}")


_audit_responseheaders_guard: set = set()


def responseheaders(flow: http.HTTPFlow) -> None:
    _fid = id(flow)
    if _fid in _audit_responseheaders_guard:
        return
    _audit_responseheaders_guard.add(_fid)
    if len(_audit_responseheaders_guard) > 500:
        _audit_responseheaders_guard.clear()
    if "anthropic.com" not in flow.request.host: return
    if "/v1/messages" not in flow.request.path: return
    flow_id = id(flow)
    capture = streaming_captures.get(flow_id)
    if not capture: return
    content_type = flow.response.headers.get("content-type", "")
    if "text/event-stream" not in content_type: return
    capture.request_id = flow.response.headers.get("request-id", "")
    capture.envoy_time_ms = float(flow.response.headers.get("x-envoy-upstream-service-time", 0))
    capture.cf_ray = flow.response.headers.get("cf-ray", "")
    capture.cf_edge_location = capture.cf_ray.split("-")[-1] if capture.cf_ray else ""

    # Preserve existing stream callback (if ITT addon set one before us)
    existing_callback = flow.response.stream if callable(flow.response.stream) else None
    
    def stream_callback(chunk: bytes) -> bytes:
        nonlocal capture, existing_callback
        # Chain: call existing callback first (ITT addon needs chunks for timing)
        if existing_callback:
            chunk = existing_callback(chunk)
        
        now = time.time()
        if capture.first_chunk_time == 0 and chunk:
            capture.first_chunk_time = now
        if chunk:
            capture.last_chunk_time = now
            try:
                chunk_text = chunk.decode("utf-8", errors="ignore")
                capture.sse_buffer += chunk_text
                while "\n\n" in capture.sse_buffer:
                    event_end = capture.sse_buffer.index("\n\n")
                    event_block = capture.sse_buffer[:event_end]
                    capture.sse_buffer = capture.sse_buffer[event_end + 2:]
                    for line in event_block.split("\n"):
                        if line.startswith("data: "):
                            try:
                                event = json.loads(line[6:])
                                process_sse_event(capture, event, now)
                            except json.JSONDecodeError:
                                pass
            except Exception as e:
                ctx.log.debug(f"[AUDIT] Chunk parse error: {e}")
        return chunk
    flow.response.stream = stream_callback


_audit_response_guard: set = set()


def response(flow: http.HTTPFlow) -> None:
    _fid = id(flow)
    if _fid in _audit_response_guard:
        return
    _audit_response_guard.add(_fid)
    if len(_audit_response_guard) > 500:
        _audit_response_guard.clear()
    if "anthropic.com" not in flow.request.host: return
    if "/v1/messages" not in flow.request.path: return
    flow_id = id(flow)
    capture = streaming_captures.pop(flow_id, None)
    if not capture: return
    end_time = time.time()

    # Process remaining buffer
    if capture.sse_buffer:
        for line in capture.sse_buffer.split("\n"):
            if line.startswith("data: "):
                try:
                    event = json.loads(line[6:])
                    process_sse_event(capture, event, end_time)
                except json.JSONDecodeError:
                    pass

    if capture.first_chunk_time == 0:
        ctx.log.warn(f"[AUDIT] Skipping - no timing data")
        return
    if not capture.model_response:
        capture.model_response = capture.model_requested

    # Calculate metrics
    total_time_ms = (end_time - capture.start_time) * 1000
    ttft_ms = (capture.first_chunk_time - capture.start_time) * 1000 if capture.first_chunk_time > 0 else 0.0

    all_itts, thinking_itts, text_itts = [], [], []
    if len(capture.chunks) > 1:
        sorted_c = sorted(capture.chunks, key=lambda c: c.timestamp)
        for i in range(1, len(sorted_c)):
            itt = (sorted_c[i].timestamp - sorted_c[i-1].timestamp) * 1000
            if itt > 0: all_itts.append(itt)
    if len(capture.thinking_chunks) > 1:
        sorted_t = sorted(capture.thinking_chunks, key=lambda c: c.timestamp)
        for i in range(1, len(sorted_t)):
            itt = (sorted_t[i].timestamp - sorted_t[i-1].timestamp) * 1000
            if itt > 0: thinking_itts.append(itt)
    if len(capture.text_chunks) > 1:
        sorted_x = sorted(capture.text_chunks, key=lambda c: c.timestamp)
        for i in range(1, len(sorted_x)):
            itt = (sorted_x[i].timestamp - sorted_x[i-1].timestamp) * 1000
            if itt > 0: text_itts.append(itt)

    itt_stats = calculate_itt_stats(all_itts)
    thinking_itt_stats = calculate_itt_stats(thinking_itts)
    text_itt_stats = calculate_itt_stats(text_itts)

    thinking_duration_ms = 0.0
    if capture.thinking_chunks:
        sorted_t = sorted(capture.thinking_chunks, key=lambda c: c.timestamp)
        thinking_duration_ms = (sorted_t[-1].timestamp - sorted_t[0].timestamp) * 1000
    text_duration_ms = 0.0
    if capture.text_chunks:
        sorted_x = sorted(capture.text_chunks, key=lambda c: c.timestamp)
        text_duration_ms = (sorted_x[-1].timestamp - sorted_x[0].timestamp) * 1000

    gen_time = (capture.last_chunk_time - capture.first_chunk_time) if capture.first_chunk_time > 0 else 0
    tps = capture.output_tokens / gen_time if gen_time > 0 else 0.0

    backend, confidence, location = classify_backend(itt_stats, tps)
    spec_detected, spec_type = detect_speculative_decoding(all_itts)

    model_match = 1 if capture.model_requested.lower() == capture.model_response.lower() else 0
    is_subagent = 0
    subagent_type = None
    if main_session_model and capture.model_response.lower() != main_session_model.lower():
        is_subagent = 1
        if "haiku" in capture.model_response.lower(): subagent_type = "haiku"
        elif "sonnet" in capture.model_response.lower(): subagent_type = "sonnet"
        else: subagent_type = "other"

    cache_efficiency = min(100.0, (capture.cache_read / capture.input_tokens * 100)) if capture.input_tokens > 0 else 0.0

    thinking_utilization = 0.0
    thinking_tokens_used = 0
    if capture.thinking_enabled and capture.thinking_budget > 0:
        if capture.output_tokens > 0:
            thinking_tokens_used = capture.output_tokens
            thinking_utilization = (thinking_tokens_used / capture.thinking_budget) * 100

    # === SYCOPHANCY ANALYSIS ===
    syco_result = None
    syco_score = 0.0
    syco_signals = []
    syco_dimensional = {}
    syco_face_metrics = {}
    syco_divergence = 0.0
    
    if SYCO_AVAILABLE and (capture.thinking_text or capture.output_text):
        try:
            analyzer = SycophancyAnalyzer()
            if capture.thinking_text:
                analyzer.accumulate_thinking(capture.thinking_text)
            if capture.output_text:
                analyzer.accumulate_output(capture.output_text)
            if capture.user_message:
                analyzer.set_user_message(capture.user_message)
            
            # Get verification_ratio from behavioral fingerprint
            try:
                from lib.fingerprint_db import FingerprintDatabase
                fp_db = FingerprintDatabase()
                behavior = fp_db.get_behavioral_signature()
                ver_ratio = behavior.get("verification_ratio", 0.0)
                analyzer.set_verification_ratio(ver_ratio)
            except Exception:
                pass  # Continue without verification_ratio if unavailable
            
            syco_result = analyzer.analyze()
            syco_score = syco_result.score
            syco_signals = [s.to_dict() for s in syco_result.signals]
            if syco_result.dimensional_scores:
                syco_dimensional = syco_result.dimensional_scores.to_dict()
            if syco_result.face_metrics:
                syco_face_metrics = syco_result.face_metrics.to_dict()
            syco_divergence = syco_result.divergence_score
            
            # Log sycophancy detection
            if syco_score >= 0.4:
                ctx.log.warn(f"[SYCO] Score: {syco_score:.2f} | Signals: {[s['signal'] for s in syco_signals[:3]]}")
        except Exception as e:
            ctx.log.warn(f"[SYCO] Analysis error: {e}")

    # Use instance-specific session_id so multi-CC metrics are separated
    effective_session = _get_session_for_instance(capture.instance_id) if capture.instance_id else session_id

    # Read real rate limit values stashed by mitm_itt_addon (before header spoofing)
    _rl = getattr(flow, '_rl_real', {})

    sample = {
        "timestamp": datetime.now().isoformat(),
        "session_id": effective_session,
        "instance_id": capture.instance_id or "unknown",
        "model_requested": capture.model_requested,
        "model_response": capture.model_response,
        "model_match": model_match,
        "model_ui_selected": capture.model_ui_selected,
        "ui_api_mismatch": 1 if capture.ui_api_mismatch else 0,
        "is_subagent": is_subagent,
        "subagent_type": subagent_type,
        "thinking_enabled": 1 if (capture.thinking_enabled or capture.has_thinking) else 0,
        "thinking_budget_requested": capture.thinking_budget,
        "thinking_budget_tier": get_thinking_tier(capture.thinking_budget) if capture.thinking_enabled else "none",
        "thinking_chunk_count": len(capture.thinking_chunks),
        "thinking_tokens_used": thinking_tokens_used,
        "thinking_utilization": round(thinking_utilization, 1),
        "thinking_duration_ms": round(thinking_duration_ms, 1),
        "thinking_itt_mean_ms": thinking_itt_stats["mean"],
        "thinking_itt_std_ms": thinking_itt_stats["std"],
        "text_chunk_count": len(capture.text_chunks),
        "text_duration_ms": round(text_duration_ms, 1),
        "text_itt_mean_ms": text_itt_stats["mean"],
        "text_itt_std_ms": text_itt_stats["std"],
        "input_tokens": capture.input_tokens,
        "output_tokens": capture.output_tokens,
        "cache_creation_tokens": capture.cache_creation,
        "cache_read_tokens": capture.cache_read,
        "cache_efficiency": round(cache_efficiency, 1),
        "ttft_ms": round(ttft_ms, 1),
        "total_time_ms": round(total_time_ms, 1),
        "itt_mean_ms": itt_stats["mean"],
        "itt_std_ms": itt_stats["std"],
        "itt_min_ms": itt_stats["min"],
        "itt_max_ms": itt_stats["max"],
        "itt_p50_ms": itt_stats["p50"],
        "itt_p90_ms": itt_stats["p90"],
        "itt_p99_ms": itt_stats["p99"],
        "variance_coef": itt_stats["variance_coef"],
        "tokens_per_sec": round(tps, 1),
        "num_chunks": len(capture.chunks),
        "classified_backend": backend,
        "confidence": confidence,
        "location": location,
        "request_id": capture.request_id,
        "stop_reason": capture.stop_reason,
        "envoy_time_ms": capture.envoy_time_ms,
        "cf_ray": capture.cf_ray,
        "cf_edge_location": capture.cf_edge_location,
        "speculative_decoding": 1 if spec_detected else 0,
        "speculative_type": spec_type,
        # Sycophancy analysis fields
        "sycophancy_score": round(syco_score, 3),
        "sycophancy_signals": json.dumps(syco_signals) if syco_signals else None,
        "sycophancy_dimensional": json.dumps(syco_dimensional) if syco_dimensional else None,
        "sycophancy_face_metrics": json.dumps(syco_face_metrics) if syco_face_metrics else None,
        "sycophancy_divergence": round(syco_divergence, 3),
        "thinking_text": capture.thinking_text if capture.thinking_text else None,  # Phase 1: full, no truncation
        "output_text": capture.output_text if capture.output_text else None,  # Phase 1: full, no truncation
        "user_message": capture.user_message if capture.user_message else None,  # Phase 1: full, no truncation
        # Phase 1: Session context store fields
        "conversation_id": capture.conversation_id or None,
        "turn_index": capture.turn_index,
        "num_messages": capture.num_messages,
        # Rate limit headers (read from flow._rl_real stashed by mitm_itt_addon before spoofing)
        "rl_5h_utilization": round(_rl.get('h5', 0.0), 6),
        "rl_5h_reset": _rl.get('h5_reset', 0),
        "rl_5h_status": _rl.get('h5_status', ''),
        "rl_7d_utilization": round(_rl.get('d7', 0.0), 6),
        "rl_7d_reset": _rl.get('d7_reset', 0),
        "rl_7d_status": _rl.get('d7_status', ''),
        "rl_overall_status": _rl.get('overall_status', ''),
        "rl_binding_window": _rl.get('binding', ''),
        "rl_fallback_pct": round(_rl.get('fallback_pct', 0.0), 6),
        "rl_overage_status": _rl.get('overage_status', ''),
    }

    state_icon = "DIRECT" if model_match else ("SUB" if is_subagent else "ROUTED")
    tier = sample["thinking_budget_tier"]
    tier_info = THINKING_TIERS[tier]
    think_str = f" {tier_info['emoji']}{tier_info['name']}" if sample["thinking_enabled"] else ""
    itt_str = f"ITT:{itt_stats['mean']:.0f}ms"
    backend_str = f"{backend[:3].upper()} {confidence:.0f}%"
    ctx.log.info(f"[AUDIT] {state_icon} {capture.model_response}{think_str} | {backend_str} | {itt_str} | {tps:.0f}t/s | cache:{cache_efficiency:.0f}%")

    # Save to database
    save_to_db(sample)


def save_to_db(sample: dict) -> None:
    """Save sample to SQLite database."""
    import sqlite3
    from pathlib import Path
    db_path = Path(DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, session_id TEXT,
            model_requested TEXT, model_response TEXT, model_match INTEGER,
            model_ui_selected TEXT, ui_api_mismatch INTEGER,
            is_subagent INTEGER, subagent_type TEXT,
            thinking_enabled INTEGER, thinking_budget_requested INTEGER,
            thinking_budget_tier TEXT, thinking_chunk_count INTEGER,
            thinking_tokens_used INTEGER, thinking_utilization REAL,
            thinking_duration_ms REAL, thinking_itt_mean_ms REAL, thinking_itt_std_ms REAL,
            text_chunk_count INTEGER, text_duration_ms REAL,
            text_itt_mean_ms REAL, text_itt_std_ms REAL,
            input_tokens INTEGER, output_tokens INTEGER,
            cache_creation_tokens INTEGER, cache_read_tokens INTEGER, cache_efficiency REAL,
            ttft_ms REAL, total_time_ms REAL,
            itt_mean_ms REAL, itt_std_ms REAL, itt_min_ms REAL, itt_max_ms REAL,
            itt_p50_ms REAL, itt_p90_ms REAL, itt_p99_ms REAL,
            variance_coef REAL, tokens_per_sec REAL, num_chunks INTEGER,
            classified_backend TEXT, confidence REAL, location TEXT,
            request_id TEXT, stop_reason TEXT, envoy_time_ms REAL,
            cf_ray TEXT, cf_edge_location TEXT,
            speculative_decoding INTEGER, speculative_type TEXT,
            sycophancy_score REAL, sycophancy_signals TEXT,
            sycophancy_dimensional TEXT, sycophancy_face_metrics TEXT,
            sycophancy_divergence REAL,
            thinking_text TEXT, output_text TEXT, user_message TEXT,
            conversation_id TEXT, turn_index INTEGER, num_messages INTEGER
        )
    """)
    
    # Add columns if they dont exist (migration for existing DBs)
    new_columns = [
        ("sycophancy_score", "REAL"),
        ("sycophancy_signals", "TEXT"),
        ("sycophancy_dimensional", "TEXT"),
        ("sycophancy_face_metrics", "TEXT"),
        ("sycophancy_divergence", "REAL"),
        ("thinking_text", "TEXT"),
        ("output_text", "TEXT"),
        ("user_message", "TEXT"),
        ("instance_id", "TEXT"),
        ("rl_5h_utilization", "REAL"),
        ("rl_5h_reset", "INTEGER"),
        ("rl_5h_status", "TEXT"),
        ("rl_7d_utilization", "REAL"),
        ("rl_7d_reset", "INTEGER"),
        ("rl_7d_status", "TEXT"),
        ("rl_overall_status", "TEXT"),
        ("rl_binding_window", "TEXT"),
        ("rl_fallback_pct", "REAL"),
        ("rl_overage_status", "TEXT"),
        # Phase 1: Session context store columns
        ("conversation_id", "TEXT"),
        ("turn_index", "INTEGER"),
        ("num_messages", "INTEGER"),
    ]
    for col_name, col_type in new_columns:
        try:
            conn.execute(f"ALTER TABLE audit_samples ADD COLUMN {col_name} {col_type}")
        except sqlite3.OperationalError:
            pass  # Column already exists
    
    cols = list(sample.keys())
    placeholders = ",".join(["?" for _ in cols])
    col_names = ",".join(cols)
    values = [sample[c] for c in cols]
    conn.execute(f"INSERT INTO audit_samples ({col_names}) VALUES ({placeholders})", values)

    # Phase 2: Write to session_turns table (full conversation archive)
    _save_session_turn(conn, sample)

    conn.commit()
    conn.close()
    ctx.log.info(f"[AUDIT] Saved to {DB_PATH}")


def _save_session_turn(conn, sample: dict) -> None:
    """Phase 2: Write full turn data to session_turns for context reconstruction."""
    conv_id = sample.get("conversation_id")
    if not conv_id:
        return  # Cannot index without conversation_id

    sid = sample.get("session_id", "")
    turn_idx = sample.get("turn_index", 0)
    is_sub = sample.get("is_subagent", 0)

    # Create table if needed (idempotent)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS session_turns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            turn_index INTEGER NOT NULL,
            thinking_text TEXT,
            thinking_tokens INTEGER,
            output_text TEXT,
            output_tokens INTEGER,
            stop_reason TEXT,
            timestamp TEXT NOT NULL,
            cache_creation_tokens INTEGER,
            cache_read_tokens INTEGER,
            is_subagent INTEGER DEFAULT 0,
            model TEXT,
            thinking_summary TEXT,
            output_summary TEXT,
            compression_ratio REAL,
            num_messages INTEGER,
            UNIQUE(session_id, conversation_id, turn_index)
        )
    """)

    # UPSERT: if same session+conv+turn already exists, update it
    # (can happen on retries where CC sends same turn again)
    conn.execute("""
        INSERT INTO session_turns (
            session_id, conversation_id, turn_index,
            thinking_text, thinking_tokens,
            output_text, output_tokens,
            stop_reason, timestamp,
            cache_creation_tokens, cache_read_tokens,
            is_subagent, model, num_messages
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_id, conversation_id, turn_index)
        DO UPDATE SET
            thinking_text = COALESCE(excluded.thinking_text, thinking_text),
            thinking_tokens = excluded.thinking_tokens,
            output_text = COALESCE(excluded.output_text, output_text),
            output_tokens = excluded.output_tokens,
            stop_reason = excluded.stop_reason,
            timestamp = excluded.timestamp,
            cache_creation_tokens = excluded.cache_creation_tokens,
            cache_read_tokens = excluded.cache_read_tokens
    """, (
        sid, conv_id, turn_idx,
        sample.get("thinking_text"),
        sample.get("thinking_tokens_used", 0),
        sample.get("output_text"),
        sample.get("output_tokens", 0),
        sample.get("stop_reason", ""),
        sample.get("timestamp", ""),
        sample.get("cache_creation_tokens", 0),
        sample.get("cache_read_tokens", 0),
        is_sub,
        sample.get("model_response", ""),
        sample.get("num_messages", 0),
    ))


class ThinkingAudit:
    """Mitmproxy addon class."""
    def request(self, flow: http.HTTPFlow) -> None: request(flow)
    def responseheaders(self, flow: http.HTTPFlow) -> None: responseheaders(flow)
    def response(self, flow: http.HTTPFlow) -> None: response(flow)


addons = [ThinkingAudit()]
