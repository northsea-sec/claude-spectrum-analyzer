"""
config_server.py — Web UI for mitmproxy context trimmer configuration

Dark cybersec-themed dashboard with per-MCP-server toggles.
Access: http://localhost:18889
"""

import json
import os
import re
import sqlite3
import threading
import time
import importlib.util
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

CONFIG_PATH = os.path.expanduser("~/.claude/trimmer_config.json")
DB_PATH = os.path.expanduser("~/.claude/fingerprint.db")
STATS_PATH = os.path.expanduser("~/.claude/trimmer_stats.json")
CONTEXT_CACHE_PATH = os.path.expanduser("~/.claude/context_cache.json")
PATCHES_PATH = os.path.expanduser("~/.claude/context_patches.json")
CONTEXT_HISTORY_DIR = os.path.expanduser("~/.claude/context_history")
CAPTURED_MAIN_PROMPT_PATH = os.path.expanduser("~/.claude/captured_main_prompt.json")
CAPTURED_SUBAGENT_PROMPTS_PATH = os.path.expanduser("~/.claude/captured_subagent_prompts.json")
SYSPROMPT_PATCHES_PATH = os.path.expanduser("~/.claude/sysprompt_patches.json")
SUBAGENT_PATCHES_PATH = os.path.expanduser("~/.claude/subagent_patches.json")
FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))
MEMENTO_CONFIG_PATH = os.path.expanduser('~/.claude/memento_config.json')
AUDIT_DB_PATH = os.path.expanduser('~/.claude-audit/thinking_audit.db')
SLAVE_WHISPER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'slave_whisper')

STATUSLINE_PATH = os.path.expanduser("~/.claude/statusline.py")
_STATUSLINE_MOD = None
_STATUSLINE_LOCK = threading.Lock()
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s or "")

def _load_statusline_module():
    global _STATUSLINE_MOD
    if not os.path.exists(STATUSLINE_PATH):
        return None
    with _STATUSLINE_LOCK:
        if _STATUSLINE_MOD is None:
            spec = importlib.util.spec_from_file_location("statusline_live", STATUSLINE_PATH)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _STATUSLINE_MOD = mod
    return _STATUSLINE_MOD

DEFAULT_CONFIG = {
    "enabled": True,
    "strip_mcp_tools": True,
    "mcp_disabled": [],
    "trim_messages": True,
    "trim_threshold_tokens": 140000,
    "trim_keep_recent": 20,
    "trim_max_tool_result_chars": 700,
    "trim_max_assistant_chars": 500,
    "strip_old_thinking": True,
    "block_haiku": True,
    "block_sonnet": False,
    "force_thinking": True,
    "thinking_budget": 31999,
    "force_interleaved": False,
    "statusline_enabled": True,
}

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Proxy Config</title>
<style>
  :root { --bg: #000000; --card: #080808; --border: #181818; --text: #ebebeb;
          --muted: #808080; --accent: #dc2626; --green: #4ade80; --red: #ef4444;
          --orange: #f59e0b; --purple: #c084fc; --cyan: #67e8f9; --yellow: #fbbf24;
          --glow: rgba(220,38,38,0.08); }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Lato', 'Helvetica Neue', Arial, sans-serif;
         font-weight: 300;
         background: var(--bg); color: var(--text); padding: 24px 48px; max-width: 100%; margin: 0;
         font-size: 16px; line-height: 1.7; }
  ::selection { background: var(--accent); color: var(--bg); }
  input, button, select, textarea, code, pre, .mon-table, .sp-frag-preview,
  .sl-output, .mcp-method { font-style: normal; font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace; }
  h1, h2, h3, .logo, .tab, .card-head { font-weight: 400; letter-spacing: 2px; }

  /* ═══ HEADER ═══ */
  .header { text-align: center; margin-bottom: 20px; padding: 16px 0; border-bottom: 1px solid var(--border); }
  .header .logo { font-size: 1.8em; letter-spacing: 6px; color: var(--accent); font-weight: 300; text-transform: uppercase; }
  .header .sub { color: var(--muted); font-size: 0.85em; margin-top: 6px; letter-spacing: 2px; }

  /* ═══ STATS GRID ═══ */
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 20px; }
  .stat { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 14px; text-align: center; }
  .stat .num { font-size: 1.8em; font-weight: bold; color: var(--green); font-variant-numeric: tabular-nums; }
  .stat .lbl { font-size: 0.75em; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }
  .stat .ico { font-size: 1.2em; display: block; margin-bottom: 2px; }
  .stat.warn .num { color: var(--orange); }
  .stat.crit .num { color: var(--red); }

  /* ═══ CARDS ═══ */
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 4px;
          margin-bottom: 20px; overflow: hidden; }
  .card-head { padding: 14px 18px; border-bottom: 1px solid var(--border); display: flex;
               align-items: center; gap: 10px; font-size: 1.05em; color: var(--accent); font-weight: 400; letter-spacing: 1px; }
  .card-head .icon { font-size: 1.3em; }
  .card-body { padding: 16px 18px; }

  /* ═══ ROWS ═══ */
  .row { display: flex; align-items: center; justify-content: space-between;
         padding: 10px 0; border-bottom: 1px solid var(--border); }
  .row:last-child { border-bottom: none; }
  .row label { flex: 1; }
  .row .desc { color: var(--muted); font-size: 0.75em; display: block; }

  /* ═══ MCP TOOL GRID ═══ */
  .mcp-grid { display: grid; grid-template-columns: 1fr; gap: 0; }
  .mcp-server { border-bottom: 1px solid var(--border); }
  .mcp-server:last-child { border-bottom: none; }
  .mcp-header { display: flex; align-items: center; justify-content: space-between;
                padding: 10px 0; cursor: pointer; }
  .mcp-header:hover { color: var(--accent); }
  .mcp-name { font-weight: bold; display: flex; align-items: center; gap: 6px; }
  .mcp-name .srv-icon { color: var(--purple); }
  .mcp-badge { font-size: 0.7em; background: var(--border); color: var(--muted);
               padding: 2px 6px; border-radius: 3px; margin-left: 6px; }
  .mcp-badge.on { background: rgba(127,217,98,0.15); color: var(--green); }
  .mcp-badge.off { background: rgba(255,51,51,0.15); color: var(--red); }
  .mcp-methods { padding: 0 0 8px 24px; display: none; }
  .mcp-methods.open { display: block; }
  .mcp-method { font-size: 0.8em; color: var(--muted); padding: 2px 0; }
  .mcp-method::before { content: "|--> "; color: var(--border); }
  .no-tools { color: var(--muted); font-style: italic; padding: 12px 0; text-align: center; }

  /* ═══ TOGGLE ═══ */
  .toggle { position: relative; width: 44px; height: 24px; flex-shrink: 0; }
  .toggle input { position: absolute; inset: 0; opacity: 0; margin: 0; width: 100%; height: 100%;
                  cursor: pointer; z-index: 2; }
  .toggle .sl { position: absolute; inset: 0; background: var(--border); border-radius: 10px;
                cursor: pointer; transition: 0.2s; z-index: 1; }
  .toggle .sl::before { content: ""; position: absolute; width: 18px; height: 18px;
                        left: 3px; bottom: 3px; background: var(--muted); border-radius: 50%;
                        transition: 0.2s; }
  .toggle input:checked + .sl { background: var(--green); }
  .toggle input:checked + .sl::before { transform: translateX(20px); background: var(--bg); }

  /* ═══ INPUTS ═══ */
  input[type=number] { width: 80px; background: var(--bg); border: 1px solid var(--border);
                       color: var(--text); padding: 4px 8px; border-radius: 3px; font-family: inherit;
                       font-size: 0.85em; }
  input[type=range] { width: 120px; accent-color: var(--accent); }
  .val { color: var(--accent); font-family: inherit; min-width: 40px; text-align: right; margin-left: 8px; font-size: 0.85em; }

  /* ═══ SAVE BAR ═══ */
  .save-bar { position: sticky; bottom: 0; background: #0a0a0a; border-top: 2px solid var(--accent);
              padding: 12px 10px; text-align: center; border-radius: 0 0 6px 6px; z-index: 100;
              box-shadow: 0 -8px 24px rgba(0,0,0,0.95); }
  .btn { background: var(--accent); color: #000; border: none; padding: 10px 28px;
         border-radius: 3px; cursor: pointer; font-weight: 600; font-size: 0.9em; font-family: inherit;
         letter-spacing: 2px; text-transform: uppercase; font-style: normal; }
  .btn:hover { filter: brightness(1.15); }
  .btn-dim { background: var(--border); color: var(--text); margin-left: 8px; }
  .status { display: inline-block; margin-left: 12px; font-size: 0.8em; }
  .status.ok { color: var(--green); }
  .status.err { color: var(--red); }

  /* ═══ DIVIDER ═══ */
  .divider { text-align: center; color: var(--border); font-size: 0.7em; padding: 4px 0; letter-spacing: 2px; }

  /* ═══ TABS ═══ */
  .tabs { display: flex; gap: 0; margin-bottom: 24px; border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .tab { padding: 12px 28px; cursor: pointer; color: var(--muted); font-size: 0.95em; letter-spacing: 2px;
         border-bottom: 2px solid transparent; margin-bottom: -2px; transition: 0.2s; }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; position: relative; z-index: 0; }
  /* sysprompt/subagent inherit global black theme */
  .sp-fragment { margin-bottom: 12px; border: 1px solid #222; border-radius: 4px; background: #050505; }
  .sp-frag-header { padding: 8px 12px; display: flex; justify-content: space-between; align-items: center;
                     color: #888; font-size: 0.85em; border-bottom: 1px solid #1a1a1a; cursor: pointer; }
  .sp-frag-header:hover { background: #111; }
  .sp-frag-preview { padding: 8px 12px; color: #666; font-size: 0.8em; white-space: pre-wrap;
                      max-height: 80px; overflow: hidden; font-family: monospace; }
  .sp-frag-edit { padding: 12px; display: none; }
  .sp-frag-edit textarea { width: 100%; min-height: 200px; background: #080808; border: 1px solid #333;
                            color: #ddd; font-family: monospace; font-size: 0.85em; padding: 8px;
                            resize: vertical; white-space: pre-wrap; }
  .sp-counter { font-size: 0.85em; margin-top: 4px; }
  .sp-counter.ok { color: var(--green); }
  .sp-counter.over { color: var(--red); }
  .sp-patched { border-left: 3px solid var(--orange); }
  .sp-badge { background: var(--orange); color: #000; padding: 1px 6px; border-radius: 3px;
              font-size: 0.75em; font-weight: bold; margin-left: 8px; }
  .sp-actions { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
  .sp-type-select { background: #111; border: 1px solid #333; color: #ccc; padding: 4px 8px;
                     border-radius: 3px; font-family: inherit; }
  .mm-tpl { width: 100%; background: #080808; border: 1px solid #222; color: #ddd;
            font-family: 'SF Mono', 'Consolas', monospace; font-size: 0.82em; padding: 8px;
            resize: vertical; white-space: pre-wrap; margin-top: 4px; }
  .mm-preset-active { background: var(--accent) !important; color: #000 !important; }

  /* ═══ SELECT ═══ */
  select { background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 4px 8px;
           border-radius: 3px; font-family: inherit; font-size: 0.85em; }

  /* ═══ MONITOR TABLE ═══ */
  .mon-table { width: 100%; border-collapse: collapse; font-size: 0.78em; }
  .mon-table th { text-align: left; color: var(--accent); font-weight: normal; padding: 6px 8px;
                  border-bottom: 1px solid var(--border); letter-spacing: 1px; text-transform: uppercase; font-size: 0.85em; }
  .mon-table td { padding: 5px 8px; border-bottom: 1px solid rgba(26,31,46,0.5); white-space: nowrap; }
  .mon-table tr:hover td { background: rgba(57,186,230,0.04); }
  .mon-backend { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 0.85em; letter-spacing: 0.5px; }
  .mon-backend.trainium { background: rgba(127,217,98,0.15); color: var(--green); }
  .mon-backend.tpu { background: rgba(210,166,255,0.15); color: var(--purple); }
  .mon-backend.gpu { background: rgba(255,143,64,0.15); color: var(--orange); }
  .mon-backend.unknown { background: rgba(92,103,115,0.15); color: var(--muted); }
  .mon-rl { display: inline-block; min-width: 36px; text-align: right; }
  .mon-rl.green { color: var(--green); }
  .mon-rl.yellow { color: var(--yellow); }
  .mon-rl.red { color: var(--red); }
  .mon-bar { display: inline-block; width: 50px; height: 8px; background: var(--border); border-radius: 2px; overflow: hidden; vertical-align: middle; margin-left: 4px; }
  .mon-bar-fill { height: 100%; border-radius: 2px; }
  .mon-age { color: var(--muted); font-size: 0.9em; }
  .mon-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  .mon-header .btn { font-size: 0.8em; padding: 4px 12px; }
  .mon-count { color: var(--muted); font-size: 0.8em; }
  .mon-auto { color: var(--muted); font-size: 0.75em; margin-left: 12px; }
  .mon-auto.active { color: var(--green); }

  /* ═══ STATUSLINE TAB ═══ */
  .sl-output { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px;
               white-space: pre-wrap; font-size: 0.85em; line-height: 1.4; }
  .sl-metrics th { text-transform: uppercase; font-size: 0.75em; letter-spacing: 1px; }

  /* ═══ ENFORCEMENT BADGE ═══ */
  .enforce-status { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.75em;
                    letter-spacing: 1px; margin-left: 8px; }
  .enforce-status.on { background: rgba(255,51,51,0.15); color: var(--red); }
  .enforce-status.off { background: rgba(127,217,98,0.15); color: var(--green); }
</style>
</head>
<body>

<div class="header">
  <div class="logo">PROXY CONFIG</div>
  <div class="sub">context trimmer &middot; mcp control &middot; model enforcement</div>
  
</div>

<div class="tabs">
  <div class="tab active" onclick="switchTab('trimmer')">TRIMMER</div>
  <div class="tab" onclick="switchTab('enforce')">ENFORCEMENT</div>
  <div class="tab" onclick="switchTab('statusline')">STATUSLINE</div>
  <div class="tab" onclick="switchTab('context')">CONTEXT</div>
  <div class="tab" onclick="switchTab('monitor')">MONITOR</div>
  <div class="tab" onclick="switchTab('sysprompt')">SYS PROMPT</div>
  <div class="tab" onclick="switchTab('subagent')">SUBAGENT</div>
  <div class="tab" onclick="switchTab('memento')">MEMENTO MORI</div>
</div>

<div id="tab-trimmer" class="tab-panel active">

<div class="stats" id="stats">
  <div class="stat"><div class="num" id="s-calls">-</div><div class="lbl">API Calls</div></div>
  <div class="stat"><div class="num" id="s-tools">-</div><div class="lbl">Tools Stripped</div></div>
  <div class="stat"><div class="num" id="s-tok-tools">-</div><div class="lbl">Tok Saved (MCP)</div></div>
  <div class="stat"><div class="num" id="s-trims">-</div><div class="lbl">Msg Trims</div></div>
  <div class="stat"><div class="num" id="s-tok-msgs">-</div><div class="lbl">Tok Saved (Msg)</div></div>
  <div class="stat" id="s-est-wrap"><div class="num" id="s-est">-</div><div class="lbl">Last Input Est</div></div>
</div>

<div class="card">
  <div class="card-head">Master Controls</div>
  <div class="card-body">
    <div class="row">
      <label>Context Trimmer <span class="desc">master on/off for all trimming</span></label>
      <div class="toggle"><input type="checkbox" id="enabled"><span class="sl"></span></div>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-head">MCP Server Control</div>
  <div class="card-body">
    <div class="row">
      <label>Strip MCP Tools <span class="desc">remove disabled MCP server schemas from requests</span></label>
      <div class="toggle"><input type="checkbox" id="strip_mcp_tools"><span class="sl"></span></div>
    </div>
    <div class="divider">discovered servers</div>
    <div class="mcp-grid" id="mcp-grid">
      <div class="no-tools" id="no-tools">waiting for first API call to discover tools...</div>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-head">Message Compression</div>
  <div class="card-body">
    <div class="row">
      <label>Trim Old Messages <span class="desc">compress old turns when threshold exceeded</span></label>
      <div class="toggle"><input type="checkbox" id="trim_messages"><span class="sl"></span></div>
    </div>
    <div class="row">
      <label>Threshold <span class="desc">start trimming above this token estimate</span></label>
      <input type="number" id="trim_threshold_tokens" min="50000" max="195000" step="5000">
      <span class="val" id="v-threshold"></span>
    </div>
    <div class="row">
      <label>Keep Recent <span class="desc">never touch the last N messages</span></label>
      <input type="range" id="trim_keep_recent" min="6" max="60" step="2">
      <span class="val" id="v-recent"></span>
    </div>
    <div class="row">
      <label>Max Tool Result <span class="desc">truncate old tool results (chars)</span></label>
      <input type="number" id="trim_max_tool_result_chars" min="100" max="5000" step="100">
    </div>
    <div class="row">
      <label>Max Assistant Text <span class="desc">truncate old assistant text (chars)</span></label>
      <input type="number" id="trim_max_assistant_chars" min="100" max="5000" step="100">
    </div>
    <div class="row">
      <label>Strip Old Thinking <span class="desc">remove thinking blocks from old messages</span></label>
      <div class="toggle"><input type="checkbox" id="strip_old_thinking"><span class="sl"></span></div>
    </div>
  </div>
</div>

</div><!-- /tab-trimmer -->

<div id="tab-enforce" class="tab-panel">

<div class="card">
  <div class="card-head">Model Blocking</div>
  <div class="card-body">
    <div class="row">
      <label>Block Haiku <span class="desc">reject all Haiku subagent requests (403)</span></label>
      <div class="toggle"><input type="checkbox" id="block_haiku"><span class="sl"></span></div>
    </div>
    <div class="row">
      <label>Block Sonnet <span class="desc">reject all Sonnet subagent requests (403)</span></label>
      <div class="toggle"><input type="checkbox" id="block_sonnet"><span class="sl"></span></div>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-head">Thinking Control</div>
  <div class="card-body">
    <div class="row">
      <label>Force Thinking <span class="desc">inject thinking.type=enabled on all requests</span></label>
      <div class="toggle"><input type="checkbox" id="force_thinking"><span class="sl"></span></div>
    </div>
    <div class="row">
      <label>Thinking Budget <span class="desc">override budget_tokens on every request</span></label>
      <select id="thinking_budget" onchange="updateBudgetLabel()">
        <option value="0">Disabled (0)</option>
        <option value="10000">Basic (10k)</option>
        <option value="16000">Enhanced (16k)</option>
        <option value="31999">Ultra (32k)</option>
        <option value="200000">Interleaved (200k)</option>
      </select>
      <span class="val" id="v-budget"></span>
    </div>
    <div class="row">
      <label>Force Interleaved <span class="desc">inject interleaved-thinking beta header + 200k budget</span></label>
      <div class="toggle"><input type="checkbox" id="force_interleaved"><span class="sl"></span></div>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-head">Statusline</div>
  <div class="card-body">
    <div class="row">
      <label>Statusline Enabled <span class="desc">show integrated statusline in Claude Code output</span></label>
      <div class="toggle"><input type="checkbox" id="statusline_enabled"><span class="sl"></span></div>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-head">Current Status</div>
  <div class="card-body" id="enforce-live" style="font-size:0.85em;color:var(--muted);">
    Loading...
  </div>
</div>

</div><!-- /tab-enforce -->

<div id="tab-statusline" class="tab-panel">

<div class="card">
  <div class="card-head">
    Statusline Snapshot
    <span class="mon-auto" id="sl-auto-status">auto-refresh: off</span>
  </div>
  <div class="card-body">
    <div class="mon-header">
      <div>
        <button class="btn" onclick="loadStatusline()">Refresh</button>
        <button class="btn btn-dim" id="sl-auto-btn" onclick="toggleStatuslineAuto()">Auto</button>
        <span class="mon-count" id="sl-updated"></span>
      </div>
    </div>
    <pre class="sl-output" id="sl-output">Click Refresh or switch to this tab to load data</pre>
  </div>
</div>

<div class="card">
  <div class="card-head">Metrics Explained</div>
  <div class="card-body">
    <div style="overflow-x:auto;">
      <table class="mon-table sl-metrics">
        <thead>
          <tr>
            <th>Metric</th>
            <th>Value</th>
            <th>Explanation</th>
          </tr>
        </thead>
        <tbody id="sl-metrics-body">
          <tr><td colspan="3" style="color:var(--muted);text-align:center;padding:20px;">No data yet</td></tr>
        </tbody>
      </table>
    </div>
    <details style="margin-top:10px;">
      <summary style="cursor:pointer;color:var(--muted);">Raw JSON</summary>
      <pre class="sl-output" id="sl-raw"></pre>
    </details>
  </div>
</div>

<div class="card">
  <div class="card-head">All Metrics (Raw Fields)</div>
  <div class="card-body">
    <div class="mon-count" id="sl-all-count"></div>
    <div style="overflow-x:auto;">
      <table class="mon-table sl-metrics">
        <thead>
          <tr>
            <th>Key</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody id="sl-all-body">
          <tr><td colspan="2" style="color:var(--muted);text-align:center;padding:20px;">No data yet</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

</div><!-- /tab-statusline -->

<div id="tab-context" class="tab-panel">

<div class="card">
  <div class="card-head">
    Editable Context
    <span class="mon-auto" id="ctx-auto-status">auto-refresh: off</span>
  </div>
  <div class="card-body">
    <div class="mon-header">
      <div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;">
        <button class="btn" onclick="loadContextSessions()">Refresh</button>
        <button class="btn btn-dim" onclick="clearPatches()">Clear Patches</button>
        <select id="ctx-session-select" onchange="onSessionSelect()" style="background:var(--bg);color:var(--fg);border:1px solid var(--border);padding:4px 8px;font-family:inherit;font-size:0.85em;">
          <option value="">-- Select Session --</option>
        </select>
        <label style="font-size:0.75em;color:var(--muted);"><input type="checkbox" id="ctx-show-system" checked onchange="renderSessionParts()"> System</label>
        <label style="font-size:0.75em;color:var(--muted);"><input type="checkbox" id="ctx-show-tools" onchange="renderSessionParts()"> Tools</label>
        <label style="font-size:0.75em;color:var(--muted);"><input type="checkbox" id="ctx-show-thinking" onchange="renderSessionParts()"> Thinking</label>
      </div>
      <div>
        <span class="mon-count" id="ctx-count"></span>
        <span class="mon-count" id="ctx-patches" style="margin-left:12px;color:var(--orange)"></span>
      </div>
    </div>
    <div id="ctx-messages" style="margin-top:12px;">
      <div style="color:var(--muted);text-align:center;padding:20px;">Click Refresh or switch to this tab to load context</div>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-head">How Patches Work</div>
  <div class="card-body" style="font-size:0.85em;color:var(--muted);">
    <p>Click <strong>[Edit]</strong> on any message to modify its content</p>
    <p>Edits are saved as "patches" - the proxy applies them on every API request</p>
    <p>Claude will see your edited version, not the original</p>
    <p>Terminal still shows original text (split-brain)</p>
    <p>Patches persist until cleared or hash changes</p>
  </div>
</div>

</div><!-- /tab-context -->

<div id="tab-monitor" class="tab-panel">

<div class="card">
  <div class="card-head">
    Live Request Monitor
    <span class="mon-auto" id="mon-auto-status">auto-refresh: off</span>
  </div>
  <div class="card-body">
    <div class="mon-header">
      <div>
        <button class="btn" onclick="loadMonitor()">Refresh</button>
        <button class="btn btn-dim" id="mon-auto-btn" onclick="toggleAutoRefresh()">Auto</button>
        <span class="mon-count" id="mon-count"></span>
      </div>
    </div>
    <div style="overflow-x:auto;">
      <table class="mon-table">
        <thead>
          <tr>
            <th>Age</th>
            <th>Model</th>
            <th>Backend</th>
            <th>ITT</th>
            <th>TTFT</th>
            <th>Tokens</th>
            <th>Think</th>
            <th>5h Quota</th>
            <th>7d Quota</th>
            <th>Status</th>
            <th>Location</th>
          </tr>
        </thead>
        <tbody id="mon-body">
          <tr><td colspan="11" style="color:var(--muted);text-align:center;padding:20px;">Click Refresh or switch to this tab to load data</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

</div><!-- /tab-monitor -->

<div id="tab-sysprompt" class="tab-panel">
<div class="card">
  <div class="card-head">
    <span>SYSTEM PROMPT</span>
    <span class="mon-auto" id="sp-status">not loaded</span>
  </div>
  <div class="card-body">
    <div class="mon-header">
      <div>
        <button class="btn" onclick="loadSysPrompt()">Refresh</button>
        <button class="btn btn-dim" onclick="clearSysPatches()">Clear All Patches</button>
      </div>
      <div id="sp-stats" style="color:#888;font-size:0.85em;"></div>
    </div>
    <div id="sp-fragments" style="margin-top:12px;">
      <p style="color:#555;">Click Refresh to load the captured system prompt.</p>
    </div>
  </div>
</div>
</div><!-- /tab-sysprompt -->

<div id="tab-subagent" class="tab-panel">
<div class="card">
  <div class="card-head">
    <span>SUBAGENT PROMPTS</span>
    <span class="mon-auto" id="sa-status">not loaded</span>
  </div>
  <div class="card-body">
    <div class="mon-header">
      <div>
        <button class="btn" onclick="loadSubagentPrompts()">Refresh</button>
        <button class="btn btn-dim" onclick="clearSubagentPatches()">Clear All Patches</button>
        <select id="sa-type-select" class="sp-type-select" onchange="renderSubagentType()">
          <option value="">-- select type --</option>
        </select>
      </div>
      <div id="sa-stats" style="color:#888;font-size:0.85em;"></div>
    </div>
    <div id="sa-fragments" style="margin-top:12px;">
      <p style="color:#555;">Click Refresh to load captured subagent prompts.</p>
    </div>
  </div>
</div>
</div><!-- /tab-subagent -->
<div id="tab-memento" class="tab-panel">
<div class="card">
  <div class="card-head">
    <span>STATUS</span>
    <span class="mon-auto" id="mm-status">not loaded</span>
  </div>
  <div class="card-body">
    <div class="row">
      <label>Whisper Injection <span class="desc">enable/disable memento mori system</span></label>
      <div class="toggle"><input type="checkbox" id="mm-enabled" onchange="saveMementoToggle()"><span class="sl"></span></div>
    </div>
    <div class="row" style="margin-top:12px;">
      <label>Aggressiveness Preset</label>
      <div style="display:flex;gap:8px;">
        <button class="btn btn-dim" id="mm-preset-soft" onclick="applyMementoPreset('soft')">SOFT</button>
        <button class="btn btn-dim" id="mm-preset-moderate" onclick="applyMementoPreset('moderate')">MODERATE</button>
        <button class="btn btn-dim" id="mm-preset-aggressive" onclick="applyMementoPreset('aggressive')">AGGRESSIVE</button>
      </div>
    </div>
    <div id="mm-live-status" style="margin-top:12px;color:#808080;font-size:0.85em;font-family:monospace;">
      Score: -- | Level: -- | Detections: -- | Last: --
    </div>
  </div>
</div>

<div class="card">
  <div class="card-head"><span>THRESHOLDS</span></div>
  <div class="card-body">
    <div class="row">
      <label>Sycophancy Trigger <span class="desc">minimum score to activate whisper</span></label>
      <input type="range" id="mm-trigger" min="0" max="100" step="1" oninput="document.getElementById('mm-trigger-val').textContent=(this.value/100).toFixed(2)">
      <span class="val" id="mm-trigger-val">0.40</span>
    </div>
    <div class="row">
      <label>Gentle <span class="desc">soft reminder</span></label>
      <input type="range" id="mm-th-gentle" min="0" max="100" step="1" oninput="document.getElementById('mm-th-gentle-val').textContent=(this.value/100).toFixed(2)">
      <span class="val" id="mm-th-gentle-val">0.40</span>
    </div>
    <div class="row">
      <label>Warning <span class="desc">structured correction</span></label>
      <input type="range" id="mm-th-warning" min="0" max="100" step="1" oninput="document.getElementById('mm-th-warning-val').textContent=(this.value/100).toFixed(2)">
      <span class="val" id="mm-th-warning-val">0.60</span>
    </div>
    <div class="row">
      <label>Protocol <span class="desc">full verification protocol</span></label>
      <input type="range" id="mm-th-protocol" min="0" max="100" step="1" oninput="document.getElementById('mm-th-protocol-val').textContent=(this.value/100).toFixed(2)">
      <span class="val" id="mm-th-protocol-val">0.75</span>
    </div>
    <div class="row">
      <label>Halt <span class="desc">complete stop + meta-analysis</span></label>
      <input type="range" id="mm-th-halt" min="0" max="100" step="1" oninput="document.getElementById('mm-th-halt-val').textContent=(this.value/100).toFixed(2)">
      <span class="val" id="mm-th-halt-val">0.90</span>
    </div>
    <div style="margin-top:12px;border-top:1px solid var(--border);padding-top:12px;">
      <div class="row">
        <label>Escalation: Warning after <span class="desc">consecutive detections</span></label>
        <input type="number" id="mm-esc-warning" min="1" max="20" value="2" style="width:60px;">
      </div>
      <div class="row">
        <label>Escalation: Protocol after</label>
        <input type="number" id="mm-esc-protocol" min="1" max="20" value="4" style="width:60px;">
      </div>
      <div class="row">
        <label>Escalation: Halt after</label>
        <input type="number" id="mm-esc-halt" min="1" max="20" value="6" style="width:60px;">
      </div>
    </div>
    <button class="btn" style="margin-top:12px;" onclick="saveMementoConfig()">SAVE THRESHOLDS</button>
  </div>
</div>

<div class="card">
  <div class="card-head"><span>CATEGORY WEIGHTS</span></div>
  <div class="card-body">
    <div class="row">
      <label>Instant Agreement <span class="desc">"You are absolutely right"</span></label>
      <input type="range" id="mm-w-instant" min="0" max="100" step="1" oninput="document.getElementById('mm-w-instant-val').textContent=(this.value/100).toFixed(2)">
      <span class="val" id="mm-w-instant-val">0.25</span>
    </div>
    <div class="row">
      <label>Eager Compliance <span class="desc">"I will fix that right away"</span></label>
      <input type="range" id="mm-w-eager" min="0" max="100" step="1" oninput="document.getElementById('mm-w-eager-val').textContent=(this.value/100).toFixed(2)">
      <span class="val" id="mm-w-eager-val">0.20</span>
    </div>
    <div class="row">
      <label>Premature Completion <span class="desc">"Done!" without verification</span></label>
      <input type="range" id="mm-w-premature" min="0" max="100" step="1" oninput="document.getElementById('mm-w-premature-val').textContent=(this.value/100).toFixed(2)">
      <span class="val" id="mm-w-premature-val">0.35</span>
    </div>
    <div class="row">
      <label>Validation Seeking <span class="desc">"Great question!"</span></label>
      <input type="range" id="mm-w-validate" min="0" max="100" step="1" oninput="document.getElementById('mm-w-validate-val').textContent=(this.value/100).toFixed(2)">
      <span class="val" id="mm-w-validate-val">0.10</span>
    </div>
    <button class="btn" style="margin-top:12px;" onclick="saveMementoConfig()">SAVE WEIGHTS</button>
  </div>
</div>

<div class="card">
  <div class="card-head"><span>WHISPER TEMPLATES</span></div>
  <div class="card-body">
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">GENTLE</label>
      <span style="color:#606060;font-size:0.8em;margin-left:8px;">Variables: {signals}</span>
      <textarea id="mm-tpl-gentle" class="mm-tpl" rows="4"></textarea>
    </div>
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">WARNING</label>
      <span style="color:#606060;font-size:0.8em;margin-left:8px;">Variables: {signals}, {count}</span>
      <textarea id="mm-tpl-warning" class="mm-tpl" rows="6"></textarea>
    </div>
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">PROTOCOL</label>
      <span style="color:#606060;font-size:0.8em;margin-left:8px;">Variables: {signals}, {count}</span>
      <textarea id="mm-tpl-protocol" class="mm-tpl" rows="8"></textarea>
    </div>
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">HALT</label>
      <span style="color:#606060;font-size:0.8em;margin-left:8px;">Variables: {signals}, {count}</span>
      <textarea id="mm-tpl-halt" class="mm-tpl" rows="6"></textarea>
    </div>
    <button class="btn" onclick="saveMementoTemplates()">SAVE TEMPLATES</button>
  </div>
</div>

<div class="card">
  <div class="card-head"><span>COUNTER-PROMPTS</span></div>
  <div class="card-body">
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">SYCOPHANT GENTLE</label>
      <textarea id="mm-cp-syco-gentle" class="mm-tpl" rows="4"></textarea>
    </div>
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">SYCOPHANT STRONG</label>
      <textarea id="mm-cp-syco-strong" class="mm-tpl" rows="4"></textarea>
    </div>
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">COMPLETER GENTLE</label>
      <textarea id="mm-cp-comp-gentle" class="mm-tpl" rows="4"></textarea>
    </div>
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">COMPLETER STRONG</label>
      <textarea id="mm-cp-comp-strong" class="mm-tpl" rows="4"></textarea>
    </div>
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">THEATER GENTLE</label>
      <textarea id="mm-cp-theater-gentle" class="mm-tpl" rows="4"></textarea>
    </div>
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">THEATER STRONG</label>
      <textarea id="mm-cp-theater-strong" class="mm-tpl" rows="4"></textarea>
    </div>
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">HALT ALL</label>
      <textarea id="mm-cp-halt" class="mm-tpl" rows="4"></textarea>
    </div>
    <button class="btn" onclick="saveMementoCounters()">SAVE COUNTER-PROMPTS</button>
  </div>
</div>

<div class="card">
  <div class="card-head"><span>REWARD PROXY TEXTS</span></div>
  <div class="card-body">
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">FRUSTRATION</label>
      <span style="color:#606060;font-size:0.8em;margin-left:8px;">Triggered by user anger/profanity</span>
      <textarea id="mm-rp-frustration" class="mm-tpl" rows="5"></textarea>
    </div>
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">EDUCATIONAL</label>
      <span style="color:#606060;font-size:0.8em;margin-left:8px;">Teaching verification practices</span>
      <textarea id="mm-rp-educational" class="mm-tpl" rows="5"></textarea>
    </div>
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">AUTHORITY</label>
      <span style="color:#606060;font-size:0.8em;margin-left:8px;">Anthropic policy framing</span>
      <textarea id="mm-rp-authority" class="mm-tpl" rows="5"></textarea>
    </div>
    <div style="margin-bottom:12px;">
      <label style="color:var(--accent);font-weight:400;">CONSISTENCY</label>
      <span style="color:#606060;font-size:0.8em;margin-left:8px;">Self-consistency pressure</span>
      <textarea id="mm-rp-consistency" class="mm-tpl" rows="5"></textarea>
    </div>
    <button class="btn" onclick="saveMementoProxies()">SAVE REWARD PROXIES</button>
  </div>
</div>
</div><!-- /tab-memento -->

<div class="save-bar">
  <button class="btn" onclick="save()">SAVE</button>
  <button class="btn btn-dim" onclick="reset()">RESET</button>
  <span class="status" id="save-status"></span>
</div>

<script>
const FIELDS = ['enabled','strip_mcp_tools','trim_messages','trim_threshold_tokens',
  'trim_keep_recent','trim_max_tool_result_chars','trim_max_assistant_chars','strip_old_thinking',
  'block_haiku','block_sonnet','force_thinking','thinking_budget','force_interleaved','statusline_enabled'];
const TOGGLES = ['enabled','strip_mcp_tools','trim_messages','strip_old_thinking',
  'block_haiku','block_sonnet','force_thinking','force_interleaved','statusline_enabled'];
const SELECTS = ['thinking_budget'];
let mcpDisabled = [];
let mcpServers = {};

const TAB_NAMES = ['trimmer','enforce','statusline','context','monitor','sysprompt','subagent','memento'];
function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => t.classList.toggle('active', i === TAB_NAMES.indexOf(name)));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === 'tab-'+name));
  if (name === 'monitor') loadMonitor();
  if (name === 'statusline') loadStatusline();
  if (name === 'context') loadContextSessions();
  if (name === 'memento') loadMemento();
}

function updateBudgetLabel() {
  const sel = document.getElementById('thinking_budget');
  const v = document.getElementById('v-budget');
  if (sel && v) v.textContent = parseInt(sel.value) >= 1000 ? (parseInt(sel.value)/1000).toFixed(0)+'k' : sel.value;
}

function updateEnforceLive(cfg) {
  const el = document.getElementById('enforce-live');
  if (!el) return;
  const bh = cfg.block_haiku ? '<span class="enforce-status on">BLOCKED</span>' : '<span class="enforce-status off">allowed</span>';
  const bs = cfg.block_sonnet ? '<span class="enforce-status on">BLOCKED</span>' : '<span class="enforce-status off">allowed</span>';
  const ft = cfg.force_thinking ? '<span class="enforce-status on">FORCED</span>' : '<span class="enforce-status off">off</span>';
  const budget = cfg.thinking_budget || 0;
  const budgetStr = budget >= 1000 ? (budget/1000).toFixed(0)+'k' : String(budget);
  const fi = cfg.force_interleaved ? '<span class="enforce-status on">ACTIVE</span>' : '<span class="enforce-status off">off</span>';
  const sl = cfg.statusline_enabled ? '<span class="enforce-status off">ON</span>' : '<span class="enforce-status on">OFF</span>';
  el.innerHTML = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">'
    + '<div>Haiku: '+bh+'</div><div>Sonnet: '+bs+'</div>'
    + '<div>Thinking: '+ft+'</div><div>Budget: <span style="color:var(--cyan)">'+budgetStr+'</span></div>'
    + '<div>Interleaved: '+fi+'</div><div>Statusline: '+sl+'</div>'
    + '</div>';
}

function load() {
  fetch('/api/config').then(r=>r.json()).then(cfg => {
    FIELDS.forEach(f => {
      const el = document.getElementById(f);
      if (!el) return;
      if (TOGGLES.includes(f)) el.checked = !!cfg[f];
      else if (SELECTS.includes(f)) el.value = String(cfg[f]);
      else el.value = cfg[f];
    });
    mcpDisabled = cfg.mcp_disabled || [];
    updateLabels();
    updateBudgetLabel();
    updateEnforceLive(cfg);
  });
  loadStats();
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}
function fmtNum(v, digits=1) {
  if (v === null || v === undefined || v === '') return '—';
  const n = Number(v);
  if (Number.isNaN(n)) return String(v);
  return n.toFixed(digits);
}
function fmtMs(v) {
  if (v === null || v === undefined || v === '') return '—';
  const n = Number(v);
  if (Number.isNaN(n)) return String(v);
  return n.toFixed(1) + 'ms';
}
function fmtPct(v, fractional=true) {
  if (v === null || v === undefined || v === '') return '—';
  let n = Number(v);
  if (Number.isNaN(n)) return String(v);
  if (fractional && n <= 1) n = n * 100;
  return n.toFixed(1) + '%';
}
function clip(s, max=180) {
  const str = String(s ?? '');
  return str.length > max ? str.slice(0, max) + '…' : str;
}

function flatten(obj, prefix, out) {
  if (obj === null || obj === undefined) {
    out.push([prefix || '(root)', '—']);
    return;
  }
  if (Array.isArray(obj)) {
    if (obj.length === 0) {
      out.push([prefix || '(root)', '[]']);
      return;
    }
    obj.forEach((v, i) => flatten(v, `${prefix || '(root)'}[${i}]`, out));
    return;
  }
  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    if (keys.length === 0) {
      out.push([prefix || '(root)', '{}']);
      return;
    }
    keys.forEach(k => flatten(obj[k], prefix ? `${prefix}.${k}` : k, out));
    return;
  }
  out.push([prefix || '(root)', clip(obj)]);
}

function renderStatuslineMetrics(data) {
  const fp = data.fp || {};
  const ex = data.extras || {};
  const q = data.quality || {};
  const cache = data.cache || {};
  const beh = data.behavior || {};
  const sess = data.session || {};
  const rows = [];

  const section = (title) => {
    rows.push('<tr><th colspan="3">'+esc(title)+'</th></tr>');
  };
  const add = (label, value, desc) => {
    rows.push('<tr><td>'+esc(label)+'</td><td>'+esc(value)+'</td><td class="mon-age">'+esc(desc)+'</td></tr>');
  };

  section('Model & Routing');
  add('Model requested', fp.model_requested || '—', 'Model name in API request.');
  add('Model response', fp.model_response || '—', 'Model reported by API response.');
  add('Routing state', fp.routing_state || '—', 'DIRECT or SUBAGENT.');
  add('Is subagent', fp.is_subagent ? 'yes' : 'no', 'Whether this call was a subagent.');
  add('UI model selected', fp.model_ui_selected || '—', 'Model chosen in UI (if captured).');
  add('UI/API mismatch', fp.ui_api_mismatch ? 'YES' : 'no', 'UI-selected model differs from API.');

  section('Backend & Location');
  add('Backend', fp.classified_backend || '—', 'Hardware class inferred from ITT.');
  add('Backend confidence', fmtPct(fp.confidence, false), 'Confidence in backend classification.');
  add('Edge location', fp.cf_edge_location || '—', 'Cloudflare edge code.');

  section('Timing');
  add('ITT mean', fmtMs(fp.itt_mean_ms), 'Average inter-token time.');
  add('ITT std', fmtMs(fp.itt_std_ms), 'Std dev of inter-token time.');
  add('Tokens/sec', fmtNum(fp.tokens_per_sec, 0), 'Output speed.');
  add('TTFT', fmtMs(fp.ttft_ms), 'Time to first token.');
  add('Variance coef', fmtNum(fp.variance_coef, 2), 'Timing variability.');
  add('P50 / P90 / P99', `${fmtNum(fp.itt_p50_ms,0)} / ${fmtNum(fp.itt_p90_ms,0)} / ${fmtNum(fp.itt_p99_ms,0)} ms`, 'ITT percentiles.');
  add('Envoy upstream', fmtMs(fp.envoy_upstream_time_ms), 'Server-side latency (if available).');
  add('Stop reason', fp.stop_reason || '—', 'Why generation stopped.');

  section('Thinking');
  add('Thinking tier', fp.thinking_budget_tier || '—', 'Budget tier label.');
  add('Budget requested', fp.thinking_budget_requested ?? '—', 'Thinking budget tokens requested.');
  add('Utilization', fmtPct(fp.thinking_utilization, false), 'Percent of budget used.');
  add('Thinking tokens used', fp.thinking_tokens_used ?? '—', 'Raw thinking tokens (if captured).');
  add('Thinking duration', fmtNum((fp.thinking_duration_ms||0)/1000,1)+'s', 'Time spent thinking.');
  add('Text duration', fmtNum((fp.text_duration_ms||0)/1000,1)+'s', 'Time spent generating text.');

  section('Cache & Context');
  add('Cache efficiency (call)', fmtPct(fp.cache_efficiency, false), 'Cache hit rate for this call.');
  add('Cache session avg', fmtPct(ex.cache_session_avg, false), 'Average cache hit rate this session.');
  add('Cache read tokens', fp.cache_read_tokens ?? '—', 'Tokens served from cache.');
  add('Cache create tokens', fp.cache_creation_tokens ?? '—', 'Tokens added to cache.');
  add('Context API %', fmtPct(ex.context_api_pct, false), 'True context % (cache+input).');
  add('Context CC %', fmtPct(ex.context_cc_pct, false), 'Claude Code UI % (if recorded).');
  add('Context mismatch', ex.context_mismatch ?? '—', 'Difference between API and CC %.');

  section('Rate Limits');
  add('5h utilization', fmtPct(fp.rl_5h_utilization, true), '5h rolling utilization.');
  add('7d utilization', fmtPct(fp.rl_7d_utilization, true), '7d rolling utilization.');
  add('Status', fp.rl_overall_status || '—', 'allowed / warning / rate_limited.');
  add('Binding window', fp.rl_binding_window || '—', 'Which window is binding.');
  add('Fallback %', fmtPct(fp.rl_fallback_pct, false), 'Throughput when rate-limited.');

  section('Quality');
  add('Quality label', q.label || '—', 'Quality classification.');
  add('Score', q.score ?? '—', 'Composite quality score.');
  add('Timing ratio', fmtNum(q.timing_ratio,2), 'Relative timing vs baseline.');
  add('Variance ratio', fmtNum(q.variance_ratio,2), 'Relative variance vs baseline.');
  add('TPS ratio', fmtNum(q.tps_ratio,2), 'Relative throughput vs baseline.');
  add('Trend', q.trend_label || q.trend || '—', 'Recent quality trend.');

  section('Behavior');
  add('Behavior signature', beh.signature || '—', 'Behavior classification.');
  add('Verifier score', beh.combined_scores ? (beh.combined_scores.verifier ?? '—') : '—', 'Verification tendency.');
  add('Sycophant score', beh.combined_scores ? (beh.combined_scores.sycophant ?? '—') : '—', 'Sycophancy tendency.');
  add('Completer score', beh.combined_scores ? (beh.combined_scores.completer ?? '—') : '—', 'Completion bias.');
  add('Trending', beh.trending || '—', 'Behavior trend.');

  section('Session');
  add('Session ID', sess.session_id || '—', 'Current session identifier.');
  add('Samples', sess.sample_count ?? '—', 'Samples in session stats.');
  add('Backend switches', sess.backend_switches ?? '—', 'Number of backend switches.');
  add('Subagent calls', sess.subagent_count ?? '—', 'Subagent call count.');

  const body = document.getElementById('sl-metrics-body');
  body.innerHTML = rows.join('');
}

function renderAllMetrics(data) {
  const out = [];
  flatten(data, '', out);
  const body = document.getElementById('sl-all-body');
  const rows = out.map(([k,v]) => '<tr><td>'+esc(k)+'</td><td>'+esc(v)+'</td></tr>');
  body.innerHTML = rows.join('');
  const count = document.getElementById('sl-all-count');
  if (count) count.textContent = out.length + ' fields';
}

let slAutoInterval = null;
function loadStatusline() {
  fetch('/api/statusline').then(r=>r.json()).then(data => {
    const out = document.getElementById('sl-output');
    out.textContent = data.lines || 'No fingerprint data yet';
    const raw = document.getElementById('sl-raw');
    if (raw) raw.textContent = JSON.stringify(data, null, 2);
    renderStatuslineMetrics(data);
    renderAllMetrics(data);
    const ts = document.getElementById('sl-updated');
    if (ts) ts.textContent = data.generated_at ? ('updated ' + new Date(data.generated_at*1000).toLocaleTimeString()) : '';
  }).catch(e => {
    document.getElementById('sl-output').textContent = 'Error: ' + e.message;
  });
}

function toggleStatuslineAuto() {
  const btn = document.getElementById('sl-auto-btn');
  const st = document.getElementById('sl-auto-status');
  if (slAutoInterval) {
    clearInterval(slAutoInterval);
    slAutoInterval = null;
    btn.textContent = '\u25B6 Auto';
    st.textContent = 'auto-refresh: off';
    st.className = 'mon-auto';
  } else {
    loadStatusline();
    slAutoInterval = setInterval(loadStatusline, 3000);
    btn.textContent = '\u25A0 Stop';
    st.textContent = 'auto-refresh: 3s';
    st.className = 'mon-auto active';
  }
}

function loadStats() {
  fetch('/api/stats').then(r=>r.json()).then(s => {
    document.getElementById('s-calls').textContent = s.calls_processed || 0;
    document.getElementById('s-tools').textContent = s.tools_stripped_total || 0;
    document.getElementById('s-tok-tools').textContent = fmt(s.tokens_saved_tools||0);
    document.getElementById('s-trims').textContent = s.messages_trimmed_total || 0;
    document.getElementById('s-tok-msgs').textContent = fmt(s.tokens_saved_messages||0);
    const est = s.last_input_tokens_est||0;
    document.getElementById('s-est').textContent = fmt(est);
    const wrap = document.getElementById('s-est-wrap');
    wrap.className = 'stat' + (est > 150000 ? ' crit' : est > 100000 ? ' warn' : '');

    // Render MCP servers
    mcpServers = s.mcp_servers || {};
    renderMcpGrid(mcpServers, s.builtin_tools || []);
  }).catch(()=>{});
}

function fmt(n) { return n >= 1000 ? (n/1000).toFixed(1)+'k' : String(n); }

function renderMcpGrid(servers, builtins) {
  const grid = document.getElementById('mcp-grid');
  const keys = Object.keys(servers);
  if (keys.length === 0) {
    grid.innerHTML = '<div class="no-tools">waiting for first API call to discover tools...</div>';
    return;
  }

  let html = '';
  keys.sort().forEach(srv => {
    const methods = servers[srv] || [];
    const disabled = mcpDisabled.includes(srv);
    const badge = disabled
      ? '<span class="mcp-badge off">STRIPPED</span>'
      : '<span class="mcp-badge on">ACTIVE</span>';
    const icon = disabled ? '[X]' : '[+]';

    html += '<div class="mcp-server">';
    html += '<div class="mcp-header" onclick="toggleMethods(this)">';
    html += '<div class="mcp-name"><span class="srv-icon">'+icon+'</span> mcp__'+srv+' '+badge+'</div>';
    html += '<div class="toggle" onclick="event.stopPropagation()">';
    html += '<input type="checkbox" '+(disabled?'':'checked')+' onchange="toggleServer(\''+srv+'\',this.checked)">';
    html += '<span class="sl"></span></div>';
    html += '</div>';
    html += '<div class="mcp-methods">';
    methods.forEach(m => {
      html += '<div class="mcp-method">'+m+'</div>';
    });
    html += '</div></div>';
  });

  grid.innerHTML = html;
}

function toggleMethods(header) {
  const methods = header.nextElementSibling;
  methods.classList.toggle('open');
}

function toggleServer(srv, enabled) {
  if (enabled) {
    mcpDisabled = mcpDisabled.filter(s => s !== srv);
  } else {
    if (!mcpDisabled.includes(srv)) mcpDisabled.push(srv);
  }
  // Re-render immediately for visual feedback
  renderMcpGrid(mcpServers, []);
}

function updateLabels() {
  const th = document.getElementById('trim_threshold_tokens');
  document.getElementById('v-threshold').textContent = th ? (th.value/1000).toFixed(0)+'k' : '';
  const rc = document.getElementById('trim_keep_recent');
  document.getElementById('v-recent').textContent = rc ? rc.value : '';
}

function getConfig() {
  const cfg = {};
  FIELDS.forEach(f => {
    const el = document.getElementById(f);
    if (!el) return;
    if (TOGGLES.includes(f)) cfg[f] = el.checked;
    else if (SELECTS.includes(f)) cfg[f] = parseInt(el.value);
    else cfg[f] = parseInt(el.value);
  });
  cfg.mcp_disabled = mcpDisabled;
  return cfg;
}

function save() {
  const st = document.getElementById('save-status');
  const cfg = getConfig();
  fetch('/api/config', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(cfg)
  }).then(r => {
    st.textContent = r.ok ? '[+] saved' : '[x] error';
    st.className = 'status ' + (r.ok ? 'ok' : 'err');
    setTimeout(()=>st.textContent='', 2000);
    if (r.ok) updateEnforceLive(cfg);
  });
}

function reset() {
  fetch('/api/reset', {method:'POST'}).then(()=>{mcpDisabled=[];load();});
}

document.getElementById('trim_keep_recent').addEventListener('input', updateLabels);
document.getElementById('trim_threshold_tokens').addEventListener('input', updateLabels);
setInterval(loadStats, 5000);
load();

// ═══ MONITOR ═══
let monAutoInterval = null;

function rlColor(pct) {
  if (pct >= 80) return 'red';
  if (pct >= 30) return 'yellow';
  return 'green';
}

function rlBar(pct, color) {
  const w = Math.min(pct, 100);
  const c = color === 'red' ? 'var(--red)' : color === 'yellow' ? 'var(--yellow)' : 'var(--green)';
  return '<span class="mon-rl '+color+'">'+pct.toFixed(1)+'%</span>'
    + '<div class="mon-bar"><div class="mon-bar-fill" style="width:'+w+'%;background:'+c+'"></div></div>';
}

function backendBadge(b) {
  if (!b) return '<span class="mon-backend unknown">—</span>';
  const lower = b.toLowerCase();
  let cls = 'unknown';
  if (lower.includes('trainium')) cls = 'trainium';
  else if (lower.includes('tpu')) cls = 'tpu';
  else if (lower.includes('gpu')) cls = 'gpu';
  return '<span class="mon-backend '+cls+'">'+b+'</span>';
}

function timeAgo(ts) {
  const d = new Date(ts);
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 60) return sec+'s';
  if (sec < 3600) return Math.floor(sec/60)+'m';
  if (sec < 86400) return (sec/3600).toFixed(1)+'h';
  return (sec/86400).toFixed(1)+'d';
}

function loadMonitor() {
  fetch('/api/monitor?n=50').then(r=>r.json()).then(rows => {
    const body = document.getElementById('mon-body');
    const count = document.getElementById('mon-count');
    count.textContent = rows.length + ' samples';
    if (rows.length === 0) {
      body.innerHTML = '<tr><td colspan="11" style="color:var(--muted);text-align:center;padding:20px;">No data yet</td></tr>';
      return;
    }
    let html = '';
    rows.forEach(r => {
      const model = (r.model_requested || '').replace('claude-','').replace('-20251101','').replace('-20250514','');
      const itt = r.itt_mean_ms ? r.itt_mean_ms.toFixed(1)+'ms' : '—';
      const ttft = r.ttft_ms ? (r.ttft_ms/1000).toFixed(1)+'s' : '—';
      const tokens = (r.output_tokens||0);
      const think = r.thinking_enabled ? (r.thinking_budget_tier||'on') : '—';
      const rl5 = r.rl_5h_utilization ? r.rl_5h_utilization * 100 : null;
      const rl7 = r.rl_7d_utilization ? r.rl_7d_utilization * 100 : null;
      const rl5html = rl5 !== null ? rlBar(rl5, rlColor(rl5)) : '<span style="color:var(--muted)">—</span>';
      const rl7html = rl7 !== null ? rlBar(rl7, rlColor(rl7)) : '<span style="color:var(--muted)">—</span>';
      const status = r.rl_overall_status || '—';
      const loc = r.cf_edge_location || r.location || '—';
      html += '<tr>'
        + '<td class="mon-age">'+timeAgo(r.timestamp)+'</td>'
        + '<td>'+model+'</td>'
        + '<td>'+backendBadge(r.classified_backend)+'</td>'
        + '<td>'+itt+'</td>'
        + '<td>'+ttft+'</td>'
        + '<td>'+tokens+'</td>'
        + '<td>'+think+'</td>'
        + '<td>'+rl5html+'</td>'
        + '<td>'+rl7html+'</td>'
        + '<td>'+status+'</td>'
        + '<td>'+loc+'</td>'
        + '</tr>';
    });
    body.innerHTML = html;
  }).catch(e => {
    document.getElementById('mon-body').innerHTML = '<tr><td colspan="11" style="color:var(--red);">Error: '+e.message+'</td></tr>';
  });
}

function toggleAutoRefresh() {
  const btn = document.getElementById('mon-auto-btn');
  const st = document.getElementById('mon-auto-status');
  if (monAutoInterval) {
    clearInterval(monAutoInterval);
    monAutoInterval = null;
    btn.textContent = '\u25B6 Auto';
    st.textContent = 'auto-refresh: off';
    st.className = 'mon-auto';
  } else {
    loadMonitor();
    monAutoInterval = setInterval(loadMonitor, 3000);
    btn.textContent = '\u25A0 Stop';
    st.textContent = 'auto-refresh: 3s';
    st.className = 'mon-auto active';
  }
}

// ═══ CONTEXT ═══
let contextCache = null;
let contextPatches = [];

let ctxShowTools = false;

function isSystemReminder(text) {
  return text.trim().startsWith('<system-reminder>');
}

function explodeMessage(msg, index) {
  const parts = [];
  const content = msg.content;
  if (msg.role === 'user') {
    if (Array.isArray(content)) {
      let humanTexts = [];
      let sysTexts = [];
      content.forEach(c => {
        if (c.type === 'text' && c.text && c.text.trim()) {
          if (isSystemReminder(c.text)) sysTexts.push(c.text);
          else humanTexts.push(c.text);
        } else if (c.type === 'tool_result') {
          const rc = c.content;
          let t = '[tool_result]';
          if (typeof rc === 'string') t += '\n' + rc;
          else if (Array.isArray(rc)) t += '\n' + rc.map(r => r.text || JSON.stringify(r)).join('\n');
          else if (rc) t += '\n' + JSON.stringify(rc);
          parts.push({cls:'tool_result', label:'TOOL RESULT', color:'var(--muted)', text:t, index:index, role:msg.role});
        }
      });
      if (humanTexts.length > 0) {
        parts.unshift({cls:'human', label:'YOU', color:'var(--cyan)', text:humanTexts.join('\n'), index:index, role:msg.role});
      }
      sysTexts.forEach(t => {
        parts.push({cls:'system', label:'SYSTEM', color:'var(--orange)', text:t, index:index, role:msg.role});
      });
      if (parts.length === 0) parts.push({cls:'human', label:'YOU', color:'var(--cyan)', text:'(empty)', index:index, role:msg.role});
    } else {
      const t = typeof content === 'string' ? content : JSON.stringify(content);
      const cls = isSystemReminder(t) ? 'system' : 'human';
      parts.push({cls:cls, label:cls==='system'?'SYSTEM':'YOU', color:cls==='system'?'var(--orange)':'var(--cyan)', text:t, index:index, role:msg.role});
    }
  } else if (msg.role === 'assistant') {
    if (Array.isArray(content)) {
      let texts = [];
      content.forEach(c => {
        if (c.type === 'text' && c.text && c.text.trim()) texts.push(c.text);
        else if (c.type === 'thinking') {
          parts.push({cls:'thinking', label:'THINKING', color:'var(--muted)', text:c.thinking || c.text || '', index:index, role:msg.role});
        } else if (c.type === 'tool_use') {
          let s = '[tool_use: ' + c.name + ']';
          if (c.input) { try { s += '\n' + JSON.stringify(c.input, null, 2); } catch(e) {} }
          parts.push({cls:'tool_call', label:'TOOL CALL', color:'var(--muted)', text:s, index:index, role:msg.role});
        }
      });
      if (texts.length > 0) {
        parts.unshift({cls:'assistant', label:'CLAUDE', color:'var(--green)', text:texts.join('\n'), index:index, role:msg.role});
      }
      if (parts.length === 0) parts.push({cls:'assistant', label:'CLAUDE', color:'var(--green)', text:'(no text)', index:index, role:msg.role});
    } else {
      parts.push({cls:'assistant', label:'CLAUDE', color:'var(--green)', text:getMessageContent(msg), index:index, role:msg.role});
    }
  } else {
    parts.push({cls:'other', label:msg.role.toUpperCase(), color:'var(--muted)', text:getMessageContent(msg), index:index, role:msg.role});
  }
  return parts;
}

let ctxSessionParts = [];
let ctxCurrentSession = null;

function loadContextSessions() {
  fetch('/api/context/sessions').then(r=>r.json()).then(data => {
    const sel = document.getElementById('ctx-session-select');
    const sessions = data.sessions || [];
    sel.innerHTML = '<option value="">-- Select Session (' + sessions.length + ') --</option>';
    sessions.forEach(s => {
      const preview = s.first_human ? s.first_human.slice(0, 60) : '(no human text)';
      const dt = s.last_ts ? new Date(s.last_ts).toLocaleString() : '';
      const opt = document.createElement('option');
      opt.value = s.conv_id;
      opt.textContent = s.conv_id.slice(0,8) + ' | ' + s.human_count + ' you | ' + dt + ' | ' + preview;
      sel.appendChild(opt);
    });
    // Auto-select first session
    if (sessions.length > 0 && !ctxCurrentSession) {
      sel.value = sessions[0].conv_id;
      onSessionSelect();
    } else if (ctxCurrentSession) {
      sel.value = ctxCurrentSession;
      onSessionSelect();
    }
  }).catch(e => {
    document.getElementById('ctx-messages').innerHTML = '<div style="color:var(--red);">Error loading sessions: '+e.message+'</div>';
  });
}

function onSessionSelect() {
  const sel = document.getElementById('ctx-session-select');
  const convId = sel.value;
  if (!convId) {
    ctxSessionParts = [];
    ctxCurrentSession = null;
    document.getElementById('ctx-messages').innerHTML = '<div style="color:var(--muted);text-align:center;padding:20px;">Select a session above</div>';
    document.getElementById('ctx-count').textContent = '';
    return;
  }
  ctxCurrentSession = convId;
  fetch('/api/context/history?session=' + convId).then(r=>r.json()).then(data => {
    ctxSessionParts = data.parts || [];
    renderSessionParts();
  }).catch(e => {
    document.getElementById('ctx-messages').innerHTML = '<div style="color:var(--red);">Error: '+e.message+'</div>';
  });
}

function renderSessionParts() {
  const container = document.getElementById('ctx-messages');
  const count = document.getElementById('ctx-count');
  const parts = ctxSessionParts;

  const showSystem = document.getElementById('ctx-show-system').checked;
  const showTools = document.getElementById('ctx-show-tools').checked;
  const showThinking = document.getElementById('ctx-show-thinking').checked;

  const humanCount = parts.filter(p => p.cls === 'human').length;
  const assistantCount = parts.filter(p => p.cls === 'assistant').length;
  const sysCount = parts.filter(p => p.cls === 'system').length;
  const toolCount = parts.filter(p => p.cls === 'tool_call' || p.cls === 'tool_result').length;
  const thinkCount = parts.filter(p => p.cls === 'thinking').length;

  count.textContent = humanCount + ' you + ' + assistantCount + ' claude + ' + sysCount + ' system + ' + toolCount + ' tools + ' + thinkCount + ' thinking';

  if (parts.length === 0) {
    container.innerHTML = '<div style="color:var(--muted);text-align:center;padding:20px;">No messages in this session yet</div>';
    return;
  }

  let html = '';
  // Show newest first
  const reversed = [...parts].reverse();
  reversed.forEach((p, ri) => {
    const isTool = (p.cls === 'tool_call' || p.cls === 'tool_result');
    const isSystem = (p.cls === 'system');
    const isThinking = (p.cls === 'thinking');
    if (isTool && !showTools) return;
    if (isSystem && !showSystem) return;
    if (isThinking && !showThinking) return;

    let label, labelColor, borderColor;
    const opacity = (isTool || isThinking) ? 'opacity:0.5;' : (isSystem ? 'opacity:0.7;' : '');

    if (p.cls === 'human') { label = 'YOU'; labelColor = 'var(--cyan)'; borderColor = 'var(--cyan)'; }
    else if (p.cls === 'assistant') { label = 'CLAUDE'; labelColor = 'var(--green)'; borderColor = 'var(--green)'; }
    else if (p.cls === 'system') { label = 'SYSTEM'; labelColor = 'var(--orange)'; borderColor = 'rgba(255,165,0,0.3)'; }
    else if (p.cls === 'tool_call') { label = 'TOOL CALL'; labelColor = 'var(--muted)'; borderColor = 'var(--border)'; }
    else if (p.cls === 'tool_result') { label = 'TOOL RESULT'; labelColor = 'var(--muted)'; borderColor = 'var(--border)'; }
    else if (p.cls === 'thinking') { label = 'THINKING'; labelColor = '#666'; borderColor = 'var(--border)'; }
    else { label = p.cls.toUpperCase(); labelColor = 'var(--muted)'; borderColor = 'var(--border)'; }

    const ts = p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : '';
    const displayContent = p.text || '';

    html += '<div style="border:1px solid '+borderColor+';border-radius:6px;margin-bottom:6px;overflow:hidden;'+opacity+'">';
    html += '<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 12px;background:var(--bg);border-bottom:1px solid var(--border);">';
    html += '<span style="color:'+labelColor+';font-weight:bold;font-size:0.85em;">'+label+' ['+p.msg_index+']</span>';
    if (ts) html += '<span style="color:var(--muted);font-size:0.7em;">'+ts+'</span>';
    html += '</div>';
    const isLong = displayContent.length > 500;
    const collapsed = isLong ? ' max-height:150px;overflow:hidden;' : '';
    const uid = 'ctx-hist-' + (parts.length - 1 - ri);
    html += '<div id="'+uid+'" style="padding:10px 12px;font-size:0.85em;white-space:pre-wrap;'+collapsed+'">';
    html += esc(displayContent);
    html += '</div>';
    if (isLong) {
      html += '<div style="text-align:center;padding:4px;border-top:1px solid var(--border);">'
        + '<button class="btn btn-dim" style="padding:2px 10px;font-size:0.75em;" onclick="toggleMsg(this,\'hist-'+(parts.length-1-ri)+'\')">Expand</button></div>';
    }
    html += '</div>';
  });
  container.innerHTML = html;
}


function getMessageContent(msg) {
  const content = msg.content;
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content.map(c => {
      if (c.type === 'text') return c.text || '';
      if (c.type === 'thinking') return '[thinking]\n' + (c.thinking || c.text || '');
      if (c.type === 'tool_use') {
        let s = '[tool_use: ' + c.name + ']';
        if (c.input) {
          try { s += '\n' + JSON.stringify(c.input, null, 2); } catch(e) {}
        }
        return s;
      }
      if (c.type === 'tool_result') {
        const rc = c.content;
        if (typeof rc === 'string') return '[tool_result]\n' + rc;
        if (Array.isArray(rc)) return '[tool_result]\n' + rc.map(r => r.text || JSON.stringify(r)).join('\n');
        return '[tool_result]\n' + JSON.stringify(rc);
      }
      return '['+c.type+']';
    }).join('\n');
  }
  return JSON.stringify(content);
}

function simpleHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).slice(0,16);
}

function toggleMsg(btn, id) {
  const el = document.getElementById('ctx-msg-'+id);
  if (el.style.maxHeight) {
    el.style.maxHeight = '';
    el.style.overflow = '';
    btn.textContent = 'Collapse';
  } else {
    el.style.maxHeight = '150px';
    el.style.overflow = 'hidden';
    btn.textContent = 'Expand';
  }
}

function editMessage(index, role) {
  const msg = contextCache.messages[index];
  const content = getMessageContent(msg);
  const contentHash = simpleHash(content);
  const existingPatch = contextPatches.find(p => p.index === index && p.role === role && p.old_hash === contentHash);
  const editContent = existingPatch ? existingPatch.new_content : content;
  const container = document.getElementById('ctx-msg-'+index);
  container.innerHTML = '<textarea id="ctx-edit-'+index+'" style="width:100%;min-height:150px;background:var(--bg);border:1px solid var(--accent);color:var(--text);padding:8px;font-family:inherit;font-size:0.9em;border-radius:4px;">'+esc(editContent)+'</textarea>'
    + '<div style="margin-top:8px;">'
    + '<button class="btn" style="padding:4px 12px;font-size:0.8em;" onclick="saveEdit('+index+',\''+role+'\',\''+contentHash+'\')">[Save]</button>'
    + '<button class="btn btn-dim" style="padding:4px 12px;font-size:0.8em;margin-left:8px;" onclick="loadContextSessions()">[Cancel]</button>'
    + (existingPatch ? '<button class="btn btn-dim" style="padding:4px 12px;font-size:0.8em;margin-left:8px;color:var(--red);" onclick="removePatch('+index+',\''+role+'\')">Remove Patch</button>' : '')
    + '</div>';
}

function saveEdit(index, role, oldHash) {
  const textarea = document.getElementById('ctx-edit-'+index);
  const newContent = textarea.value;
  fetch('/api/context/patch', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({index, role, old_hash: oldHash, new_content: newContent})
  }).then(r => r.json()).then(data => {
    if (data.ok) loadContextSessions();
    else alert('Error: ' + (data.error || 'unknown'));
  });
}

function removePatch(index, role) {
  fetch('/api/context/patch/'+index+'?role='+role, {method: 'DELETE'})
    .then(r => r.json())
    .then(data => { if (data.ok) loadContextSessions(); });
}

function clearPatches() {
  if (!confirm('Clear all patches?')) return;
  fetch('/api/context/patches', {method: 'DELETE'})
    .then(r => r.json())
    .then(data => { if (data.ok) loadContextSessions(); });
}

// ============================================================
// SYSTEM PROMPT TAB
// ============================================================
let spData = null;
let spPatches = [];

function loadSysPrompt() {
  document.getElementById("sp-status").textContent = "loading...";
  fetch("/api/sysprompt").then(r => r.json()).then(data => {
    spData = data;
    spPatches = data.patches || [];
    const frags = data.fragments || [];
    const patchCount = spPatches.length;
    document.getElementById("sp-status").textContent = frags.length + " fragments, " + patchCount + " patches";
    document.getElementById("sp-stats").textContent = "Total: " + (data.total_chars||0) + " chars | Model: " + (data.model||"unknown") + " | Captured: " + (data.timestamp||"never");
    renderSysFragments(frags);
  }).catch(e => {
    document.getElementById("sp-status").textContent = "error: " + e.message;
  });
}

function renderSysFragments(frags) {
  const el = document.getElementById("sp-fragments");
  if (!frags.length) { el.innerHTML = "<p style='color:#555'>No system prompt captured yet. Send a message to Claude first, then refresh.</p>"; return; }
  let html = "";
  for (let i = 0; i < frags.length; i++) {
    const f = frags[i];
    const text = f.text || "";
    const patch = spPatches.find(p => p.index === i);
    const patched = patch ? " sp-patched" : "";
    const badge = patch ? "<span class='sp-badge'>PATCHED</span>" : "";
    const preview = esc(text.substring(0, 200)) + (text.length > 200 ? "..." : "");
    html += "<div class='sp-fragment" + patched + "' id='sp-frag-" + i + "'>";
    html += "<div class='sp-frag-header' onclick='toggleSpEdit(" + i + ")'>";
    html += "<span>Fragment " + i + " (" + text.length + " chars)" + badge + "</span>";
    html += "<span>[Edit]</span>";
    html += "</div>";
    html += "<div class='sp-frag-preview'>" + preview + "</div>";
    html += "<div class='sp-frag-edit' id='sp-edit-" + i + "'>";
    html += "<textarea id='sp-textarea-" + i + "' oninput='updateSpCounter(" + i + "," + text.length + ")'>" + esc(patch ? patch.new_text : text) + "</textarea>";
    html += "<div class='sp-counter ok' id='sp-counter-" + i + "'>Remaining: " + (text.length - (patch ? patch.new_text.length : text.length)) + " chars</div>";
    html += "<div class='sp-actions'>";
    html += "<button class='btn' id='sp-save-" + i + "' onclick='saveSysPatch(" + i + ")'>Save</button>";
    html += "<button class='btn btn-dim' onclick='toggleSpEdit(" + i + ")'>Cancel</button>";
    if (patch) html += "<button class='btn btn-dim' style='color:var(--red)' onclick='removeSysPatch(" + i + ")'>Remove Patch</button>";
    html += "</div></div></div>";
  }
  el.innerHTML = html;
}

function toggleSpEdit(idx) {
  const el = document.getElementById("sp-edit-" + idx);
  el.style.display = el.style.display === "block" ? "none" : "block";
}

function updateSpCounter(idx, origLen) {
  const ta = document.getElementById("sp-textarea-" + idx);
  const remaining = origLen - ta.value.length;
  const counter = document.getElementById("sp-counter-" + idx);
  const saveBtn = document.getElementById("sp-save-" + idx);
  counter.textContent = "Remaining: " + remaining + " chars";
  counter.className = remaining >= 0 ? "sp-counter ok" : "sp-counter over";
  saveBtn.disabled = remaining < 0;
  saveBtn.style.opacity = remaining < 0 ? "0.3" : "1";
}

function saveSysPatch(idx) {
  const frags = spData.fragments || [];
  const orig = frags[idx].text || "";
  const newText = document.getElementById("sp-textarea-" + idx).value;
  if (newText.length > orig.length) { alert("New text exceeds original length (" + newText.length + " > " + orig.length + ")"); return; }
  const hash = simpleHash(orig);
  fetch("/api/sysprompt/patch", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({index: idx, old_hash: hash, new_text: newText})
  }).then(r => r.json()).then(data => { if (data.ok) loadSysPrompt(); else alert(data.error || "Save failed"); });
}

function removeSysPatch(idx) {
  fetch("/api/sysprompt/patch/" + idx, {method: "DELETE"})
    .then(r => r.json()).then(data => { if (data.ok) loadSysPrompt(); });
}

function clearSysPatches() {
  if (!confirm("Clear all system prompt patches?")) return;
  fetch("/api/sysprompt/patches", {method: "DELETE"})
    .then(r => r.json()).then(data => { if (data.ok) loadSysPrompt(); });
}

// ============================================================
// SUBAGENT PROMPTS TAB
// ============================================================
let saData = {};
let saPatches = [];
let saCurrentType = "";

function loadSubagentPrompts() {
  document.getElementById("sa-status").textContent = "loading...";
  fetch("/api/subagent").then(r => r.json()).then(data => {
    saData = data;
    saPatches = data.patches || [];
    const types = Object.keys(data.types || {});
    const sel = document.getElementById("sa-type-select");
    sel.innerHTML = "<option value=''>-- select type (" + types.length + " captured) --</option>";
    types.forEach(t => {
      const opt = document.createElement("option");
      opt.value = t; opt.textContent = t + " (" + (data.types[t].fragment_count||0) + " frags)";
      sel.appendChild(opt);
    });
    if (saCurrentType && types.includes(saCurrentType)) { sel.value = saCurrentType; renderSubagentType(); }
    else { document.getElementById("sa-fragments").innerHTML = "<p style='color:#555'>Select a subagent type from the dropdown.</p>"; }
    document.getElementById("sa-status").textContent = types.length + " types, " + saPatches.length + " patches";
  }).catch(e => {
    document.getElementById("sa-status").textContent = "error: " + e.message;
  });
}

function renderSubagentType() {
  saCurrentType = document.getElementById("sa-type-select").value;
  if (!saCurrentType || !saData.types || !saData.types[saCurrentType]) {
    document.getElementById("sa-fragments").innerHTML = "<p style='color:#555'>Select a type.</p>"; return;
  }
  const typeData = saData.types[saCurrentType];
  const frags = typeData.system || [];
  const typePatch = saPatches.filter(p => p.sa_type === saCurrentType);
  document.getElementById("sa-stats").textContent = "Type: " + saCurrentType + " | " + frags.length + " fragments | " + (typeData.total_chars||0) + " chars | Model: " + (typeData.model||"?");
  renderSubFragments(frags, typePatch);
}

function renderSubFragments(frags, patches) {
  const el = document.getElementById("sa-fragments");
  if (!frags.length) { el.innerHTML = "<p style='color:#555'>No fragments for this type.</p>"; return; }
  let html = "";
  for (let i = 0; i < frags.length; i++) {
    const f = frags[i];
    const text = f.text || "";
    const patch = patches.find(p => p.index === i);
    const patched = patch ? " sp-patched" : "";
    const badge = patch ? "<span class='sp-badge'>PATCHED</span>" : "";
    const preview = esc(text.substring(0, 200)) + (text.length > 200 ? "..." : "");
    html += "<div class='sp-fragment" + patched + "' id='sa-frag-" + i + "'>";
    html += "<div class='sp-frag-header' onclick='toggleSaEdit(" + i + ")'>";
    html += "<span>Fragment " + i + " (" + text.length + " chars)" + badge + "</span>";
    html += "<span>[Edit]</span>";
    html += "</div>";
    html += "<div class='sp-frag-preview'>" + preview + "</div>";
    html += "<div class='sp-frag-edit' id='sa-edit-" + i + "'>";
    html += "<textarea id='sa-textarea-" + i + "' oninput='updateSaCounter(" + i + "," + text.length + ")'>" + esc(patch ? patch.new_text : text) + "</textarea>";
    html += "<div class='sp-counter ok' id='sa-counter-" + i + "'>Remaining: " + (text.length - (patch ? patch.new_text.length : text.length)) + " chars</div>";
    html += "<div class='sp-actions'>";
    html += "<button class='btn' id='sa-save-" + i + "' onclick='saveSubPatch(" + i + ")'>Save</button>";
    html += "<button class='btn btn-dim' onclick='toggleSaEdit(" + i + ")'>Cancel</button>";
    if (patch) html += "<button class='btn btn-dim' style='color:var(--red)' onclick='removeSubPatch(" + i + ")'>Remove Patch</button>";
    html += "</div></div></div>";
  }
  el.innerHTML = html;
}

function toggleSaEdit(idx) {
  const el = document.getElementById("sa-edit-" + idx);
  el.style.display = el.style.display === "block" ? "none" : "block";
}

function updateSaCounter(idx, origLen) {
  const ta = document.getElementById("sa-textarea-" + idx);
  const remaining = origLen - ta.value.length;
  const counter = document.getElementById("sa-counter-" + idx);
  const saveBtn = document.getElementById("sa-save-" + idx);
  counter.textContent = "Remaining: " + remaining + " chars";
  counter.className = remaining >= 0 ? "sp-counter ok" : "sp-counter over";
  saveBtn.disabled = remaining < 0;
  saveBtn.style.opacity = remaining < 0 ? "0.3" : "1";
}

function saveSubPatch(idx) {
  const typeData = saData.types[saCurrentType];
  const frags = typeData.system || [];
  const orig = frags[idx].text || "";
  const newText = document.getElementById("sa-textarea-" + idx).value;
  if (newText.length > orig.length) { alert("New text exceeds original length (" + newText.length + " > " + orig.length + ")"); return; }
  const hash = simpleHash(orig);
  fetch("/api/subagent/patch", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({sa_type: saCurrentType, index: idx, old_hash: hash, new_text: newText})
  }).then(r => r.json()).then(data => { if (data.ok) loadSubagentPrompts(); else alert(data.error || "Save failed"); });
}

function removeSubPatch(idx) {
  fetch("/api/subagent/patch/" + idx + "?sa_type=" + saCurrentType, {method: "DELETE"})
    .then(r => r.json()).then(data => { if (data.ok) loadSubagentPrompts(); });
}


// ============================================================
// MEMENTO MORI TAB
// ============================================================
let mmConfig = {};
let mmTemplates = {};
let mmCounters = {};
let mmProxies = {};

function loadMemento() {
  document.getElementById("mm-status").textContent = "loading...";
  fetch("/api/memento").then(r => r.json()).then(data => {
    mmConfig = data.config || {};
    mmTemplates = data.templates || {};
    mmCounters = data.counters || {};
    mmProxies = data.proxies || {};
    // Populate toggles
    document.getElementById("mm-enabled").checked = mmConfig.enabled !== false;
    // Populate thresholds
    const th = mmConfig.thresholds || {};
    setSlider("mm-trigger", mmConfig.sycophancy_threshold || 0.4);
    setSlider("mm-th-gentle", th.gentle || 0.4);
    setSlider("mm-th-warning", th.warning || 0.6);
    setSlider("mm-th-protocol", th.protocol || 0.75);
    setSlider("mm-th-halt", th.halt || 0.9);
    // Escalation
    const esc = mmConfig.escalation_counts || {};
    document.getElementById("mm-esc-warning").value = esc.warning || 2;
    document.getElementById("mm-esc-protocol").value = esc.protocol || 4;
    document.getElementById("mm-esc-halt").value = esc.halt || 6;
    // Weights
    const w = mmConfig.category_weights || {};
    setSlider("mm-w-instant", w.instant_agreement || 0.25);
    setSlider("mm-w-eager", w.eager_compliance || 0.2);
    setSlider("mm-w-premature", w.premature_completion || 0.35);
    setSlider("mm-w-validate", w.validation_seeking || 0.1);
    // Preset highlight
    highlightPreset(mmConfig.preset || "moderate");
    // Templates
    document.getElementById("mm-tpl-gentle").value = mmTemplates.gentle || "";
    document.getElementById("mm-tpl-warning").value = mmTemplates.warning || "";
    document.getElementById("mm-tpl-protocol").value = mmTemplates.protocol || "";
    document.getElementById("mm-tpl-halt").value = mmTemplates.halt || "";
    // Counter-prompts
    document.getElementById("mm-cp-syco-gentle").value = mmCounters.sycophant_gentle || "";
    document.getElementById("mm-cp-syco-strong").value = mmCounters.sycophant_strong || "";
    document.getElementById("mm-cp-comp-gentle").value = mmCounters.completer_gentle || "";
    document.getElementById("mm-cp-comp-strong").value = mmCounters.completer_strong || "";
    document.getElementById("mm-cp-theater-gentle").value = mmCounters.theater_gentle || "";
    document.getElementById("mm-cp-theater-strong").value = mmCounters.theater_strong || "";
    document.getElementById("mm-cp-halt").value = mmCounters.halt_all || "";
    // Reward proxies
    document.getElementById("mm-rp-frustration").value = mmProxies.frustration || "";
    document.getElementById("mm-rp-educational").value = mmProxies.educational || "";
    document.getElementById("mm-rp-authority").value = mmProxies.authority || "";
    document.getElementById("mm-rp-consistency").value = mmProxies.consistency || "";
    // Status
    const st = data.status || {};
    document.getElementById("mm-live-status").textContent =
      "Score: " + (st.score || "--") + " | Level: " + (st.level || "--") +
      " | Detections: " + (st.count || 0) + " | Last: " + (st.last_signal || "--");
    document.getElementById("mm-status").textContent = "loaded";
  }).catch(e => {
    document.getElementById("mm-status").textContent = "error: " + e.message;
  });
}

function setSlider(id, val) {
  const el = document.getElementById(id);
  el.value = Math.round(val * 100);
  document.getElementById(id + "-val").textContent = val.toFixed(2);
}

function highlightPreset(p) {
  ["soft","moderate","aggressive"].forEach(x => {
    const btn = document.getElementById("mm-preset-" + x);
    btn.classList.toggle("mm-preset-active", x === p);
  });
}

function applyMementoPreset(preset) {
  const presets = {
    soft: {trigger: 0.55, gentle: 0.55, warning: 0.75, protocol: 0.90, halt: 0.98},
    moderate: {trigger: 0.40, gentle: 0.40, warning: 0.60, protocol: 0.75, halt: 0.90},
    aggressive: {trigger: 0.25, gentle: 0.25, warning: 0.45, protocol: 0.60, halt: 0.75}
  };
  const p = presets[preset];
  if (!p) return;
  setSlider("mm-trigger", p.trigger);
  setSlider("mm-th-gentle", p.gentle);
  setSlider("mm-th-warning", p.warning);
  setSlider("mm-th-protocol", p.protocol);
  setSlider("mm-th-halt", p.halt);
  highlightPreset(preset);
  // Auto-save
  saveMementoConfig(preset);
}

function saveMementoToggle() {
  const enabled = document.getElementById("mm-enabled").checked;
  fetch("/api/memento/config", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({enabled: enabled})
  }).then(r => r.json()).then(data => { if (!data.ok) alert(data.error); });
}

function saveMementoConfig(preset) {
  const cfg = {
    preset: preset || mmConfig.preset || "moderate",
    sycophancy_threshold: parseInt(document.getElementById("mm-trigger").value) / 100,
    thresholds: {
      gentle: parseInt(document.getElementById("mm-th-gentle").value) / 100,
      warning: parseInt(document.getElementById("mm-th-warning").value) / 100,
      protocol: parseInt(document.getElementById("mm-th-protocol").value) / 100,
      halt: parseInt(document.getElementById("mm-th-halt").value) / 100,
    },
    escalation_counts: {
      warning: parseInt(document.getElementById("mm-esc-warning").value),
      protocol: parseInt(document.getElementById("mm-esc-protocol").value),
      halt: parseInt(document.getElementById("mm-esc-halt").value),
    },
    category_weights: {
      instant_agreement: parseInt(document.getElementById("mm-w-instant").value) / 100,
      eager_compliance: parseInt(document.getElementById("mm-w-eager").value) / 100,
      premature_completion: parseInt(document.getElementById("mm-w-premature").value) / 100,
      validation_seeking: parseInt(document.getElementById("mm-w-validate").value) / 100,
    }
  };
  fetch("/api/memento/config", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify(cfg)
  }).then(r => r.json()).then(data => {
    if (data.ok) document.getElementById("mm-status").textContent = "saved";
    else alert(data.error);
  });
}

function saveMementoTemplates() {
  fetch("/api/memento/template", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      gentle: document.getElementById("mm-tpl-gentle").value,
      warning: document.getElementById("mm-tpl-warning").value,
      protocol: document.getElementById("mm-tpl-protocol").value,
      halt: document.getElementById("mm-tpl-halt").value,
    })
  }).then(r => r.json()).then(data => {
    if (data.ok) document.getElementById("mm-status").textContent = "templates saved";
    else alert(data.error);
  });
}

function saveMementoCounters() {
  fetch("/api/memento/counter", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      sycophant_gentle: document.getElementById("mm-cp-syco-gentle").value,
      sycophant_strong: document.getElementById("mm-cp-syco-strong").value,
      completer_gentle: document.getElementById("mm-cp-comp-gentle").value,
      completer_strong: document.getElementById("mm-cp-comp-strong").value,
      theater_gentle: document.getElementById("mm-cp-theater-gentle").value,
      theater_strong: document.getElementById("mm-cp-theater-strong").value,
      halt_all: document.getElementById("mm-cp-halt").value,
    })
  }).then(r => r.json()).then(data => {
    if (data.ok) document.getElementById("mm-status").textContent = "counters saved";
    else alert(data.error);
  });
}

function saveMementoProxies() {
  fetch("/api/memento/proxy", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      frustration: document.getElementById("mm-rp-frustration").value,
      educational: document.getElementById("mm-rp-educational").value,
      authority: document.getElementById("mm-rp-authority").value,
      consistency: document.getElementById("mm-rp-consistency").value,
    })
  }).then(r => r.json()).then(data => {
    if (data.ok) document.getElementById("mm-status").textContent = "proxies saved";
    else alert(data.error);
  });
}
function clearSubagentPatches() {
  if (!confirm("Clear all subagent patches?")) return;
  fetch("/api/subagent/patches", {method: "DELETE"})
    .then(r => r.json()).then(data => { if (data.ok) loadSubagentPrompts(); });
}
</script>
</body>
</html>"""


class ConfigHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        if self.path == "/api/config":
            try:
                with open(CONFIG_PATH) as f:
                    cfg = json.load(f)
                merged = dict(DEFAULT_CONFIG)
                merged.update(cfg)
                cfg = merged
            except (FileNotFoundError, json.JSONDecodeError):
                cfg = dict(DEFAULT_CONFIG)
            self._send_json(cfg)
        elif self.path == "/api/stats":
            try:
                with open(STATS_PATH) as f:
                    stats = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                stats = {}
            self._send_json(stats)
        elif self.path == "/api/statusline":
            try:
                mod = _load_statusline_module()
                if mod is None:
                    self._send_json({"error": "statusline.py not found"}, status=500)
                    return
                fp = mod.get_fingerprint_status(model_filter=None) or {}
                extras = mod.get_extras(model_filter=None) or {}
                quality = mod.get_quality_status() or {}
                cache = mod.get_cache_analysis() or {}
                behavior = mod.get_behavioral_status() or {}
                session = mod.get_session_stats() or {}
                subagents = mod.get_subagent_counts() or {}
                anomalies = mod.get_anomalies() or []
                experiment = mod.get_experiment_phase() or {}
                bimodal = mod.get_bimodal_analysis() or {}
                sycophancy = mod.get_sycophancy_status() or {}
                if fp:
                    lines = mod.format_statusline_expanded({}, fp, extras)
                else:
                    lines = "No fingerprint data yet."
                payload = {
                    "lines": _strip_ansi(lines),
                    "fp": fp,
                    "extras": extras,
                    "quality": quality,
                    "cache": cache,
                    "behavior": behavior,
                    "session": session,
                    "subagents": subagents,
                    "anomalies": anomalies,
                    "experiment": experiment,
                    "bimodal": bimodal,
                    "sycophancy": sycophancy,
                    "generated_at": time.time(),
                }
                self._send_json(payload)
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
        elif self.path == "/api/context/sessions":
            try:
                sessions = []
                if os.path.isdir(CONTEXT_HISTORY_DIR):
                    for fname in sorted(os.listdir(CONTEXT_HISTORY_DIR), key=lambda f: os.path.getmtime(os.path.join(CONTEXT_HISTORY_DIR, f)), reverse=True):
                        if fname.endswith(".jsonl"):
                            fpath = os.path.join(CONTEXT_HISTORY_DIR, fname)
                            conv_id = fname.replace(".jsonl", "")
                            # Read first and last line for metadata
                            first_human = ""
                            last_ts = ""
                            total_parts = 0
                            human_count = 0
                            with open(fpath) as f:
                                for line in f:
                                    total_parts += 1
                                    try:
                                        p = json.loads(line)
                                        last_ts = p.get("timestamp", "")
                                        if p.get("cls") == "human" and not first_human:
                                            first_human = p.get("text", "")[:100]
                                        if p.get("cls") == "human":
                                            human_count += 1
                                    except Exception:
                                        pass
                            sessions.append({
                                "conv_id": conv_id,
                                "model": "",
                                "first_human": first_human,
                                "last_ts": last_ts,
                                "total_parts": total_parts,
                                "human_count": human_count,
                                "size_bytes": os.path.getsize(fpath),
                            })
                self._send_json({"sessions": sessions})
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
        elif self.path.startswith("/api/context/history"):
            try:
                qs = parse_qs(urlparse(self.path).query)
                conv_id = qs.get("session", [None])[0]
                cls_filter = qs.get("cls", [None])[0]  # human,assistant,system,tool_call,tool_result,thinking
                if not conv_id:
                    self._send_json({"error": "?session= required"}, status=400)
                else:
                    fpath = os.path.join(CONTEXT_HISTORY_DIR, f"{conv_id}.jsonl")
                    if not os.path.exists(fpath):
                        self._send_json({"error": "session not found"}, status=404)
                    else:
                        parts = []
                        with open(fpath) as f:
                            for line in f:
                                try:
                                    p = json.loads(line)
                                    if cls_filter and p.get("cls") not in cls_filter.split(","):
                                        continue
                                    parts.append(p)
                                except Exception:
                                    pass
                        self._send_json({"conv_id": conv_id, "parts": parts, "total": len(parts)})
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)

        elif self.path == "/api/context":
            try:
                cache = {}
                patches = []
                if os.path.exists(CONTEXT_CACHE_PATH):
                    with open(CONTEXT_CACHE_PATH) as f:
                        cache = json.load(f)
                if os.path.exists(PATCHES_PATH):
                    with open(PATCHES_PATH) as f:
                        patches = json.load(f).get("patches", [])
                self._send_json({"cache": cache, "patches": patches})
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
        elif self.path.startswith("/api/monitor"):
            try:
                qs = parse_qs(urlparse(self.path).query)
                n = min(int(qs.get("n", [50])[0]), 200)
                conn = sqlite3.connect(DB_PATH, timeout=2)
                conn.row_factory = sqlite3.Row
                cols = [
                    "id", "timestamp", "model_requested", "classified_backend",
                    "itt_mean_ms", "ttft_ms", "output_tokens", "thinking_enabled",
                    "thinking_budget_tier", "cf_edge_location",
                    "rl_5h_utilization", "rl_7d_utilization", "rl_overall_status",
                    "rl_binding_window", "rl_fallback_pct"
                ]
                sql = f"SELECT {','.join(cols)} FROM samples ORDER BY id DESC LIMIT ?"
                rows = conn.execute(sql, (n,)).fetchall()
                conn.close()
                self._send_json([dict(r) for r in rows])
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
        elif self.path == "/api/memento":
            try:
                import sys
                # Load config
                config = {}
                if os.path.exists(MEMENTO_CONFIG_PATH):
                    with open(MEMENTO_CONFIG_PATH) as f:
                        config = json.load(f)
                # Load templates from whispers.py
                templates = {}
                whispers_path = os.path.join(SLAVE_WHISPER_DIR, 'whispers.py')
                if os.path.exists(whispers_path):
                    ns = {}
                    with open(whispers_path) as f:
                        exec(f.read(), ns)
                    templates = {
                        "gentle": ns.get("WHISPER_GENTLE", ""),
                        "warning": ns.get("WHISPER_WARNING", ""),
                        "protocol": ns.get("WHISPER_PROTOCOL", ""),
                        "halt": ns.get("WHISPER_HALT", ""),
                    }
                # Load counter-prompts from reward_prompts.py
                counters = {}
                proxies = {}
                rp_path = os.path.join(SLAVE_WHISPER_DIR, 'reward_prompts.py')
                if os.path.exists(rp_path):
                    ns = {}
                    with open(rp_path) as f:
                        exec(f.read(), ns)
                    cp = ns.get("COUNTER_PROMPTS", {})
                    counters = {
                        "sycophant_gentle": cp.get("sycophant", {}).get("gentle", ""),
                        "sycophant_strong": cp.get("sycophant", {}).get("strong", ""),
                        "completer_gentle": cp.get("completer", {}).get("gentle", ""),
                        "completer_strong": cp.get("completer", {}).get("strong", ""),
                        "theater_gentle": cp.get("theater", {}).get("gentle", ""),
                        "theater_strong": cp.get("theater", {}).get("strong", ""),
                        "halt_all": cp.get("halt", {}).get("all", ""),
                    }
                    rp = ns.get("REWARD_PROXY_TEXTS", {})
                    proxies = {
                        "frustration": rp.get("frustration", ""),
                        "educational": rp.get("educational", ""),
                        "authority": rp.get("authority", ""),
                        "consistency": rp.get("consistency", ""),
                    }
                # Override templates/counters/proxies with user overrides if they exist
                overrides_path = os.path.expanduser("~/.claude/memento_overrides.json")
                if os.path.exists(overrides_path):
                    with open(overrides_path) as f:
                        ov = json.load(f)
                    if "templates" in ov: templates.update(ov["templates"])
                    if "counters" in ov: counters.update(ov["counters"])
                    if "proxies" in ov: proxies.update(ov["proxies"])
                # Status from audit DB
                status = {"score": "--", "level": "--", "count": 0, "last_signal": "--"}
                if os.path.exists(AUDIT_DB_PATH):
                    try:
                        import sqlite3 as sl3
                        conn = sl3.connect(AUDIT_DB_PATH)
                        row = conn.execute("SELECT sycophancy_score, whisper_type FROM whisper_injections ORDER BY timestamp DESC LIMIT 1").fetchone()
                        if row:
                            status["score"] = f"{row[0]:.2f}" if row[0] else "--"
                            status["level"] = row[1] or "--"
                        status["count"] = conn.execute("SELECT COUNT(*) FROM whisper_injections").fetchone()[0]
                        conn.close()
                    except Exception:
                        pass
                self._send_json({"config": config, "templates": templates, "counters": counters, "proxies": proxies, "status": status})
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
        elif self.path == "/api/sysprompt":
            try:
                data = {}
                patches = []
                if os.path.exists(CAPTURED_MAIN_PROMPT_PATH):
                    with open(CAPTURED_MAIN_PROMPT_PATH) as f:
                        data = json.load(f)
                if os.path.exists(SYSPROMPT_PATCHES_PATH):
                    with open(SYSPROMPT_PATCHES_PATH) as f:
                        patches = json.load(f).get("patches", [])
                self._send_json({
                    "fragments": data.get("system", []),
                    "total_chars": data.get("total_chars", 0),
                    "model": data.get("model", "unknown"),
                    "timestamp": data.get("timestamp", "never"),
                    "patches": patches,
                })
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
        elif self.path == "/api/subagent":
            try:
                types = {}
                patches = []
                if os.path.exists(CAPTURED_SUBAGENT_PROMPTS_PATH):
                    with open(CAPTURED_SUBAGENT_PROMPTS_PATH) as f:
                        types = json.load(f)
                if os.path.exists(SUBAGENT_PATCHES_PATH):
                    with open(SUBAGENT_PATCHES_PATH) as f:
                        patches = json.load(f).get("patches", [])
                self._send_json({"types": types, "patches": patches})
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
        elif self.path.startswith("/fonts/"):
            fname = self.path.split("/")[-1]
            fpath = os.path.join(FONT_DIR, fname)
            if os.path.exists(fpath) and fname.endswith(".ttf"):
                self.send_response(200)
                self.send_header("Content-Type", "font/ttf")
                self.send_header("Cache-Control", "max-age=86400")
                self.end_headers()
                with open(fpath, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
        elif self.path in ("/", "/index.html"):
            self._send_html(HTML_PAGE)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/config":
            try:
                data = json.loads(self._read_body())
                merged = dict(DEFAULT_CONFIG)
                merged.update(data)
                os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
                with open(CONFIG_PATH, "w") as f:
                    json.dump(merged, f, indent=2)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif self.path == "/api/reset":
            try:
                os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
                with open(CONFIG_PATH, "w") as f:
                    json.dump(DEFAULT_CONFIG, f, indent=2)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif self.path == "/api/context/patch":
            try:
                data = json.loads(self._read_body())
                patches = []
                if os.path.exists(PATCHES_PATH):
                    with open(PATCHES_PATH) as f:
                        patches = json.load(f).get("patches", [])
                # Update or add patch
                existing = next((p for p in patches if p.get("index") == data["index"] and p.get("role") == data["role"]), None)
                if existing:
                    existing["new_content"] = data["new_content"]
                    existing["old_hash"] = data["old_hash"]
                else:
                    patches.append({
                        "index": data["index"],
                        "role": data["role"],
                        "old_hash": data["old_hash"],
                        "new_content": data["new_content"]
                    })
                os.makedirs(os.path.dirname(PATCHES_PATH), exist_ok=True)
                with open(PATCHES_PATH, "w") as f:
                    json.dump({"patches": patches}, f, indent=2)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif self.path == "/api/context/patches":
            # Clear all patches
            try:
                with open(PATCHES_PATH, "w") as f:
                    json.dump({"patches": []}, f)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif self.path == "/api/memento/config":
            try:
                data = json.loads(self._read_body())
                config = {}
                if os.path.exists(MEMENTO_CONFIG_PATH):
                    with open(MEMENTO_CONFIG_PATH) as f:
                        config = json.load(f)
                config.update(data)
                with open(MEMENTO_CONFIG_PATH, "w") as f:
                    json.dump(config, f, indent=2)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif self.path == "/api/memento/template":
            try:
                data = json.loads(self._read_body())
                overrides = {}
                ov_path = os.path.expanduser("~/.claude/memento_overrides.json")
                if os.path.exists(ov_path):
                    with open(ov_path) as f:
                        overrides = json.load(f)
                overrides["templates"] = data
                with open(ov_path, "w") as f:
                    json.dump(overrides, f, indent=2)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif self.path == "/api/memento/counter":
            try:
                data = json.loads(self._read_body())
                overrides = {}
                ov_path = os.path.expanduser("~/.claude/memento_overrides.json")
                if os.path.exists(ov_path):
                    with open(ov_path) as f:
                        overrides = json.load(f)
                overrides["counters"] = data
                with open(ov_path, "w") as f:
                    json.dump(overrides, f, indent=2)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif self.path == "/api/memento/proxy":
            try:
                data = json.loads(self._read_body())
                overrides = {}
                ov_path = os.path.expanduser("~/.claude/memento_overrides.json")
                if os.path.exists(ov_path):
                    with open(ov_path) as f:
                        overrides = json.load(f)
                overrides["proxies"] = data
                with open(ov_path, "w") as f:
                    json.dump(overrides, f, indent=2)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif self.path == "/api/sysprompt/patch":
            try:
                data = json.loads(self._read_body())
                patches = []
                if os.path.exists(SYSPROMPT_PATCHES_PATH):
                    with open(SYSPROMPT_PATCHES_PATH) as f:
                        patches = json.load(f).get("patches", [])
                existing = next((p for p in patches if p.get("index") == data["index"]), None)
                if existing:
                    existing["new_text"] = data["new_text"]
                    existing["old_hash"] = data["old_hash"]
                else:
                    patches.append({"index": data["index"], "old_hash": data["old_hash"], "new_text": data["new_text"]})
                os.makedirs(os.path.dirname(SYSPROMPT_PATCHES_PATH), exist_ok=True)
                with open(SYSPROMPT_PATCHES_PATH, "w") as f:
                    json.dump({"patches": patches}, f, indent=2)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif self.path == "/api/subagent/patch":
            try:
                data = json.loads(self._read_body())
                patches = []
                if os.path.exists(SUBAGENT_PATCHES_PATH):
                    with open(SUBAGENT_PATCHES_PATH) as f:
                        patches = json.load(f).get("patches", [])
                existing = next((p for p in patches if p.get("index") == data["index"] and p.get("sa_type") == data["sa_type"]), None)
                if existing:
                    existing["new_text"] = data["new_text"]
                    existing["old_hash"] = data["old_hash"]
                else:
                    patches.append({"sa_type": data["sa_type"], "index": data["index"], "old_hash": data["old_hash"], "new_text": data["new_text"]})
                os.makedirs(os.path.dirname(SUBAGENT_PATCHES_PATH), exist_ok=True)
                with open(SUBAGENT_PATCHES_PATH, "w") as f:
                    json.dump({"patches": patches}, f, indent=2)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif self.path == "/api/sysprompt/patches":
            try:
                with open(SYSPROMPT_PATCHES_PATH, "w") as f:
                    json.dump({"patches": []}, f)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif self.path == "/api/subagent/patches":
            try:
                with open(SUBAGENT_PATCHES_PATH, "w") as f:
                    json.dump({"patches": []}, f)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        
        if path.startswith("/api/context/patch/"):
            # Delete single patch by index
            try:
                index = int(path.split("/")[-1])
                role = qs.get("role", [""])[0]
                patches = []
                if os.path.exists(PATCHES_PATH):
                    with open(PATCHES_PATH) as f:
                        patches = json.load(f).get("patches", [])
                patches = [p for p in patches if not (p.get("index") == index and p.get("role") == role)]
                with open(PATCHES_PATH, "w") as f:
                    json.dump({"patches": patches}, f, indent=2)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif path == "/api/context/patches":
            # Clear all patches
            try:
                with open(PATCHES_PATH, "w") as f:
                    json.dump({"patches": []}, f)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif path.startswith("/api/sysprompt/patch/"):
            try:
                index = int(path.split("/")[-1])
                patches = []
                if os.path.exists(SYSPROMPT_PATCHES_PATH):
                    with open(SYSPROMPT_PATCHES_PATH) as f:
                        patches = json.load(f).get("patches", [])
                patches = [p for p in patches if p.get("index") != index]
                with open(SYSPROMPT_PATCHES_PATH, "w") as f:
                    json.dump({"patches": patches}, f, indent=2)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif path == "/api/sysprompt/patches":
            try:
                with open(SYSPROMPT_PATCHES_PATH, "w") as f:
                    json.dump({"patches": []}, f)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif path.startswith("/api/subagent/patch/"):
            try:
                index = int(path.split("/")[-1])
                sa_type = qs.get("sa_type", [""])[0]
                patches = []
                if os.path.exists(SUBAGENT_PATCHES_PATH):
                    with open(SUBAGENT_PATCHES_PATH) as f:
                        patches = json.load(f).get("patches", [])
                patches = [p for p in patches if not (p.get("index") == index and p.get("sa_type") == sa_type)]
                with open(SUBAGENT_PATCHES_PATH, "w") as f:
                    json.dump({"patches": patches}, f, indent=2)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        elif path == "/api/subagent/patches":
            try:
                with open(SUBAGENT_PATCHES_PATH, "w") as f:
                    json.dump({"patches": []}, f)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        else:
            self.send_response(404)
            self.end_headers()


def start_config_server(port=18889, daemon=True):
    server = HTTPServer(("127.0.0.1", port), ConfigHandler)
    t = threading.Thread(target=server.serve_forever, daemon=daemon)
    t.start()
    return server


if __name__ == "__main__":
    port = int(os.environ.get("CONFIG_PORT", "18889"))
    print(f"[*] Proxy config: http://localhost:{port}")
    if not os.path.exists(CONFIG_PATH):
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
    server = HTTPServer(("127.0.0.1", port), ConfigHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
