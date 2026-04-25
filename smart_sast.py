# -*- coding: utf-8 -*-
"""
SMART SAST v2.3 - Colab Optimized with Full RAG Integration
============================================================
Semgrep + LLM Verification + Semantic Analysis + AST
With LIVE PROGRESS REPORTING & Complete RAG Field Utilization

Code website: https://github.com/NLPSaST/SmartSast

RAG Optimizations included:
  ✓ Abstraction-based prompt adaptation
  ✓ DetectionMethods weighted by effectiveness
  ✓ RelatedWeaknesses for search expansion
  ✓ Smart truncation for code examples
  ✓ CommonConsequences.note emphasized
"""

# =========================
# COLAB-OPTIMIZED CONFIG
# =========================
output_filepath = "/content/gdrive/MyDrive/"
rag_folder      = "/content/gdrive/MyDrive/CWE-top25"
INTERIM_SAVE_PATH = "/content/gdrive/MyDrive/.smart_sast_interim"

# Minimum LLM confidence thresholds
SEMGREP_VERIFY_THRESHOLD: int = 70
SEMANTIC_CONFIRM_THRESHOLD: int = 70

# Taint analysis config
TAINT_MAX_HOPS: int = 5
SEMANTIC_PREFILTER_ENABLED: bool = True

# COLAB OPTIMIZATIONS
ENABLE_MEMORY_CLEANUP: bool = True
MEMORY_CLEANUP_INTERVAL: int = 5

USE_QUANTIZED_MODEL: bool = True

SKIP_SEMANTIC_FOR_SMALL_FILES: bool = True
SMALL_FILE_THRESHOLD: int = 500
SKIP_TAINT_IF_NO_INPUT: bool = True

ENABLE_AST_CACHE: bool = True
_AST_CACHE_MAX_SIZE: int = 10

ENABLE_INTERIM_SAVE: bool = True
INTERIM_SAVE_INTERVAL: int = 180

LOAD_RAG_ON_DEMAND: bool = True
RAG_EXPANSION_RADIUS: int = 1

ENABLE_LIVE_REPORTING: bool = True
ENABLE_PARALLEL_CHUNKS: bool = False
MAX_LLM_WORKERS: int = 2

# =========================
# COLAB SETUP
# =========================
from google.colab import drive, output
drive.mount('/content/gdrive/', force_remount=True)
output.enable_custom_widget_manager()

# 🛡️ SECURITY NOTE: The following commands allow auto-updates.
# To use known-safe versions (Tested 2026-04-12):
# !pip install llama-cpp-python==0.3.5 instructor==1.4.2 rapidfuzz==3.9.6
# fmt: off
!pip install google-generativeai
!pip install -U llama-cpp-python
!pip install instructor
!pip install -qU langchain-text-splitters
!pip install rapidfuzz
!pip install pandas
!pip install psutil
!pip install -q "click==8.1.7"
!pip install -q "typer==0.9.4"
!pip install -q "semgrep==1.62.0"
# fmt: on

# =========================
# IMPORTS
# =========================
import ast
import json
import os
import re
import subprocess
import tempfile
import time
import pathlib
import sys
import gc
import hashlib
import threading
from datetime import datetime
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

import torch
import psutil
from rapidfuzz import fuzz

import llama_cpp
from llama_cpp.llama_speculative import LlamaPromptLookupDecoding
import instructor
from pydantic import BaseModel
from huggingface_hub import hf_hub_download, list_repo_files
from langchain_text_splitters import RecursiveCharacterTextSplitter, Language

# =========================
# DEVICE & HARDWARE DETECTION
# =========================
if torch.cuda.is_available():
    device = "cuda"
    gpu_name = torch.cuda.get_device_name(0)
    gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1e9
elif "COLAB_TPU_ADDR" in os.environ:
    device = "tpu"
    gpu_name = "TPU"
    gpu_memory = 8.0
else:
    device = "cpu"
    gpu_name = "CPU"
    gpu_memory = 0.0

ram_gb = psutil.virtual_memory().total / 1e9

print(f"\n{'='*60}")
print(f"🔧 SMART SAST v2.3 - Full RAG Optimization (Hardened)")
print(f"{'='*60}")
print(f"💾 RAM: {ram_gb:.1f} GB")
print(f"🎮 GPU: {gpu_name} ({gpu_memory:.1f} GB VRAM)" if device != "cpu" else "⚠️  Running on CPU (slower)")
print(f"{'='*60}\n")

print("""
╔══════════════════════════════════════════════════════════════╗
║  ⚠️  COLAB RUNTIME WARNINGS                                  ║
╠══════════════════════════════════════════════════════════════╣
║  • Free tier: 12-hour runtime limit                          ║
║  • GPU disconnects after 90 min idle                         ║
║  • Save interim results every 3 minutes!                     ║
║  • Keep browser tab open during analysis                     ║
╚══════════════════════════════════════════════════════════════╝
""")

# =========================
# LIVE PROGRESS REPORTING
# =========================

def flush_print(*args, **kwargs):
    """Print and immediately flush stdout for real-time output."""
    print(*args, **kwargs)
    sys.stdout.flush()


def _count_by_key(items: List[Dict], key: str) -> Dict[str, int]:
    """Count occurrences of a key's value across a list of dicts."""
    counts = defaultdict(int)
    for item in items:
        val = item.get(key, "UNKNOWN")
        if val:
            counts[val] += 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


def print_partial_report(stage: str, step: int, total: int, **kwargs):
    """Print a formatted partial report for the current pipeline stage."""
    if not ENABLE_LIVE_REPORTING:
        return

    bar_len = 40
    filled = int(bar_len * step / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    pct = int(100 * step / total)

    flush_print(f"\n{'='*60}")
    flush_print(f"🔄 SMART SAST v2.3 — Progress: [{bar}] {pct}%")
    flush_print(f"📍 Stage {step}/{total}: {stage}")
    flush_print(f"{'-'*60}")

    if stage == "Semgrep scan" and "semgrep_findings" in kwargs:
        findings = kwargs["semgrep_findings"]
        flush_print(f"✅ Semgrep completed: {len(findings)} raw findings")
        if findings:
            by_severity = _count_by_key(findings, "severity")
            by_cwe = _count_by_key(findings, "cwe")
            flush_print(f"   By severity: {by_severity}")
            flush_print(f"   Top CWEs: {dict(list(by_cwe.items())[:5])}")

    elif stage == "LLM chunk analysis" and "chunks_done" in kwargs:
        flush_print(f"🧠 LLM processing: {kwargs['chunks_done']}/{kwargs['total_chunks']} chunks")
        flush_print(f"   Vulns found so far: {kwargs.get('vulns_found', 0)}")
        if kwargs.get("elapsed_sec"):
            rate = kwargs["chunks_done"] / kwargs["elapsed_sec"]
            eta = (kwargs["total_chunks"] - kwargs["chunks_done"]) / rate if rate > 0 else 0
            flush_print(f"   Speed: {rate:.1f} chunks/sec | ETA: {eta:.0f}s")

    elif stage == "LLM verification" and "verified" in kwargs:
        v, a, r = kwargs["verified"], kwargs["alternatives"], kwargs["rejected"]
        flush_print(f"🔍 Verification complete:")
        flush_print(f"   ✅ Confirmed (≥{SEMGREP_VERIFY_THRESHOLD}%): {len(v)}")
        flush_print(f"   ⚠️  Alternatives found: {len(a)}")
        flush_print(f"   ❌ Rejected: {len(r)}")

    elif stage == "Taint analysis" and "taint_flows" in kwargs:
        intra = kwargs.get("intra_flows", [])
        inter = kwargs.get("inter_flows", [])
        flush_print(f"🔗 Taint analysis complete:")
        flush_print(f"   • Intra-procedural flows: {len(intra)}")
        flush_print(f"   • Inter-procedural flows: {len(inter)}")
        if intra or inter:
            by_cwe = _count_by_key(intra + inter, "cwe")
            flush_print(f"   • Top CWEs in flows: {dict(list(by_cwe.items())[:3])}")

    elif stage == "Semantic analysis" and "semantic_confirmed" in kwargs:
        conf = kwargs["semantic_confirmed"]
        total_sem = kwargs.get("semantic_total", 0)
        flush_print(f"🎯 Semantic analysis complete:")
        flush_print(f"   ✅ Confirmed (≥{SEMANTIC_CONFIRM_THRESHOLD}%): {len(conf)}")
        flush_print(f"   📋 Total raw findings: {total_sem}")
        if conf:
            by_class = _count_by_key(conf, "semantic_class")
            flush_print(f"   • By vulnerability class: {by_class}")

    elif stage == "Merge & AST verification" and "confirmed" in kwargs:
        conf = kwargs["confirmed"]
        extra = kwargs.get("all_extra", [])
        flush_print(f"🧩 Merge & AST verification complete:")
        flush_print(f"   🏆 Final confirmed findings: {len(conf)}")
        flush_print(f"   🗂️  Additional findings (all report): {len(extra)}")
        if conf:
            by_source = defaultdict(int)
            for f in conf:
                src = "semgrep" if f.get("semgrep_confirmed") else \
                      "taint" if f.get("taint_confirmed") else \
                      "semantic" if f.get("semantic_confirmed") else "llm"
                by_source[src] += 1
            flush_print(f"   • By source: {dict(by_source)}")
            by_cwe = _count_by_key(conf, "CWE")
            flush_print(f"   • Top CWEs in final report: {dict(list(by_cwe.items())[:5])}")

    flush_print(f"{'='*60}\n")


# =========================
# MEMORY MANAGEMENT
# =========================

def cleanup_colab_memory():
    """Force garbage collection and clear GPU cache."""
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
        flush_print("🧹 GPU cache cleared")
    flush_print("🧹 Memory cleanup complete")


# =========================
# AST CACHING
# =========================

_AST_CACHE: Dict[str, ast.Module] = {}

def build_ast_index(code: str, cache_key: str = None) -> Optional[ast.Module]:
    """Parse code with optional caching."""
    if ENABLE_AST_CACHE and cache_key and cache_key in _AST_CACHE:
        return _AST_CACHE[cache_key]

    try:
        tree = ast.parse(code)
        if ENABLE_AST_CACHE and cache_key:
            if len(_AST_CACHE) >= _AST_CACHE_MAX_SIZE:
                _AST_CACHE.pop(next(iter(_AST_CACHE)))
            _AST_CACHE[cache_key] = tree
        return tree
    except SyntaxError:
        return None


def clear_ast_cache():
    """Clear AST cache."""
    _AST_CACHE.clear()
    cleanup_colab_memory()


# =========================
# PROGRESSIVE DRIVE SAVES
# =========================

def save_interim_results(output1: dict, stage: str, elapsed: float, last_save: float) -> float:
    """Save partial results to Drive if enough time has passed."""
    if not ENABLE_INTERIM_SAVE:
        return last_save

    if elapsed - last_save >= INTERIM_SAVE_INTERVAL:
        os.makedirs(INTERIM_SAVE_PATH, exist_ok=True)
        interim_path = f"{INTERIM_SAVE_PATH}/interim_{output1['date']}_{stage}.json"

        payload = {
            "stage": stage,
            "elapsed_seconds": elapsed,
            "timestamp": datetime.now().isoformat(),
            "partial_results": {
                "semgrep_count": output1.get("semgrep_findings_count", 0),
                "llm_count": output1.get("llm_findings_count", 0),
                "taint_count": output1.get("taint_intra_count", 0),
                "semantic_count": output1.get("semantic_confirmed_count", 0),
            }
        }

        with open(interim_path, 'w') as f:
            json.dump(payload, f, indent=4)

        flush_print(f"💾 Interim save → {interim_path}")
        return time.time()

    return last_save


# ─────────────────────────────────────────────────────────────────────────────
# 🆕 RAG OPTIMIZATION UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _smart_truncate_example(code: str, max_chars: int = 800) -> str:
    """Smart truncate code preserving syntactic structures."""
    if len(code) <= max_chars:
        return code

    cut_points = []

    last_semicolon = code.rfind(";", 0, max_chars)
    if last_semicolon != -1:
        cut_points.append(last_semicolon + 1)

    last_brace = code.rfind("}", 0, max_chars)
    if last_brace != -1:
        cut_points.append(last_brace + 1)

    last_newline = code.rfind("\n", 0, max_chars - 50)
    if last_newline != -1:
        cut_points.append(last_newline)

    safe_cut = max([cp for cp in cut_points if cp > max_chars * 0.7] or [max_chars])

    return code[:safe_cut] + "\n  # ... [code truncated for brevity] ..."


def _extract_detection_patterns(detection_methods: List[Dict]) -> Dict[str, List[str]]:
    """Extract detectable code patterns from DetectionMethods."""
    patterns = {
        "function_calls": [],
        "dangerous_patterns": [],
        "input_sources": [],
        "safe_patterns": [],
        "config_checks": []
    }

    for dm in detection_methods:
        desc = dm.get("Description", "").lower()

        if "execute" in desc or "query" in desc or "raw()" in desc or "eval" in desc:
            patterns["function_calls"].extend([
                "execute(", "query(", "raw(", "cursor.execute",
                "connection.execute", "db.execute", "eval(", "exec("
            ])

        if "concatenat" in desc or "string format" in desc or "f-string" in desc:
            patterns["dangerous_patterns"].extend([
                'f"', '.format(', '% ', '%s', '%d', '+ input', '+ request', "f'", '.format %'
            ])

        if "user input" in desc or "request." in desc or "input()" in desc or "external" in desc:
            patterns["input_sources"].extend([
                "request.args", "request.form", "request.json",
                "input(", "sys.argv", "os.environ", "request.headers",
                "request.data", "request.values", "stdin"
            ])

        if "parameteriz" in desc or "prepared statement" in desc or "sanitize" in desc:
            patterns["safe_patterns"].extend([
                "execute(?,", "execute(%s,", "parametrize",
                "prepared_statement", "query_params", "sanitize",
                "escape(", "parameterized", "safe_execute"
            ])

        if "config" in desc or "default" in desc or "orm" in desc:
            patterns["config_checks"].extend([
                "USE_PARAMETERIZED", "SAFE_MODE", "SQLALCHEMY_SAFE",
                "parameterized=True", "safe_execute", "ORM_SAFE"
            ])

    for key in patterns:
        patterns[key] = list(set(patterns[key]))

    return patterns


def _format_detection_methods_weighted(detection_methods: List[Dict]) -> str:
    """Format DetectionMethods prioritized by effectiveness."""
    if not detection_methods:
        return ""

    high_eff = [d for d in detection_methods if d.get("effectiveness") == "High"]
    med_eff = [d for d in detection_methods if d.get("effectiveness") == "Medium"]
    low_eff = [d for d in detection_methods if d.get("effectiveness") == "Low"]

    lines = ["\n🔍 Detection Methods (prioritized by effectiveness):"]

    for d in high_eff:
        method = d.get("method", "")
        desc = d.get("description", "")[:150]
        lines.append(f"  🔴 HIGH: {method} - {desc}")

    for d in med_eff:
        method = d.get("method", "")
        desc = d.get("description", "")[:150]
        lines.append(f"  🟡 MED:  {method} - {desc}")

    for d in low_eff:
        method = d.get("method", "")
        desc = d.get("description", "")[:150]
        lines.append(f"  🟢 LOW:  {method} - {desc}")

    if high_eff:
        lines.append("\n⚠️  High-effectiveness detection methods exist. "
                    "If you don't find this vulnerability, explicitly explain why.")

    return "\n".join(lines)


def _get_abstraction_hint(abstraction: str) -> str:
    """Get prompt hint based on CWE abstraction level."""
    hints = {
        "Class": (
            "\n💡 ABSTRACTION NOTE: This is a HIGH-LEVEL vulnerability class. "
            "Look for broad architectural patterns and design issues, not just exact code matches. "
            "Consider multiple manifestations of this vulnerability type."
        ),
        "Base": (
            "\n💡 ABSTRACTION NOTE: This is a SPECIFIC vulnerability type. "
            "Focus on the exact patterns described in the CWE. "
            "Be thorough but precise in your analysis."
        ),
        "Variant": (
            "\n💡 ABSTRACTION NOTE: This is a very SPECIFIC variant. "
            "Check for the exact code pattern described. "
            "False positives are more likely at this level - be strict."
        ),
    }
    return hints.get(abstraction, "")


def _format_rag_block_full(rag_info: dict) -> str:
    """Render RAG entry with ALL fields optimized for LLM consumption."""
    lines = [
        f"\n{'='*60}",
        f"📚 RAG REFERENCE: {rag_info.get('Name', '')} (CWE-{rag_info.get('ID', '')})",
        f"{'='*60}",
        f"Abstraction Level: {rag_info.get('Abstraction', 'Unknown')}",
        f"Description: {rag_info.get('Description', '')}",
        f"Likelihood of Exploit: {rag_info.get('LikelihoodOfExploit', 'N/A')}",
    ]

    abstraction = rag_info.get("Abstraction", "")
    abstraction_hint = _get_abstraction_hint(abstraction)
    if abstraction_hint:
        lines.append(abstraction_hint)

    mitigations = rag_info.get("PotentialMitigations", [])
    if mitigations:
        lines.append("\n🛡️ Potential Mitigations:")
        for m in mitigations:
            phases = ", ".join(m.get("phases", [])) or "N/A"
            desc = m.get("description", "")
            lines.append(f"  [{phases}] {desc}")

    consequences = rag_info.get("CommonConsequences", [])
    if consequences:
        lines.append("\n⚠️ Common Consequences if Exploited:")
        for c in consequences:
            scopes = ", ".join(c.get("scopes", []))
            impacts = ", ".join(c.get("impacts", []))
            note = c.get("note", "")
            lines.append(f"  Scope: {scopes} | Impact: {impacts}")
            if note:
                lines.append(f"    💬 IMPORTANT NOTE: {note}")

    related = rag_info.get("RelatedWeaknesses", [])
    if related:
        lines.append("\n🔗 Related CWEs (also check these if primary not found):")
        child_cwes = []
        for r in related:
            nature = r.get('nature', '?')
            cwe_id = r.get('cwe_id', '')
            lines.append(f"  {nature} CWE-{cwe_id}")
            if nature == "Child":
                child_cwes.append(cwe_id)
        if child_cwes:
            lines.append(f"\n  🔍 Tip: If CWE-{rag_info.get('ID', '')} not found, "
                        f"also check child CWEs: {', '.join(child_cwes[:5])}")

    detection = rag_info.get("DetectionMethods", [])
    if detection:
        lines.append(_format_detection_methods_weighted(detection))

        patterns = _extract_detection_patterns(detection)
        if patterns["input_sources"]:
            lines.append(f"\n  📥 Input Sources to Trace: {', '.join(patterns['input_sources'][:5])}")
        if patterns["function_calls"]:
            lines.append(f"\n  📤 Dangerous Sinks to Check: {', '.join(patterns['function_calls'][:5])}")
        if patterns["safe_patterns"]:
            lines.append(f"\n  ✅ Safe Patterns (if present, likely NOT vulnerable): {', '.join(patterns['safe_patterns'][:3])}")

    demos = rag_info.get("DemonstrativeExamples", [])
    if demos:
        lines.append("\n📋 Known Bad-Code Patterns:")
        for grp in demos:
            intro = grp.get("intro", "")
            if intro:
                lines.append(f"  {intro}")
            for ex in grp.get("examples", []):
                if ex.get("nature", "").lower() == "bad":
                    lang = ex.get("language", "")
                    code = _smart_truncate_example(ex.get("code", "").strip(), max_chars=700)
                    lines.append(f"  [{lang}] ```\n{code}\n```")
                    body = ex.get("body", "")
                    if body:
                        lines.append(f"  → {body[:250]}{'...' if len(body) > 250 else ''}")

    lines.append(f"{'='*60}\n")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# RAG LOADING WITH EXPANSION
# ─────────────────────────────────────────────────────────────────────────────

def _is_nested_rag(data: dict) -> bool:
    """Check if RAG file is already in nested format."""
    pm = data.get("PotentialMitigations")
    return isinstance(pm, list)


def _unflatten_rag(flat: dict) -> dict:
    """Convert flat dot-notation CWE JSON to nested RAG format."""
    def _set(root, keys, value):
        node = root
        for i, key in enumerate(keys[:-1]):
            nk = keys[i + 1]
            is_list = nk.isdigit()
            if key.isdigit():
                idx = int(key)
                while len(node) <= idx:
                    node.append(None)
                if node[idx] is None:
                    node[idx] = [] if is_list else {}
                node = node[idx]
            else:
                if key not in node:
                    node[key] = [] if is_list else {}
                node = node[key]
        last = keys[-1]
        if last.isdigit():
            idx = int(last)
            while len(node) <= idx:
                node.append(None)
            node[idx] = value
        else:
            node[last] = value

    nested: dict = {}
    for dotted_key, value in flat.items():
        parts = dotted_key.split(".")
        if len(parts) == 1:
            nested[dotted_key] = value
        else:
            top = parts[0]
            if top not in nested:
                nested[top] = [] if parts[1].isdigit() else {}
            _set(nested, parts, value)

    def _clean(lst):
        return [x for x in lst if x is not None] if isinstance(lst, list) else []

    mitigations = []
    for item in _clean(nested.get("PotentialMitigations", [])):
        if not isinstance(item, dict):
            continue
        phases_raw = item.get("Phase", [])
        phases = phases_raw if isinstance(phases_raw, list) else [phases_raw]
        mitigations.append({"phases": [p for p in phases if p], "description": item.get("Description", "")})

    demos = []
    for grp in _clean(nested.get("DemonstrativeExamples", [])):
        if not isinstance(grp, dict):
            continue
        examples, intro = [], ""
        for e in _clean(grp.get("Entries", [])):
            if not isinstance(e, dict):
                continue
            if "IntroText" in e:
                intro = e["IntroText"]
            elif "ExampleCode" in e:
                examples.append({"nature": e.get("Nature", ""), "language": e.get("Language", ""), "code": e["ExampleCode"], "body": ""})
            elif "BodyText" in e:
                if examples:
                    examples[-1]["body"] = e["BodyText"]
                else:
                    intro += " " + e["BodyText"]
        demos.append({"id": grp.get("ID", ""), "intro": intro, "examples": examples})

    consequences = []
    for item in _clean(nested.get("CommonConsequences", [])):
        if not isinstance(item, dict):
            continue
        sc = item.get("Scope", [])
        im = item.get("Impact", [])
        consequences.append({"scopes": [s for s in (sc if isinstance(sc, list) else [sc]) if s], "impacts": [i for i in (im if isinstance(im, list) else [im]) if i], "note": item.get("Note", "")})

    related = []
    for item in _clean(nested.get("RelatedWeaknesses", [])):
        if not isinstance(item, dict):
            continue
        related.append({"nature": item.get("Nature", ""), "cwe_id": item.get("CweID", ""), "ordinal": item.get("Ordinal", "")})

    detection = []
    for item in _clean(nested.get("DetectionMethods", [])):
        if not isinstance(item, dict):
            continue
        detection.append({"method": item.get("Method", ""), "description": item.get("Description", ""), "effectiveness": item.get("Effectiveness", "")})

    return {
        "ID": flat.get("ID", ""), "Name": flat.get("Name", ""), "Description": flat.get("Description", ""),
        "LikelihoodOfExploit": flat.get("LikelihoodOfExploit", ""), "Abstraction": flat.get("Abstraction", ""),
        "PotentialMitigations": mitigations, "DemonstrativeExamples": demos,
        "CommonConsequences": consequences, "RelatedWeaknesses": related, "DetectionMethods": detection,
    }


def load_json_vulnerability_data(folder_path=rag_folder):
    """Load all CWE JSON files from folder."""
    vulnerability_db = {}
    if not os.path.exists(folder_path):
        print(f"Warning: RAG folder '{folder_path}' not found.")
        return vulnerability_db

    flat_count = nested_count = err_count = 0

    for filename in sorted(os.listdir(folder_path)):
        if not filename.endswith(".json"):
            continue
        filepath = os.path.join(folder_path, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            if "ID" not in data or not str(data["ID"]).isdigit():
                print(f"  ⚠️  Skipping {filename}: missing or non-numeric 'ID'")
                continue

            if _is_nested_rag(data):
                entry = data
                nested_count += 1
            else:
                entry = _unflatten_rag(data)
                flat_count += 1

            cwe_id = f"CWE-{entry['ID']}"
            vulnerability_db[cwe_id] = entry

        except json.JSONDecodeError:
            print(f"  ❌ Skipping {filename}: JSON decode error")
            err_count += 1
        except Exception as e:
            print(f"  ❌ Error loading {filename}: {e}")
            err_count += 1

    print(f"✔️  Loaded {len(vulnerability_db)} CWE definitions ({nested_count} nested, {flat_count} flat→converted)")
    return vulnerability_db


def load_expanded_rag(found_cwes: Set[str], folder_path: str, expansion_radius: int = 1) -> Dict:
    """Load CWEs found + related CWEs (semantic expansion)."""
    if not LOAD_RAG_ON_DEMAND:
        return load_json_vulnerability_data(folder_path)

    vulnerability_db = {}
    loaded = 0
    skipped = 0
    to_load = set(found_cwes)
    related_to_load = set()

    for cwe in to_load:
        if not cwe or cwe == "UNKNOWN":
            continue
        cwe_id = cwe.replace("CWE-", "")
        filepath = f"{folder_path}/{cwe_id}.json"

        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                entry = _unflatten_rag(data) if not _is_nested_rag(data) else data
                vulnerability_db[cwe] = entry
                loaded += 1

                if expansion_radius > 0:
                    related = entry.get("RelatedWeaknesses", [])
                    for rel in related:
                        rel_cwe = f"CWE-{rel.get('cwe_id', '')}"
                        if rel_cwe not in vulnerability_db and rel_cwe != "CWE-":
                            related_to_load.add(rel_cwe)

            except Exception as e:
                flush_print(f"⚠️  Error loading {filepath}: {e}")
                skipped += 1
        else:
            skipped += 1

    if expansion_radius > 0 and related_to_load:
        flush_print(f"🔗 Expanding RAG: {len(related_to_load)} related CWEs found")
        for rel_cwe in related_to_load:
            if rel_cwe in vulnerability_db:
                continue
            rel_id = rel_cwe.replace("CWE-", "")
            rel_path = f"{folder_path}/{rel_id}.json"
            if os.path.exists(rel_path):
                try:
                    with open(rel_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    entry = _unflatten_rag(data) if not _is_nested_rag(data) else data
                    vulnerability_db[rel_cwe] = entry
                    loaded += 1
                except Exception as e:
                    skipped += 1

    flush_print(f"📚 RAG loaded: {loaded} CWEs (skipped {skipped})")
    return vulnerability_db


# ─────────────────────────────────────────────────────────────────────────────
# SEMGREP INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────

SEMGREP_RULESETS = ["p/python", "p/owasp-top-ten", "p/security-audit", "auto"]

SEMGREP_RULE_TO_CWE: Dict[str, str] = {
    "python.django.security.injection.tainted-sql-string": "CWE-89",
    "python.flask.security.injection.tainted-sql-string": "CWE-89",
    "python.lang.security.audit.subprocess-shell-true": "CWE-78",
    "python.lang.security.audit.os-system-injection": "CWE-78",
    "python.lang.security.audit.eval-detected": "CWE-95",
    "python.lang.security.audit.exec-detected": "CWE-95",
    "python.django.security.injection.xss": "CWE-79",
    "python.flask.security.injection.tainted-html-string": "CWE-79",
    "python.cryptography.security.insecure-hash-algorithms.insecure-hash-algorithm-md5": "CWE-327",
    "python.cryptography.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1": "CWE-327",
    "python.lang.security.hardcoded-temp-file": "CWE-377",
    "generic.secrets.security.detected-generic-secret": "CWE-798",
    "python.lang.security.audit.insecure-pickle": "CWE-502",
    "python.lang.security.audit.dangerous-xml-parser": "CWE-611",
    "python.lang.security.audit.path-traversal": "CWE-22",
}

CWE_TO_AST_NODES: Dict[str, List[str]] = {
    "CWE-78": ["Call"], "CWE-89": ["Call", "JoinedStr"], "CWE-79": ["Call", "JoinedStr"],
    "CWE-95": ["Call"], "CWE-327": ["Call"], "CWE-798": ["Constant", "Assign"],
    "CWE-502": ["Call"], "CWE-611": ["Call"], "CWE-22": ["Call", "JoinedStr"],
    "CWE-20": ["Call"], "CWE-362": ["Call"], "CWE-287": ["Call"],
}

TAINT_SINKS = {
    "subprocess": ["run", "call", "Popen", "check_output", "check_call"],
    "os": ["system", "popen", "execv", "execve", "execvp"],
    "eval": [""], "exec": [""], "open": [""],
    "sqlite3": ["execute", "executemany"], "pickle": ["loads", "load"], "yaml": ["load"],
}


def run_semgrep(file_path: str, rulesets: List[str] = SEMGREP_RULESETS) -> List[Dict]:
    all_findings: List[Dict] = []
    seen_signatures: set = set()

    for ruleset in rulesets:
        cmd = ["semgrep", "--config", ruleset, "--json", "--quiet", file_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode not in (0, 1):
                print(f"[Semgrep] ⚠️  Non-zero exit ({result.returncode}) for '{ruleset}'")
                continue

            data = json.loads(result.stdout)
            for hit in data.get("results", []):
                rule_id = hit.get("check_id", "")
                line_start = hit.get("start", {}).get("line", 0)
                line_end = hit.get("end", {}).get("line", line_start)
                code_text = hit.get("extra", {}).get("lines", "").strip()
                severity = hit.get("extra", {}).get("severity", "UNKNOWN").upper()
                message = hit.get("extra", {}).get("message", "")

                sig = (rule_id, line_start)
                if sig in seen_signatures:
                    continue
                seen_signatures.add(sig)

                cwe = _semgrep_rule_to_cwe(rule_id, hit)

                all_findings.append({
                    "rule_id": rule_id, "cwe": cwe, "severity": severity,
                    "line_start": line_start, "line_end": line_end,
                    "message": message, "code": code_text, "source": "semgrep",
                })

        except subprocess.TimeoutExpired:
            print(f"[Semgrep] ⏱️  Timeout on ruleset '{ruleset}'")
        except json.JSONDecodeError as e:
            print(f"[Semgrep] ❌ JSON parse error: {e}")
        except FileNotFoundError:
            print("[Semgrep] ❌ semgrep not found")
            break

    flush_print(f"[Semgrep] ✅ {len(all_findings)} unique findings across {len(rulesets)} rulesets.")
    return all_findings


def _semgrep_rule_to_cwe(rule_id: str, hit: Dict) -> Optional[str]:
    if rule_id in SEMGREP_RULE_TO_CWE:
        return SEMGREP_RULE_TO_CWE[rule_id]

    tags = hit.get("extra", {}).get("metadata", {}).get("cwe", [])
    if isinstance(tags, list) and tags:
        return tags[0] if tags[0].startswith("CWE-") else f"CWE-{tags[0]}"
    if isinstance(tags, str) and tags:
        return tags if tags.startswith("CWE-") else f"CWE-{tags}"

    rule_lower = rule_id.lower()
    keyword_map = {
        "sql": "CWE-89", "xss": "CWE-79", "shell": "CWE-78", "command": "CWE-78",
        "injection": "CWE-78", "eval": "CWE-95", "exec": "CWE-95", "pickle": "CWE-502",
        "deserializ": "CWE-502", "hardcode": "CWE-798", "secret": "CWE-798",
        "password": "CWE-798", "crypto": "CWE-327", "hash": "CWE-327",
        "path": "CWE-22", "traversal": "CWE-22", "csrf": "CWE-352",
        "ssrf": "CWE-918", "xxe": "CWE-611", "auth": "CWE-287", "race": "CWE-362",
    }
    for kw, cwe in keyword_map.items():
        if kw in rule_lower:
            return cwe
    return None


# ─────────────────────────────────────────────────────────────────────────────
# AST VERIFICATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ASTVerificationResult:
    def __init__(self):
        self.scope_ok: bool = False
        self.reachable: bool = False
        self.cwe_node_ok: bool = False
        self.rule_node_ok: bool = False
        self.scope_name: str = ""
        self.ast_node_type: str = ""
        self.fail_reasons: List[str] = []

    @property
    def passed(self) -> bool:
        return self.scope_ok and self.reachable and self.cwe_node_ok


def _find_scope_for_line(tree: ast.Module, lineno: int) -> Tuple[str, bool]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", start)
            if start <= lineno <= end:
                return node.name, True
    return "<module>", True


def _check_reachability(tree: ast.Module, lineno: int) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            if isinstance(test, ast.Constant) and test.value is False:
                for child in ast.walk(node):
                    if hasattr(child, "lineno") and child.lineno == lineno:
                        return False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_start = node.lineno
            fn_end = getattr(node, "end_lineno", fn_start)
            if not (fn_start <= lineno <= fn_end):
                continue
            for stmt in node.body:
                if isinstance(stmt, (ast.Return, ast.Raise)) and stmt.lineno < lineno:
                    return False
    return True


def _get_ast_node_type_at_line(tree: ast.Module, lineno: int) -> str:
    candidates = []
    for node in ast.walk(tree):
        if getattr(node, "lineno", None) == lineno:
            candidates.append(type(node).__name__)
    priority = ["Call", "JoinedStr", "Assign", "Constant", "Attribute"]
    for p in priority:
        if p in candidates:
            return p
    return candidates[0] if candidates else "Unknown"


def _semgrep_rule_matches_ast_node(rule_id: str, node_type: str) -> bool:
    cwe = SEMGREP_RULE_TO_CWE.get(rule_id) or _semgrep_rule_to_cwe(rule_id, {})
    if cwe:
        expected_nodes = CWE_TO_AST_NODES.get(cwe, [])
        if node_type in expected_nodes:
            return True
    call_keywords = ["injection", "eval", "exec", "shell", "command",
                     "subprocess", "pickle", "deserializ", "sql", "xss"]
    rule_lower = rule_id.lower()
    if node_type == "Call" and any(kw in rule_lower for kw in call_keywords):
        return True
    return False


def verify_finding_with_ast(tree: ast.Module, lineno: int, cwe: Optional[str], rule_id: Optional[str] = None) -> ASTVerificationResult:
    result = ASTVerificationResult()
    scope_name, scope_ok = _find_scope_for_line(tree, lineno)
    result.scope_name = scope_name
    result.scope_ok = scope_ok
    if not scope_ok:
        result.fail_reasons.append("line not found in any scope")

    result.reachable = _check_reachability(tree, lineno)
    if not result.reachable:
        result.fail_reasons.append("line is unreachable (dead code)")

    node_type = _get_ast_node_type_at_line(tree, lineno)
    result.ast_node_type = node_type

    if cwe:
        expected_nodes = CWE_TO_AST_NODES.get(cwe, [])
        if not expected_nodes or node_type in expected_nodes:
            result.cwe_node_ok = True
        else:
            result.cwe_node_ok = False
            result.fail_reasons.append(f"CWE {cwe} expects {expected_nodes}, found '{node_type}'")
    else:
        result.cwe_node_ok = True

    if rule_id:
        result.rule_node_ok = _semgrep_rule_matches_ast_node(rule_id, node_type)
        if not result.rule_node_ok:
            result.fail_reasons.append(f"Rule '{rule_id}' not compatible with AST node '{node_type}'")
    else:
        result.rule_node_ok = True

    return result


# ─────────────────────────────────────────────────────────────────────────────
# TAINT ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

TAINT_SOURCES_PATTERNS = [
    (None, "input"), ("sys", "argv"), ("os", "environ"),
    ("os.environ", "get"), ("request", "args"), ("request", "form"),
    ("request", "json"), ("request", "data"), ("request", "values"),
]


def _node_is_source(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id == "input":
            return True
        if isinstance(func, ast.Attribute):
            for mod, meth in TAINT_SOURCES_PATTERNS:
                if func.attr == meth:
                    if mod is None:
                        return True
                    if isinstance(func.value, ast.Name) and func.value.id == mod:
                        return True
    if isinstance(node, ast.Subscript):
        val = node.value
        if isinstance(val, ast.Attribute):
            if val.attr == "argv" and isinstance(val.value, ast.Name) and val.value.id == "sys":
                return True
            if val.attr == "environ" and isinstance(val.value, ast.Name) and val.value.id == "os":
                return True
    return False


def _node_is_sink(node: ast.AST) -> Optional[str]:
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if isinstance(func, ast.Name) and func.id in ("eval", "exec", "open"):
        return func.id + "()"
    if isinstance(func, ast.Attribute):
        attr = func.attr
        owner_name = ""
        if isinstance(func.value, ast.Name):
            owner_name = func.value.id
        for mod, methods in TAINT_SINKS.items():
            if owner_name == mod and (attr in methods or methods == [""]):
                return f"{mod}.{attr}()"
    return None


def trace_taint_flows(code: str, file_path: str) -> List[Dict]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    flows: List[Dict] = []
    lines = code.splitlines()

    def _line_text(lineno: int) -> str:
        idx = lineno - 1
        return lines[idx].strip() if 0 <= idx < len(lines) else ""

    def _analyse_body(stmts: List[ast.stmt]):
        tainted_vars: Dict[str, int] = {}
        source_lines: Dict[str, str] = {}

        for stmt in stmts:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Assign):
                    if _node_is_source(node.value):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                tainted_vars[target.id] = node.lineno
                                source_lines[target.id] = _line_text(node.lineno)

                if isinstance(node, (ast.AugAssign, ast.AnnAssign)):
                    val = getattr(node, "value", None)
                    if val and _node_is_source(val):
                        target = node.target if hasattr(node, "target") else getattr(node, "target", None)
                        if target and isinstance(target, ast.Name):
                            tainted_vars[target.id] = node.lineno
                            source_lines[target.id] = _line_text(node.lineno)

                sink_desc = _node_is_sink(node)
                if sink_desc:
                    arg_names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
                    tainted_args = arg_names & set(tainted_vars.keys())
                    for var in tainted_args:
                        sink_lineno = getattr(node, "lineno", 0)
                        cwe = _infer_cwe_from_sink(sink_desc)
                        flows.append({
                            "source_line": tainted_vars[var],
                            "source_code": source_lines[var],
                            "sink_line": sink_lineno,
                            "sink_code": _line_text(sink_lineno),
                            "sink_desc": sink_desc,
                            "var_name": var,
                            "cwe": cwe,
                            "source": "taint_analysis",
                        })

    try:
        _analyse_body(tree.body)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _analyse_body(node.body)
    except Exception as e:
        print(f"[Taint] ⚠️  Error: {e}")

    return flows


def _infer_cwe_from_sink(sink_desc: str) -> str:
    mapping = {
        "subprocess": "CWE-78", "os.system": "CWE-78", "os.popen": "CWE-78",
        "os.execv": "CWE-78", "eval()": "CWE-95", "exec()": "CWE-95",
        "open()": "CWE-22", "execute": "CWE-89", "pickle": "CWE-502", "yaml.load": "CWE-502",
    }
    for kw, cwe in mapping.items():
        if kw in sink_desc:
            return cwe
    return "CWE-20"


def file_has_user_input(code: str) -> bool:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if _node_is_source(node):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# LLM VERIFICATION (with Full RAG)
# ─────────────────────────────────────────────────────────────────────────────

class SemgrepVerification(BaseModel):
    confirmed: bool
    confidence: int
    reasoning: str
    alternative_cwe: str
    alternative_name: str
    corrected_description: str


def _get_scope_code(file_lines: List[str], lineno: int, tree: Optional[ast.Module]) -> str:
    if tree:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start = node.lineno
                end = getattr(node, "end_lineno", start)
                if start <= lineno <= end:
                    return "".join(file_lines[start - 1:end])
    start = max(0, lineno - 20)
    end = min(len(file_lines), lineno + 20)
    return "".join(file_lines[start:end])


def _build_verification_prompt_full(sf: Dict, scope_code: str, rag_info: Optional[Dict]) -> str:
    """Build verification prompt with FULL RAG optimization."""
    rag_block = _format_rag_block_full(rag_info) if rag_info else ""

    return (
        "~~[INST] <>\n"
        "You are an expert cybersecurity code reviewer.\n"
        "A static analysis tool (Semgrep) flagged the following code.\n"
        "Your task is to answer TWO questions explicitly:\n\n"
        "  QUESTION 1 – Verify the reported finding:\n"
        f"    Rule     : {sf['rule_id']}\n"
        f"    CWE      : {sf.get('cwe', 'UNKNOWN')}\n"
        f"    Message  : {sf['message']}\n"
        f"    Flagged snippet:\n```\n{sf['code']}\n```\n"
        "  Is this vulnerability ACTUALLY present in context? "
        "Answer confirmed=true only if you are certain the risk is real.\n\n"
        "  QUESTION 2 – Independent scan:\n"
        "  Regardless of your answer to Q1, does the surrounding code "
        "contain ANY OTHER known vulnerability?\n"
        "  If yes, populate alternative_cwe and alternative_name.\n\n"
        f"Full function / scope containing the flagged line:\n```\n{scope_code}\n```\n"
        f"{rag_block}\n"
        "Return your answer as a JSON object with these exact fields:\n"
        "  confirmed (bool), confidence (0-100), reasoning (string),\n"
        "  alternative_cwe (string or ''), alternative_name (string or ''),\n"
        "  corrected_description (string or '')\n"
        "[/INST]"
    )


def verify_semgrep_findings_with_llm(
    semgrep_findings: List[Dict], file_lines: List[str], tree: Optional[ast.Module],
    vulnerability_data: Dict, threshold: int = SEMGREP_VERIFY_THRESHOLD,
) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    verified: List[Dict] = []
    alternatives: List[Dict] = []
    rejected: List[Dict] = []

    total = len(semgrep_findings)
    for i, sf in enumerate(semgrep_findings):
        flush_print(f"[Verify] 🔎 {i + 1}/{total} – {sf['rule_id']}")

        lineno = sf["line_start"]
        scope_code = _get_scope_code(file_lines, lineno, tree)
        cwe = sf.get("cwe")
        rag_info = vulnerability_data.get(cwe) if cwe else None
        prompt = _build_verification_prompt_full(sf, scope_code, rag_info)

        llm_ver: Optional[SemgrepVerification] = None
        try:
            llm_ver = create(
                response_model=instructor.Partial[SemgrepVerification],
                messages=[{"role": "user", "content": prompt}],
                stream=False,
            )
        except Exception as e:
            flush_print(f"[Verify] ⚠️  LLM call failed for {sf['rule_id']}: {e}")
            sf_copy = dict(sf)
            sf_copy["llm_verification"] = {
                "confirmed": False, "confidence": 0,
                "reasoning": f"LLM call failed: {e}",
                "alternative_cwe": "", "alternative_name": "",
                "corrected_description": "", "error": True,
            }
            sf_copy["semgrep_rejected_by_llm"] = True
            rejected.append(sf_copy)
            continue

        ver_dict = llm_ver.model_dump() if llm_ver else {}
        sf_enriched = dict(sf)
        sf_enriched["llm_verification"] = ver_dict

        confirmed_flag = ver_dict.get("confirmed", False)
        confidence = int(ver_dict.get("confidence", 0))

        if confirmed_flag and confidence >= threshold:
            sf_enriched["llm_confirmed"] = True
            sf_enriched["llm_confidence"] = confidence
            sf_enriched["semgrep_verified_by_llm"] = True
            corrected = ver_dict.get("corrected_description", "").strip()
            if corrected:
                sf_enriched["message"] = corrected
            flush_print(f"[Verify] ✅ CONFIRMED  (confidence={confidence})")
            verified.append(sf_enriched)
        else:
            alt_cwe = ver_dict.get("alternative_cwe", "").strip()
            alt_name = ver_dict.get("alternative_name", "").strip()
            if alt_cwe or alt_name:
                sf_enriched["llm_alternative_finding"] = True
                sf_enriched["semgrep_rejected_by_llm"] = False
                sf_enriched["llm_confirmed"] = False
                sf_enriched["llm_confidence"] = confidence
                flush_print(f"[Verify] ⚠️  REJECTED original, alternative found: {alt_cwe} {alt_name}")
                alternatives.append(sf_enriched)
            else:
                sf_enriched["semgrep_rejected_by_llm"] = True
                sf_enriched["llm_alternative_finding"] = False
                sf_enriched["llm_confirmed"] = False
                sf_enriched["llm_confidence"] = confidence
                flush_print(f"[Verify] ❌ REJECTED  (confidence={confidence})")
                rejected.append(sf_enriched)

    flush_print(f"\n[Verify] Summary → ✅ {len(verified)} | ⚠️  {len(alternatives)} | ❌ {len(rejected)}")
    return verified, alternatives, rejected


# ─────────────────────────────────────────────────────────────────────────────
# INTER-PROCEDURAL TAINT
# ─────────────────────────────────────────────────────────────────────────────

def _build_call_graph(tree: ast.Module) -> Dict[str, List[str]]:
    defined: set = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defined.add(node.name)
    graph: Dict[str, List[str]] = defaultdict(list)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        caller = node.name
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func = child.func
                callee = None
                if isinstance(func, ast.Name):
                    callee = func.id
                elif isinstance(func, ast.Attribute):
                    callee = func.attr
                if callee and callee in defined and callee != caller:
                    if callee not in graph[caller]:
                        graph[caller].append(callee)
    return dict(graph)


def trace_interprocedural_taint(code: str, file_lines: List[str], tree: ast.Module, max_hops: int = TAINT_MAX_HOPS) -> List[Dict]:
    flows: List[Dict] = []
    lines_text = file_lines
    call_graph = _build_call_graph(tree)
    rev_graph: Dict[str, List[str]] = defaultdict(list)
    for caller, callees in call_graph.items():
        for callee in callees:
            rev_graph[callee].append(caller)

    func_nodes: Dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_nodes[node.name] = node

    tainted_returns: set = set()
    for fname, fnode in func_nodes.items():
        fn_lines = lines_text[fnode.lineno - 1:getattr(fnode, "end_lineno", fnode.lineno)]
        fn_code = "".join(fn_lines)
        try:
            fn_tree = ast.parse(fn_code)
        except SyntaxError:
            continue
        has_source = any(_node_is_source(n) for n in ast.walk(fn_tree))
        if has_source:
            tainted_returns.add(fname)

    frontier = set(tainted_returns)
    for _ in range(max_hops):
        new_frontier: set = set()
        for tainted_fn in frontier:
            for caller in rev_graph.get(tainted_fn, []):
                if caller not in tainted_returns:
                    caller_node = func_nodes.get(caller)
                    if caller_node is None:
                        continue
                    caller_src = "".join(lines_text[caller_node.lineno - 1:getattr(caller_node, "end_lineno", caller_node.lineno)])
                    try:
                        c_tree = ast.parse(caller_src)
                    except SyntaxError:
                        continue
                    for node in ast.walk(c_tree):
                        sink = _node_is_sink(node)
                        if sink:
                            sink_line = caller_node.lineno + getattr(node, "lineno", 1) - 1
                            flows.append({
                                "source_line": None,
                                "source_code": f"return value of {tainted_fn}()",
                                "sink_line": sink_line,
                                "sink_code": lines_text[sink_line - 1].strip() if 0 < sink_line <= len(lines_text) else "",
                                "sink_desc": sink,
                                "var_name": f"{tainted_fn}() return",
                                "cwe": _infer_cwe_from_sink(sink),
                                "source": "interprocedural_taint",
                                "call_chain": [tainted_fn, caller],
                            })
                    tainted_returns.add(caller)
                    new_frontier.add(caller)
        if not new_frontier:
            break
        frontier = new_frontier
    return flows


# ─────────────────────────────────────────────────────────────────────────────
# LLM SEMANTIC ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

class SemanticFinding(BaseModel):
    vulnerability_class: str
    vulnerability_name: str
    cwe: str
    confidence: int
    reasoning: str
    vulnerable_code: str
    lines_hint: str
    solution: str


class SemanticAnalysisResult(BaseModel):
    findings: List[SemanticFinding]


_SEMANTIC_PREFILTERS: Dict[str, List[str]] = {
    "interprocedural_taint": ["input(", "request.", "argv", "environ", "stdin", "subprocess", "os.system", "eval(", "exec(", "execute(", "pickle", "yaml.load"],
    "business_logic": ["role", "permission", "plan", "subscription", "discount", "price", "quantity", "limit", "quota", "admin", "privilege", "access", "tier", "free", "paid", "credit"],
    "auth_authz": ["login", "logout", "authenticate", "authorize", "token", "session", "cookie", "jwt", "bearer", "password", "auth", "require_login", "login_required", "@login", "current_user", "is_authenticated", "permission_required"],
    "second_order_injection": ["INSERT", "UPDATE", "SELECT", "execute(", "executemany(", "render_template", "render(", "innerHTML", "dangerouslySet", "db.save", "db.add", "session[", ".save(", "commit()"],
    "crypto_misuse": ["md5", "sha1", "des", "rc4", "ecb", "random(", "rand(", "hashlib", "Cipher", "AES", "RSA", "hmac", "salt", "password", "encrypt", "decrypt", "key", "iv", "nonce"],
    "ssrf": ["requests.get", "requests.post", "urllib", "httpx", "http.client", "fetch(", "curl", "url", "endpoint", "webhook", "callback", "redirect", "forward"],
}


def _chunk_needs_semantic(chunk_code: str, prefilter_enabled: bool) -> Dict[str, bool]:
    if not prefilter_enabled:
        return {cls: True for cls in _SEMANTIC_PREFILTERS}
    code_lower = chunk_code.lower()
    result = {}
    for cls, patterns in _SEMANTIC_PREFILTERS.items():
        result[cls] = any(p.lower() in code_lower for p in patterns)
    return result


def _build_semantic_prompt(chunk_code: str, active_classes: Dict[str, bool], meta: Dict) -> str:
    class_descriptions = {
        "interprocedural_taint": "INTER-PROCEDURAL TAINT / CODE INJECTION (CWE-78, CWE-89, CWE-95)\n  Does user-controlled input flow into a dangerous sink?",
        "business_logic": "BUSINESS LOGIC FLAWS (CWE-840)\n  Are there inconsistencies in access control, pricing, quotas?",
        "auth_authz": "AUTH / AUTHORISATION GAPS (CWE-285, CWE-306)\n  Is any route missing authentication or authorisation?",
        "second_order_injection": "SECOND-ORDER INJECTION (CWE-89, CWE-79)\n  Is user data stored and later used unsanitised?",
        "crypto_misuse": "CRYPTOGRAPHIC MISUSE (CWE-327, CWE-330)\n  Are weak algorithms or PRNGs used?",
        "ssrf": "SSRF (CWE-918)\n  Is a URL constructed from user input used in outbound requests?",
    }
    active_descriptions = "\n\n".join(f"[{i+1}] {class_descriptions[cls]}" for i, cls in enumerate(class_descriptions) if active_classes.get(cls, False))
    scope_hint = ""
    if meta.get("function_name"):
        scope_hint = f"  Scope: function '{meta['function_name']}' (lines {meta.get('start_line','?')}–{meta.get('end_line','?')})\n"
    return (
        "~~[INST] <>\n"
        "You are an expert cybersecurity code auditor.\n\n"
        f"{scope_hint}"
        "Analyse the following code chunk for ALL of these vulnerability classes:\n\n"
        f"{active_descriptions}\n\n"
        "Code to analyse:\n"
        f"```\n{chunk_code}\n```\n\n"
        "Rules:\n"
        "  • Only report findings you are genuinely confident about.\n"
        "  • vulnerable_code must be the exact lines that are dangerous.\n"
        "  • If nothing found, return findings=[].\n"
        "Return a JSON object: {\"findings\": [ … ]}\n"
        "[/INST]"
    )


def run_semantic_analysis(code_split: List, vulnerability_data: Dict, prefilter_enabled: bool = SEMANTIC_PREFILTER_ENABLED, threshold: int = SEMANTIC_CONFIRM_THRESHOLD) -> Tuple[List[Dict], List[Dict]]:
    confirmed_semantic: List[Dict] = []
    all_semantic: List[Dict] = []
    total = len(code_split)
    skipped = 0

    for i, doc in enumerate(code_split):
        chunk_code = doc.page_content
        meta = getattr(doc, "metadata", {}) or {}
        active = _chunk_needs_semantic(chunk_code, prefilter_enabled)
        if not any(active.values()):
            skipped += 1
            continue
        active_names = [c for c, v in active.items() if v]
        flush_print(f"[Semantic] chunk {i+1}/{total} → checking: {', '.join(active_names)}")
        prompt = _build_semantic_prompt(chunk_code, active, meta)
        try:
            result = create(response_model=instructor.Partial[SemanticAnalysisResult], messages=[{"role": "user", "content": prompt}], stream=False)
            findings = result.findings if result and result.findings else []
        except Exception as e:
            flush_print(f"[Semantic] ⚠️  LLM error on chunk {i+1}: {e}")
            findings = []
        for f in findings:
            fd = f.model_dump() if hasattr(f, "model_dump") else dict(f)
            fd["chunk_index"] = i
            fd["chunk_meta"] = meta
            fd["source"] = "llm_semantic"
            fd["rag_cwe_file"] = _rag_cwe_filename(fd.get("cwe"), vulnerability_data) if vulnerability_data else None
            all_semantic.append(fd)
            if int(fd.get("confidence", 0)) >= threshold:
                confirmed_semantic.append(fd)

    flush_print(f"[Semantic] ✅ {len(confirmed_semantic)} confirmed | 📋 {len(all_semantic)} total | ⏭️  {skipped} skipped")
    return confirmed_semantic, all_semantic


def _semantic_to_finding(fd: Dict) -> Dict:
    lines_hint = fd.get("lines_hint", "unknown")
    line_num = None
    m = re.search(r"\d+", str(lines_hint))
    if m:
        line_num = int(m.group())
    meta = fd.get("chunk_meta", {}) or {}
    if line_num is None and meta.get("start_line"):
        line_num = meta["start_line"]
    return {
        "CWE": fd.get("cwe", "UNKNOWN"),
        "CWSS": fd.get("confidence", 50) / 10.0,
        "Description": fd.get("reasoning", ""),
        "Vulnerable_code": fd.get("vulnerable_code", ""),
        "lines_range": [line_num] if line_num else [],
        "Solution": fd.get("solution", ""),
        "semgrep_confirmed": False,
        "llm_confirmed": True,
        "semantic_confirmed": True,
        "semantic_class": fd.get("vulnerability_class", ""),
        "llm_confidence": fd.get("confidence", 0),
        "rag_cwe_file": fd.get("rag_cwe_file"),
        "ast_passed": None,
        "ast_reasons": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# MERGE LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def _llm_finding_line(vuln: Dict) -> Optional[int]:
    lr = vuln.get("lines_range", [])
    if not lr:
        return None
    first = lr[0]
    if isinstance(first, int):
        return first
    if isinstance(first, str):
        part = first.split("-")[0]
        return int(part) if part.isdigit() else None
    return None


def _copy_text_context_fields(source: Dict, target: Dict) -> None:
    for key in source:
        if isinstance(key, str) and key.startswith("text"):
            target[key] = source[key]


def _normalize_lines_range(lr) -> tuple:
    if not lr:
        return ()
    result = []
    for item in lr if isinstance(lr, (list, tuple)) else [lr]:
        if isinstance(item, int):
            result.append(item)
        elif isinstance(item, str) and "-" in item:
            result.append(item)
        elif isinstance(item, str) and item.isdigit():
            result.append(int(item))
    return tuple(sorted(result, key=lambda x: (isinstance(x, str), x)))


def merge_findings(llm_vulns: List[Dict], semgrep_verified: List[Dict], semgrep_alts: List[Dict], semgrep_rejected: List[Dict], taint_flows: List[Dict], interprocedural_flows: List[Dict], semantic_confirmed: List[Dict], tree: Optional[ast.Module], file_path: str, file_lines: List[str]) -> Tuple[List[Dict], List[Dict]]:
    confirmed: List[Dict] = []
    all_extra: List[Dict] = []

    for sf in semgrep_verified:
        lineno = sf["line_start"]
        cwe = sf.get("cwe")
        ast_res = verify_finding_with_ast(tree, lineno, cwe, rule_id=sf["rule_id"]) if tree else None
        finding = {
            "CWE": cwe or "UNKNOWN",
            "CWSS": _severity_to_cwss(sf["severity"]),
            "Description": sf.get("llm_verification", {}).get("corrected_description", "") or sf["message"],
            "Vulnerable_code": sf["code"],
            "lines_range": [lineno] if sf["line_start"] == sf["line_end"] else [f"{sf['line_start']}-{sf['line_end']}"],
            "Solution": "",
            "semgrep_confirmed": True,
            "semgrep_rule_id": sf["rule_id"],
            "llm_confirmed": True,
            "llm_confidence": sf.get("llm_confidence", 0),
            "semgrep_verified_by_llm": True,
            "llm_verification": sf.get("llm_verification", {}),
        }
        _copy_text_context_fields(sf, finding)
        if ast_res:
            finding["ast_scope"] = ast_res.scope_name
            finding["ast_node_type"] = ast_res.ast_node_type
            finding["ast_passed"] = ast_res.passed
            finding["ast_reasons"] = ast_res.fail_reasons
        confirmed.append(finding)

    for vuln in llm_vulns:
        lineno = _llm_finding_line(vuln)
        cwe = vuln.get("CWE")
        ast_res = verify_finding_with_ast(tree, lineno, cwe, rule_id=None) if tree and lineno else None
        if ast_res:
            vuln["ast_scope"] = ast_res.scope_name
            vuln["ast_node_type"] = ast_res.ast_node_type
            vuln["ast_passed"] = ast_res.passed
            vuln["ast_reasons"] = ast_res.fail_reasons
        vuln["semgrep_confirmed"] = False
        vuln["llm_confirmed"] = True
        vuln["discard_reason"] = "llm_only_no_semgrep_confirm"
        _copy_text_context_fields(vuln, vuln)
        all_extra.append(vuln)

    for sf in semgrep_alts:
        sf["source"] = "llm_alternative"
        all_extra.append(sf)
    for sf in semgrep_rejected:
        sf["source"] = "semgrep_rejected_by_llm"
        all_extra.append(sf)

    for flow in taint_flows:
        finding = {
            "CWE": flow["cwe"],
            "CWSS": _cwe_default_cwss(flow["cwe"]),
            "Description": f"User-controlled variable '{flow['var_name']}' (line {flow['source_line']}) reaches {flow['sink_desc']} at line {flow['sink_line']}",
            "Vulnerable_code": flow["sink_code"],
            "lines_range": [flow["sink_line"]],
            "Solution": "Validate and sanitise all user-supplied input.",
            "semgrep_confirmed": False,
            "llm_confirmed": False,
            "taint_confirmed": True,
            "taint_type": "intraprocedural",
            "taint_source_line": flow["source_line"],
        }
        sink_line = flow["sink_line"]
        if file_lines and sink_line:
            start = max(0, sink_line - 4)
            end = min(len(file_lines), sink_line + 3)
            finding["text1"] = "".join(file_lines[start:end])
        confirmed.append(finding)

    for flow in interprocedural_flows:
        finding = {
            "CWE": flow["cwe"],
            "CWSS": _cwe_default_cwss(flow["cwe"]) + 0.5,
            "Description": f"Tainted data flows through {' -> '.join(flow.get('call_chain', []))} to {flow['sink_desc']} at line {flow['sink_line']}",
            "Vulnerable_code": flow["sink_code"],
            "lines_range": [flow["sink_line"]],
            "Solution": "Validate input at each function entry point.",
            "semgrep_confirmed": False,
            "llm_confirmed": False,
            "taint_confirmed": True,
            "taint_type": "interprocedural",
            "call_chain": flow.get("call_chain", []),
        }
        sink_line = flow["sink_line"]
        if file_lines and sink_line:
            start = max(0, sink_line - 4)
            end = min(len(file_lines), sink_line + 3)
            finding["text1"] = "".join(file_lines[start:end])
        confirmed.append(finding)

    for fd in semantic_confirmed:
        finding = _semantic_to_finding(fd)
        ln = finding["lines_range"][0] if finding["lines_range"] and isinstance(finding["lines_range"][0], int) else None
        if tree and ln:
            ast_res = verify_finding_with_ast(tree, ln, finding["CWE"], rule_id=None)
            if ast_res:
                finding["ast_passed"] = ast_res.passed
                finding["ast_reasons"] = ast_res.fail_reasons
                finding["ast_node_type"] = ast_res.ast_node_type
                finding["ast_scope"] = ast_res.scope_name
        if ln and file_lines:
            start = max(0, ln - 4)
            end = min(len(file_lines), ln + 3)
            finding["text1"] = "".join(file_lines[start:end])
        confirmed.append(finding)

    flush_print(f"[Merge] confirmed={len(confirmed)} | all_extra={len(all_extra)}")
    return confirmed, all_extra


def _severity_to_cwss(severity: str) -> float:
    return {"CRITICAL": 9.0, "ERROR": 7.5, "WARNING": 5.0, "INFO": 2.5, "UNKNOWN": 0.0}.get(severity.upper(), 0.0)


def _cwe_default_cwss(cwe: str) -> float:
    defaults = {"CWE-78": 8.5, "CWE-89": 8.5, "CWE-79": 7.0, "CWE-95": 8.0, "CWE-502": 7.5, "CWE-22": 6.5, "CWE-327": 5.0, "CWE-798": 7.0, "CWE-20": 5.5}
    return defaults.get(cwe, 5.0)


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def _file_info_block(output1: dict) -> dict:
    return {
        "date": output1.get("date"),
        "file_name": output1.get("file_name"),
        "file_extension": output1.get("file_extension"),
        "path_file": output1.get("path_file"),
        "analysis duration": output1.get("analisis duration"),
        "risk_level [in progress]": output1.get("risk [in progress]"),
        "cwss_average [in progress]:": output1.get("cwss_average [in progress]"),
    }


def _dedup_vulnerabilities(vulns: List[Dict]) -> Tuple[List[Dict], dict, dict, set]:
    duplicates: dict = defaultdict(list)
    unique_cwes: set = set()
    for vuln in vulns:
        vname = vuln.get("CWE", "UNNAMED")
        cwe = vuln.get("CWE", "UNKNOWN")
        unique_cwes.add(cwe)
        sig = (vname, vuln.get("Vulnerable_code", ""), _normalize_lines_range(vuln.get("lines_range", [])))
        duplicates[sig].append(vuln)
    real_dups: dict = {str(k): v for k, v in duplicates.items() if len(v) > 1}
    final_list: list = []
    seen_exact: set = set()
    for sig, entries in duplicates.items():
        sig_str = str(sig)
        if len(entries) == 1:
            final_list.append(entries[0])
        elif sig_str not in seen_exact:
            final_list.append(entries[0])
            seen_exact.add(sig_str)
    name_dups_raw: dict = defaultdict(list)
    for vuln in vulns:
        vname = vuln.get("CWE", "UNNAMED")
        sig = (vname, vuln.get("Vulnerable_code", ""), _normalize_lines_range(vuln.get("lines_range", [])))
        if len(duplicates[sig]) == 1:
            name_dups_raw[vname].append(vuln)
    name_dups = {k: v for k, v in name_dups_raw.items() if len(v) > 1}
    return final_list, real_dups, name_dups, unique_cwes


def _stats_block(all_vulns: List[Dict], final_list: List[Dict], real_dups: dict, name_dups: dict, unique_cwes: set) -> dict:
    return {
        "total_vulnerabilities": len(all_vulns),
        "unique_cwe_ids": len(unique_cwes),
        "exact_duplicates": sum(len(v) - 1 for v in real_dups.values()),
        "name_duplicates": sum(len(v) - 1 for v in name_dups.values()),
        "clean_vulnerabilities_count": len(final_list),
    }


def build_final_report(output1: dict) -> dict:
    vulns = output1.get("vulnerabilities", [])
    final_list, real_dups, name_dups, unique_cwes = _dedup_vulnerabilities(vulns)
    clean_entries = []
    for v in final_list:
        entry = {
            "CWE": v.get("CWE", "UNKNOWN"),
            "CWSS": v.get("CWSS", 0.0),
            "lines_range": v.get("lines_range", []),
            "Description": v.get("Description", ""),
            "Solution": v.get("Solution", ""),
            "found_by": _found_by_label(v),
            "ast_passed": v.get("ast_passed", None),
            "ast_reasons": v.get("ast_reasons", []),
        }
        for k, val in v.items():
            if k.startswith("text"):
                entry[k] = val
        clean_entries.append(entry)
    return {
        "file_info": _file_info_block(output1),
        "cleaned_vulnerabilities": clean_entries,
        "stats": _stats_block(vulns, final_list, real_dups, name_dups, unique_cwes),
        "exact_duplicates": real_dups,
        "name_duplicates": name_dups,
    }


def _found_by_label(v: dict) -> str:
    by_semgrep = v.get("semgrep_confirmed", False)
    by_llm = v.get("llm_confirmed", True)
    by_taint = v.get("taint_confirmed", False)
    sources = []
    if by_semgrep:
        sources.append("semgrep")
    if by_llm:
        sources.append("llm")
    if by_taint:
        sources.append("taint_analysis")
    return " + ".join(sources) if sources else "unknown"


def build_all_report(output1: dict, semgrep_verified: List[Dict], semgrep_alts: List[Dict], semgrep_rejected: List[Dict], llm_vulns_raw: List[Dict], taint_flows: List[Dict], interprocedural_flows: List[Dict], all_semantic: List[Dict], vulnerability_data: Dict) -> dict:
    entries: List[Dict] = []
    for sf in semgrep_verified:
        ver = sf.get("llm_verification", {})
        cwe = sf.get("cwe", "UNKNOWN")
        entries.append({
            "source": "both", "CWE": cwe, "CWSS": _severity_to_cwss(sf["severity"]),
            "lines_range": [sf["line_start"]] if sf["line_start"] == sf["line_end"] else [f"{sf['line_start']}-{sf['line_end']}"],
            "Description": ver.get("corrected_description", "") or sf["message"],
            "Solution": "", "Vulnerable_code": sf["code"],
            "semgrep_rule_id": sf["rule_id"], "semgrep_severity": sf["severity"],
            "rag_cwe_file": _rag_cwe_filename(cwe, vulnerability_data),
            "llm_verification": ver, "llm_confidence": sf.get("llm_confidence", 0),
            "ast_passed": sf.get("ast_passed", None), "ast_reasons": sf.get("ast_reasons", []),
            "ast_node_type": sf.get("ast_node_type", ""), "ast_scope": sf.get("ast_scope", ""),
        })
    for sf in semgrep_alts:
        ver = sf.get("llm_verification", {})
        entries.append({
            "source": "semgrep_alternative",
            "CWE": ver.get("alternative_cwe", sf.get("cwe", "UNKNOWN")),
            "CWSS": _severity_to_cwss(sf["severity"]),
            "lines_range": [sf["line_start"]] if sf["line_start"] == sf["line_end"] else [f"{sf['line_start']}-{sf['line_end']}"],
            "Description": ver.get("reasoning", ""), "Solution": "", "Vulnerable_code": sf["code"],
            "semgrep_rule_id": sf["rule_id"], "semgrep_original_cwe": sf.get("cwe", "UNKNOWN"),
            "semgrep_severity": sf["severity"],
            "rag_cwe_file": _rag_cwe_filename(ver.get("alternative_cwe"), vulnerability_data),
            "llm_verification": ver, "llm_alternative_finding": True,
            "llm_confidence": sf.get("llm_confidence", 0),
        })
    for sf in semgrep_rejected:
        ver = sf.get("llm_verification", {})
        entries.append({
            "source": "semgrep_rejected", "CWE": sf.get("cwe", "UNKNOWN"),
            "CWSS": _severity_to_cwss(sf["severity"]),
            "lines_range": [sf["line_start"]] if sf["line_start"] == sf["line_end"] else [f"{sf['line_start']}-{sf['line_end']}"],
            "Description": sf["message"], "Solution": "", "Vulnerable_code": sf["code"],
            "semgrep_rule_id": sf["rule_id"], "semgrep_severity": sf["severity"],
            "rag_cwe_file": None, "llm_verification": ver,
            "semgrep_rejected_by_llm": True, "llm_confidence": sf.get("llm_confidence", 0),
            "llm_reasoning": ver.get("reasoning", ""),
        })
    for v in llm_vulns_raw:
        entries.append({
            "source": "llm_only", "CWE": v.get("CWE", "UNKNOWN"), "CWSS": v.get("CWSS", 0.0),
            "lines_range": v.get("lines_range", []), "Description": v.get("Description", ""),
            "Solution": v.get("Solution", ""), "Vulnerable_code": v.get("Vulnerable_code", ""),
            "semgrep_rule_id": None, "semgrep_severity": None,
            "rag_cwe_file": _rag_cwe_filename(v.get("CWE"), vulnerability_data),
            "llm_verification": None, "ast_passed": v.get("ast_passed", None),
            "ast_reasons": v.get("ast_reasons", []), "ast_node_type": v.get("ast_node_type", ""),
            "ast_scope": v.get("ast_scope", ""),
        })
    for flow in taint_flows:
        entries.append({
            "source": "taint_analysis", "CWE": flow["cwe"], "CWSS": _cwe_default_cwss(flow["cwe"]),
            "lines_range": [flow["sink_line"]],
            "Description": f"Variable '{flow['var_name']}' from line {flow['source_line']} reaches {flow['sink_desc']} at line {flow['sink_line']}",
            "Solution": "Validate and sanitise all user-supplied input.",
            "Vulnerable_code": flow["sink_code"], "semgrep_rule_id": None, "semgrep_severity": None,
            "rag_cwe_file": None, "llm_verification": None,
            "taint_source_line": flow["source_line"], "ast_passed": None, "ast_reasons": [],
        })
    for flow in interprocedural_flows:
        entries.append({
            "source": "interprocedural_taint", "CWE": flow["cwe"],
            "CWSS": _cwe_default_cwss(flow["cwe"]) + 0.5, "lines_range": [flow["sink_line"]],
            "Description": f"Tainted data flows through {' -> '.join(flow.get('call_chain', []))} to {flow['sink_desc']} at line {flow['sink_line']}",
            "Solution": "Validate input at each function entry point.",
            "Vulnerable_code": flow["sink_code"], "semgrep_rule_id": None,
            "rag_cwe_file": None, "llm_verification": None, "call_chain": flow.get("call_chain", []),
        })
    for fd in all_semantic:
        entries.append({
            "source": "llm_semantic", "CWE": fd.get("cwe", "UNKNOWN"),
            "CWSS": fd.get("confidence", 50) / 10.0, "lines_range": [],
            "Description": fd.get("reasoning", ""), "Solution": fd.get("solution", ""),
            "Vulnerable_code": fd.get("vulnerable_code", ""), "semgrep_rule_id": None,
            "rag_cwe_file": fd.get("rag_cwe_file"), "llm_verification": None,
            "llm_confidence": fd.get("confidence", 0),
            "semantic_class": fd.get("vulnerability_class", ""),
            "semantic_confirmed": fd.get("confidence", 0) >= SEMANTIC_CONFIRM_THRESHOLD,
        })
    unique_cwes = {e.get("CWE", "UNKNOWN") for e in entries}
    stats = {
        "total_findings": len(entries),
        "confirmed_by_both": sum(1 for e in entries if e["source"] == "both"),
        "semgrep_alternative": sum(1 for e in entries if e["source"] == "semgrep_alternative"),
        "semgrep_rejected": sum(1 for e in entries if e["source"] == "semgrep_rejected"),
        "llm_only": sum(1 for e in entries if e["source"] == "llm_only"),
        "taint_analysis": sum(1 for e in entries if e["source"] == "taint_analysis"),
        "interprocedural_taint": sum(1 for e in entries if e["source"] == "interprocedural_taint"),
        "llm_semantic": sum(1 for e in entries if e["source"] == "llm_semantic"),
        "llm_semantic_confirmed": sum(1 for e in entries if e["source"] == "llm_semantic" and e.get("semantic_confirmed")),
        "unique_cwe_ids": len(unique_cwes),
    }
    return {"file_info": _file_info_block(output1), "all_findings": entries, "stats": stats}


def _rag_cwe_filename(cwe: Optional[str], vulnerability_data: Dict) -> Optional[str]:
    if not cwe or cwe not in vulnerability_data:
        return None
    cwe_id = cwe.replace("CWE-", "")
    return f"{cwe_id}.json"


def print_analysis_report(final_report: dict):
    print("\n─────────── Report ───────────")
    fi = final_report.get("file_info", {})
    st = final_report.get("stats", {})
    print(f"File       : {fi.get('file_name')}{fi.get('file_extension', '')}")
    print(f"Risk Level : {fi.get('risk_level [in progress]')}")
    print(f"Avg CWSS   : {fi.get('cwss_average [in progress]:'):.2f}" if fi.get('cwss_average [in progress]:') else "Avg CWSS   : 0.00")
    print(f"Duration   : {fi.get('analysis duration')}s")
    print(f"Findings   : {st.get('clean_vulnerabilities_count', st.get('total_findings', 0))} (total raw: {st.get('total_vulnerabilities', st.get('total_findings', 0))})")
    print(f"Unique CWEs: {st.get('unique_cwe_ids', 0)}")
    print("──────────────────────────────")


def save_out(output1: dict, all_extra: List[Dict], semgrep_verified: List[Dict], semgrep_alts: List[Dict], semgrep_rejected: List[Dict], llm_vulns_raw: List[Dict], taint_flows: List[Dict], interprocedural_flows: List[Dict], all_semantic: List[Dict]) -> Tuple[str, str]:
    rag_used = "RAG" if vulnerability_data else "noRAG"
    ts = output1["date"]
    fname = output1["file_name"]
    base = f"{ts}-smart_sast_2_0_5"
    final_report = build_final_report(output1)
    p_final = f"{output_filepath}{base}-final-{device}-{rag_used}-{fname}.json"
    with open(p_final, "w") as f:
        json.dump(final_report, f, indent=4)
    flush_print(f"[Output] 💾 Final report → {p_final}")
    all_report = build_all_report(output1, semgrep_verified, semgrep_alts, semgrep_rejected, llm_vulns_raw, taint_flows, interprocedural_flows, all_semantic, vulnerability_data)
    p_all = f"{output_filepath}{base}-all-{device}-{rag_used}-{fname}.json"
    with open(p_all, "w") as f:
        json.dump(all_report, f, indent=4)
    flush_print(f"[Output] 💾 All findings → {p_all}")
    print_analysis_report(final_report)
    return p_final, p_all


def analyze_vulnerability_duplicates_and_clean(json_data: dict) -> dict:
    return build_final_report(json_data)


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def is_null_or_empty(obj):
    if obj is None:
        return True
    elif isinstance(obj, str):
        return len(obj.strip()) == 0
    elif isinstance(obj, (list, tuple)):
        return len(obj) == 0
    elif isinstance(obj, dict):
        return all(is_null_or_empty(v) for v in obj.values())
    return False


def find_null_objects(objects):
    return [i for i, obj in enumerate(objects) if is_null_or_empty(obj)]


def extract_objects(objects, null_indices):
    extracted, prev_index = [], -1
    for index in null_indices:
        if index - prev_index > 1:
            extracted.append(objects[index - 1])
        prev_index = index
    return extracted


def clean_extracted_objects(extracted_objects):
    result = []
    for obj in extracted_objects:
        if obj.get("lines_range"):
            result.append(obj)
        else:
            print("No matches found")
    return result


def condense_consecutive_numbers(numbers):
    result, start, end = [], None, None
    for num in sorted(numbers):
        if start is None:
            start = end = num
        elif num == end + 1:
            end = num
        else:
            result.append(f"{start}-{end}" if start != end else start)
            start = end = num
    if start is not None:
        result.append(f"{start}-{end}" if start != end else start)
    return result


def find_partial_matches(file_path, search_string, threshold=98):
    line_numbers = []
    with open(file_path, "r") as f:
        text = f.read()
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if fuzz.partial_ratio(line.strip(), search_string) >= threshold:
            line_numbers.append(i + 1)
    return line_numbers


def find_partial_matches_in_lines(file_lines, search_string, threshold=98, start_line=None, end_line=None):
    if not file_lines:
        return []
    if start_line is None or end_line is None:
        iterable = enumerate(file_lines, start=1)
    else:
        start_line = max(1, start_line)
        end_line = min(len(file_lines), end_line)
        iterable = enumerate(file_lines[start_line - 1:end_line], start=start_line)
    line_numbers = []
    for i, line in iterable:
        if fuzz.partial_ratio(line.strip(), search_string) >= threshold:
            line_numbers.append(i)
    return line_numbers


def extract_code_lines(file_lines, start_line, end_line, file_extension=".py"):
    extracted, in_mc = [], False
    comment_starts = {".java": "//", ".py": "#", ".cpp": "//", ".c": "//", ".php": "//", ".js": "//"}
    comment_start = comment_starts.get(file_extension, "//")
    for lc, line in enumerate(file_lines, start=1):
        s = line.strip()
        if s.startswith("/*"):
            in_mc = True
        if "*/" in s:
            in_mc = False
        if in_mc or s.startswith(comment_start) or not s:
            continue
        if start_line <= lc <= end_line:
            extracted.append(line.rstrip())
        elif lc > end_line:
            break
    return "\n".join(extracted)


def classify_value(value):
    value = min(value, 10)
    if value == 0.0:
        return "None"
    elif value <= 3.9:
        return "Low"
    elif value <= 6.9:
        return "Medium"
    elif value <= 8.9:
        return "High"
    else:
        return "Critical"


def _validate_finding(data: dict) -> bool:
    """Reject malformed LLM outputs before pipeline ingestion."""
    if not isinstance(data, dict):
        return False
    # Strict schema check
    if not all(k in data for k in ("CWE", "lines_range", "Vulnerable_code", "CWSS")):
        return False
    if not isinstance(data["CWE"], str) or not (data["CWE"].startswith("CWE-") or data["CWE"] == "UNKNOWN"):
        return False
    cwss = data.get("CWSS", 0.0)
    if not isinstance(cwss, (int, float)) or not (0.0 <= cwss <= 10.0):
        return False
    lr = data.get("lines_range", [])
    if not isinstance(lr, (list, tuple)):
        return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# CODE SPLITTING
# ─────────────────────────────────────────────────────────────────────────────

def code_splitter(code, file_extension, size, overlap):
    language_mapping = {
        ".py": Language.PYTHON, ".java": Language.JAVA, ".cpp": Language.CPP,
        ".c": Language.C, ".cs": Language.CSHARP, ".go": Language.GO,
        ".php": Language.PHP, ".ks": Language.KOTLIN, ".kts": Language.KOTLIN,
        ".rb": Language.RUBY, ".rs": Language.RUST, ".scala": Language.SCALA,
        ".swift": Language.SWIFT, ".html": Language.HTML, ".lua": Language.LUA,
    }
    lang = language_mapping.get(file_extension, Language.JAVA)
    splitter = RecursiveCharacterTextSplitter.from_language(language=lang, chunk_size=size, chunk_overlap=overlap)
    return splitter.create_documents([code])


def python_function_splitter(code, file_path, size=3000, overlap=100):
    lines = code.splitlines()
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        print(f"⚠️ SyntaxError in {file_path}: {e}. Falling back to generic chunking.")
        return code_splitter(code, ".py", size=size, overlap=overlap)
    docs = []
    splitter = RecursiveCharacterTextSplitter.from_language(language=Language.PYTHON, chunk_size=size, chunk_overlap=overlap)

    def get_segment(start, end):
        return "\n".join(lines[max(start - 1, 0):min(end, len(lines))])

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not hasattr(node, "end_lineno"):
                continue
            func_docs = splitter.create_documents([get_segment(node.lineno, node.end_lineno)])
            for d in func_docs:
                d.metadata = d.metadata or {}
                d.metadata.update({"file_path": file_path, "function_name": node.name, "start_line": node.lineno, "end_line": node.end_lineno})
            docs.extend(func_docs)
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not hasattr(child, "end_lineno"):
                        continue
                    func_docs = splitter.create_documents([get_segment(child.lineno, child.end_lineno)])
                    for d in func_docs:
                        d.metadata = d.metadata or {}
                        d.metadata.update({"file_path": file_path, "class_name": node.name, "function_name": child.name, "start_line": child.lineno, "end_line": child.end_lineno})
                    docs.extend(func_docs)
    if not docs:
        return code_splitter(code, ".py", size=size, overlap=overlap)
    return docs


# ─────────────────────────────────────────────────────────────────────────────
# LLM ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

class Risk(BaseModel):
    CWE: str
    CWSS: float
    Description: str
    Vulnerable_code: str
    lines_range: str
    Solution: str


def extract_cwe_code(code_snippet, vulnerability_data: Dict):
    cwe_mapping = {
        "SQL Injection": "CWE-89", "OS Command Injection": "CWE-78",
        "Cross-Site Scripting": "CWE-79", "Buffer Overflow": "CWE-120",
        "Hardcoded Credentials": "CWE-798", "Insecure Deserialization": "CWE-502",
        "Improper Input Validation": "CWE-20", "Race Condition": "CWE-362",
        "Path Traversal": "CWE-22", "Weak Cryptography": "CWE-327",
    }
    for keyword, cwe in cwe_mapping.items():
        if keyword.lower() in code_snippet.lower():
            return cwe
    if vulnerability_data:
        for cwe_id, info in vulnerability_data.items():
            if (fuzz.partial_ratio(info.get("Name", "").lower(), code_snippet.lower()) > 80 or
                    fuzz.partial_ratio(info.get("Description", "").lower(), code_snippet.lower()) > 80):
                return cwe_id
    return None


def code_analysis(code_split, vulnerability_data: Dict, num_chunks):
    all_vulnerabilities = []
    for i, doc in enumerate(code_split):
        cwe_code = extract_cwe_code(doc.page_content, vulnerability_data)
        vulnerability_info = vulnerability_data.get(cwe_code) if cwe_code else None

        vuln_info_str = ""
        if vulnerability_info:
            mits = vulnerability_info.get("PotentialMitigations", [])
            mits_str = "; ".join(f"[{', '.join(m.get('phases', []))}] {m.get('description', '')}" for m in mits if isinstance(m, dict)) or "N/A"
            cons = vulnerability_info.get("CommonConsequences", [])
            cons_str = "; ".join(f"scope={','.join(c.get('scopes',[]))} impact={','.join(c.get('impacts',[]))}" for c in cons if isinstance(c, dict)) or "N/A"
            demos = vulnerability_info.get("DemonstrativeExamples", [])
            ex_parts = []
            for grp in demos:
                if not isinstance(grp, dict):
                    continue
                for ex in grp.get("examples", []):
                    if ex.get("nature", "").lower() == "bad":
                        ex_parts.append(f"[{ex.get('language','')}] {ex.get('code','').strip()[:300]}")
                    if len(ex_parts) >= 2:
                        break
                if len(ex_parts) >= 2:
                    break
            examples_str = "\n".join(ex_parts) or "N/A"
            related = vulnerability_info.get("RelatedWeaknesses", [])
            related_str = ", ".join(f"{r.get('nature','')} CWE-{r.get('cwe_id','')}" for r in related if isinstance(r, dict)) or "N/A"
            vuln_info_str = (
                f"Vulnerability  : {vulnerability_info.get('Name', 'N/A')}\n"
                f"Description    : {vulnerability_info.get('Description', 'N/A')}\n"
                f"Likelihood     : {vulnerability_info.get('LikelihoodOfExploit', 'N/A')}\n"
                f"Consequences   : {cons_str}\n"
                f"Related CWEs   : {related_str}\n"
                f"Mitigations    : {mits_str}\n"
                f"Bad-code examples:\n{examples_str}\n"
            )

        try:
            extraction = create(
                response_model=instructor.Partial[Risk],
                messages=[{"role": "user", "content": f"~~[INST] <> You are a cybersecurity AI program.\nList all identified vulnerabilities and security risks in the following code.\nVulnerability database info: {vuln_info_str}\nCode: {doc.page_content} [/INST]"}],
                stream=False,
            )
            items = extraction if isinstance(extraction, list) else [extraction]
            for item in items:
                obj = item.model_dump()

                # 🛡️ SECURITY PATCH: Validate LLM Output
                if not _validate_finding(obj):
                    flush_print(f"⚠️  LLM Validation Failed for finding in chunk {i}. Raw: {obj}")
                    # Fallback to default values
                    obj = {
                        "CWE": "UNKNOWN",
                        "CWSS": 5.0,
                        "Description": "LLM output invalid, fallback applied.",
                        "Vulnerable_code": "N/A",
                        "lines_range": [],
                        "Solution": "Manual review required.",
                        "vulnerability_details": vulnerability_info,
                        "__doc_metadata__": getattr(doc, "metadata", {}) or {}
                    }
                    all_vulnerabilities.append(obj)
                else:
                    if vulnerability_info:
                        obj["vulnerability_details"] = {
                            "name": vulnerability_info.get("Name"),
                            "description": vulnerability_info.get("Description"),
                            "mitigations": vulnerability_info.get("PotentialMitigations", []),
                            "consequences": vulnerability_info.get("CommonConsequences", []),
                            "related_cwes": vulnerability_info.get("RelatedWeaknesses", []),
                            "detection": vulnerability_info.get("DetectionMethods", []),
                        }
                    obj["__doc_metadata__"] = getattr(doc, "metadata", {}) or {}
                    all_vulnerabilities.append(obj)

        except Exception as e:
            print(f"❌ LLM inference error: {e}")

    return all_vulnerabilities


def cwss_eval(extracted_objects, file_lines):
    total_cwss = []
    total_lines = len(file_lines)
    for i, obj in enumerate(extracted_objects):
        line_ranges = obj.get("lines_range")
        if not line_ranges:
            continue
        total_cwss.append(obj.get("CWSS", 0.0))
        processed_ranges = []

        if isinstance(line_ranges, str):
            try:
                # 🛡️ SECURITY PATCH: Replaced eval() with ast.literal_eval()
                parsed = ast.literal_eval(line_ranges)
                if isinstance(parsed, int):
                    processed_ranges = [(parsed, parsed)]
                elif isinstance(parsed, list):
                    for r in parsed:
                        if isinstance(r, int):
                            processed_ranges.append((r, r))
                        elif isinstance(r, str) and "-" in r:
                            p = r.split("-")
                            if len(p) == 2 and p[0].isdigit() and p[1].isdigit():
                                processed_ranges.append((int(p[0]), int(p[1])))
            except (ValueError, SyntaxError):
                # Safe parse failed (e.g. invalid syntax), treat as empty
                processed_ranges = []
        elif isinstance(line_ranges, (list, tuple)):
            for r in line_ranges:
                if isinstance(r, int):
                    processed_ranges.append((r, r))
                elif isinstance(r, str) and "-" in r:
                    p = r.split("-")
                    if len(p) == 2 and p[0].isdigit() and p[1].isdigit():
                        processed_ranges.append((int(p[0]), int(p[1])))

        for j, (start, end) in enumerate(processed_ranges, start=1):
            start = max(1, start - 3)
            end = min(total_lines, end + 3)
            obj[f"text{j}"] = extract_code_lines(file_lines, start, end)
    return total_cwss, extracted_objects


# ─────────────────────────────────────────────────────────────────────────────
# CORE: analyze_file
# ─────────────────────────────────────────────────────────────────────────────

def file_analyzed(path):
    fn_ext = os.path.basename(path)
    fn, ext = os.path.splitext(fn_ext)
    return [fn, ext, os.path.dirname(path)]


def sanitize_google_drive_path(user_input_path, allowed_base_path="/content/gdrive/MyDrive"):
    """Secure path sanitization preventing directory traversal via symlinks."""
    if not isinstance(user_input_path, str):
        print("❌ Input is not a string.")
        return None
    try:
        # 🛡️ SECURITY PATCH: Resolve symlinks with realpath
        real_path = os.path.realpath(os.path.abspath(os.path.expanduser(user_input_path)))
        real_base = os.path.realpath(allowed_base_path)
        # Strict containment check
        if not (real_path.startswith(real_base + os.sep) or real_path == real_base):
            print(f"❌ Path must be under: {allowed_base_path}\n   Got: {real_path}")
            return None
        if not os.path.exists(real_path):
            print(f"❌ Path does not exist: {real_path}")
            return None
        return real_path
    except (OSError, ValueError) as e:
        print(f"❌ Path sanitization error: {e}")
        return None


def path_identity(filepath):
    if os.path.exists(filepath):
        if os.path.isdir(filepath):
            return "directory"
        elif os.path.isfile(filepath):
            return "file"
    return None


def file_to_analyze(file_path, num, vulnerability_data):
    flush_print(f"Analyzing: {file_path}")
    file_path = sanitize_google_drive_path(file_path)
    if not file_path:
        flush_print("❌ Skipping: invalid or inaccessible path.")
        return None
    return analyze_file(file_path, vulnerability_data)


def list_files_by_extension(directory, extensions):
    found = []
    for fn in os.listdir(directory):
        fp = os.path.join(directory, fn)
        if os.path.isfile(fp) and any(fn.endswith(ext) for ext in extensions):
            found.append(fp)
    return found


def analyze_file(file_path: str, vulnerability_data: Dict) -> Dict:
    file_name, file_extension, path_file = file_analyzed(file_path)
    rag_enabled = bool(vulnerability_data)

    with open(file_path, "r") as f:
        file_lines = f.readlines()
    code = "".join(file_lines)

    start_time = time.time()
    last_save_time = time.time()
    stage_start = time.time()

    # STEP 1: Semgrep
    flush_print("\n[Pipeline] Step 1/6 - Semgrep scan ...")
    semgrep_findings = run_semgrep(file_path)
    print_partial_report(stage="Semgrep scan", step=1, total=6, semgrep_findings=semgrep_findings)

    # Selective RAG loading (only CWEs found by Semgrep + expansion)
    found_cwes = {f["cwe"] for f in semgrep_findings if f.get("cwe")}
    vulnerability_data = load_expanded_rag(found_cwes, rag_folder, expansion_radius=RAG_EXPANSION_RADIUS)

    last_save_time = save_interim_results({
        "date": datetime.now().strftime("%Y%m%d%H%M%S"),
        "semgrep_findings_count": len(semgrep_findings),
    }, "semgrep", time.time() - start_time, last_save_time)
    stage_start = time.time()

    # STEP 2: LLM analysis
    flush_print("\n[Pipeline] Step 2/6 - LLM analysis ...")
    if file_extension == ".py":
        code_split = python_function_splitter(code, file_path, size=3000, overlap=100)
    else:
        code_split = code_splitter(code, file_extension, size=3000, overlap=100)
    num_chunks = len(code_split)

    file_line_count = len(file_lines)
    flush_print(f"📊 File stats: {file_line_count} lines, {len(code)} chars")

    llm_vulns_raw = code_analysis(code_split, vulnerability_data, num_chunks)

    llm_vulns: List[Dict] = []
    for i, vuln in enumerate(llm_vulns_raw):
        search_str = vuln.get("Vulnerable_code", "")
        if not search_str:
            continue
        meta = vuln.get("__doc_metadata__", {}) or {}
        start_hint = meta.get("start_line")
        end_hint = meta.get("end_line")
        if start_hint and end_hint:
            lines_found = find_partial_matches_in_lines(file_lines, search_str, threshold=98, start_line=start_hint, end_line=end_hint)
        else:
            lines_found = find_partial_matches(file_path, search_str)
        if lines_found:
            vuln["lines_range"] = condense_consecutive_numbers(lines_found)
            llm_vulns.append(vuln)

        if ENABLE_MEMORY_CLEANUP and (i + 1) % MEMORY_CLEANUP_INTERVAL == 0:
            cleanup_colab_memory()
            flush_print(f"💾 Checkpoint: {i+1}/{len(llm_vulns_raw)} chunks processed")

    if llm_vulns_raw:
        null_indices = find_null_objects(llm_vulns_raw)
        processed = extract_objects(llm_vulns_raw, null_indices)
        seen_lr = {id(v) for v in llm_vulns}
        for v in processed:
            if id(v) not in seen_lr:
                llm_vulns.append(v)

    print_partial_report(stage="LLM chunk analysis", step=2, total=6, chunks_done=num_chunks, total_chunks=num_chunks, vulns_found=len(llm_vulns), elapsed_sec=time.time() - stage_start)
    last_save_time = save_interim_results({
        "date": datetime.now().strftime("%Y%m%d%H%M%S"),
        "llm_findings_count": len(llm_vulns),
    }, "llm_analysis", time.time() - start_time, last_save_time)
    stage_start = time.time()

    tree: Optional[ast.Module] = None
    if file_extension == ".py":
        ast_cache_key = f"{file_path}_{os.path.getmtime(file_path)}"
        tree = build_ast_index(code, cache_key=ast_cache_key)

    # STEP 3: LLM verification
    flush_print(f"\n[Pipeline] Step 3/6 - LLM verification of {len(semgrep_findings)} Semgrep finding(s) ...")
    semgrep_verified, semgrep_alts, semgrep_rejected = verify_semgrep_findings_with_llm(
        semgrep_findings, file_lines, tree, vulnerability_data, threshold=SEMGREP_VERIFY_THRESHOLD,
    )
    print_partial_report(stage="LLM verification", step=3, total=6, verified=semgrep_verified, alternatives=semgrep_alts, rejected=semgrep_rejected)
    last_save_time = save_interim_results({
        "date": datetime.now().strftime("%Y%m%d%H%M%S"),
        "semgrep_verified_count": len(semgrep_verified),
    }, "llm_verification", time.time() - start_time, last_save_time)
    stage_start = time.time()

    # STEP 4: Taint analysis
    flush_print("\n[Pipeline] Step 4/6 - Taint analysis ...")
    taint_flows: List[Dict] = []
    interprocedural_flows: List[Dict] = []

    if SKIP_TAINT_IF_NO_INPUT and not file_has_user_input(code):
        flush_print("⚡ Early exit: No user input sources - skipping taint analysis")
    else:
        if file_extension == ".py":
            if file_has_user_input(code):
                flush_print("[Taint] User-input sources detected - tracing intra-procedural flows ...")
                taint_flows = trace_taint_flows(code, file_path)
                flush_print(f"[Taint] {len(taint_flows)} intra-procedural flows found.")
            if tree:
                flush_print("[Taint] Building call graph for inter-procedural analysis ...")
                interprocedural_flows = trace_interprocedural_taint(code, file_lines, tree, max_hops=TAINT_MAX_HOPS)
                flush_print(f"[Taint] {len(interprocedural_flows)} inter-procedural flows found.")
        else:
            flush_print("[Taint] Non-Python file - skipping taint analysis.")

    print_partial_report(stage="Taint analysis", step=4, total=6, taint_flows=taint_flows, intra_flows=taint_flows, inter_flows=interprocedural_flows)
    last_save_time = save_interim_results({
        "date": datetime.now().strftime("%Y%m%d%H%M%S"),
        "taint_intra_count": len(taint_flows),
        "taint_inter_count": len(interprocedural_flows),
    }, "taint_analysis", time.time() - start_time, last_save_time)
    stage_start = time.time()

    # STEP 5: Semantic analysis
    flush_print(f"\n[Pipeline] Step 5/6 - LLM semantic analysis ({len(code_split)} chunks, pre-filter={'ON' if SEMANTIC_PREFILTER_ENABLED else 'OFF'}) ...")

    if SKIP_SEMANTIC_FOR_SMALL_FILES and file_line_count < SMALL_FILE_THRESHOLD:
        if len(semgrep_findings) == 0 and not file_has_user_input(code):
            flush_print("⚡ Early exit: Small clean file - skipping semantic analysis")
            semantic_confirmed, all_semantic = [], []
        else:
            semantic_confirmed, all_semantic = run_semantic_analysis(code_split, vulnerability_data, prefilter_enabled=SEMANTIC_PREFILTER_ENABLED, threshold=SEMANTIC_CONFIRM_THRESHOLD)
    else:
        semantic_confirmed, all_semantic = run_semantic_analysis(code_split, vulnerability_data, prefilter_enabled=SEMANTIC_PREFILTER_ENABLED, threshold=SEMANTIC_CONFIRM_THRESHOLD)

    print_partial_report(stage="Semantic analysis", step=5, total=6, semantic_confirmed=semantic_confirmed, semantic_total=len(all_semantic))
    last_save_time = save_interim_results({
        "date": datetime.now().strftime("%Y%m%d%H%M%S"),
        "semantic_confirmed_count": len(semantic_confirmed),
        "semantic_total_count": len(all_semantic),
    }, "semantic_analysis", time.time() - start_time, last_save_time)
    stage_start = time.time()

    # STEP 6: Merge + AST verification
    flush_print("\n[Pipeline] Step 6/6 - Merge & AST verification ...")
    confirmed, all_extra = merge_findings(llm_vulns, semgrep_verified, semgrep_alts, semgrep_rejected, taint_flows, interprocedural_flows, semantic_confirmed, tree, file_path, file_lines)
    confirmed = clean_extracted_objects(confirmed)
    if confirmed:
        _, confirmed = cwss_eval(confirmed, file_lines)
        total_cwss = [obj["CWSS"] for obj in confirmed if "CWSS" in obj]
        cwss_average = sum(total_cwss) / len(total_cwss) if total_cwss else 0.0
        category = classify_value(cwss_average)
    else:
        cwss_average = 0.0
        category = "None"
    print_partial_report(stage="Merge & AST verification", step=6, total=6, confirmed=confirmed, all_extra=all_extra)

    end_time = time.time()
    elapsed_time = round(end_time - start_time, 2)

    output1 = {
        "date": datetime.now().strftime("%Y%m%d%H%M%S"),
        "file_name": file_name,
        "file_extension": file_extension,
        "path_file": path_file,
        "analisis duration": elapsed_time,
        "risk [in progress]": category,
        "cwss_average [in progress]": cwss_average,
        "semgrep_findings_count": len(semgrep_findings),
        "semgrep_verified_count": len(semgrep_verified),
        "semgrep_rejected_count": len(semgrep_rejected),
        "semgrep_alternative_count": len(semgrep_alts),
        "llm_findings_count": len(llm_vulns),
        "taint_intra_count": len(taint_flows),
        "taint_inter_count": len(interprocedural_flows),
        "semantic_confirmed_count": len(semantic_confirmed),
        "semantic_total_count": len(all_semantic),
        "all_extra_count": len(all_extra),
        "vulnerabilities": confirmed,
    }

    p_final, p_all = save_out(output1, all_extra, semgrep_verified, semgrep_alts, semgrep_rejected, llm_vulns, taint_flows, interprocedural_flows, all_semantic)

    return output1


# ─────────────────────────────────────────────────────────────────────────────
# LLM SETUP (Colab-Optimized)
# ─────────────────────────────────────────────────────────────────────────────

vulnerability_data = load_json_vulnerability_data()

# Corrected model filename (lowercase)
if USE_QUANTIZED_MODEL:
    model_id = 'Qwen/Qwen2.5-Coder-1.5B-Instruct-GGUF'
    filename = 'qwen2.5-coder-1.5b-instruct-q4_k_m.gguf'
else:
    model_id = 'Qwen/Qwen2.5-Coder-1.5B-Instruct-GGUF'
    filename = 'qwen2.5-coder-1.5b-instruct-q8_0.gguf'

try:
    local_model_path = hf_hub_download(repo_id=model_id, filename=filename)
except Exception as e:
    print(f"⚠️  Download failed: {e}")
    print("🔄 Trying fallback quantization...")
    filename = 'qwen2.5-coder-1.5b-instruct-q3_k_m.gguf'
    local_model_path = hf_hub_download(repo_id=model_id, filename=filename)

print("⏳ Reading model metadata …")
temp_llama = llama_cpp.Llama(model_path=local_model_path, n_gpu_layers=0, verbose=False)
model_metadata = temp_llama.metadata
model_max_ctx = model_metadata.get("context_length", 8192)
print(f"   Model max context_length: {model_max_ctx} tokens")
del temp_llama
cleanup_colab_memory()

if device == "cuda":
    n_ctx = min(model_max_ctx, 8192)
    n_gpu_layers = 999
elif device == "tpu":
    n_ctx = min(model_max_ctx, 8192)
    n_gpu_layers = 999
else:
    n_ctx = min(model_max_ctx, 4096)
    n_gpu_layers = 0

print(f"   n_ctx={n_ctx}  n_gpu_layers={n_gpu_layers}")

llama = llama_cpp.Llama(
    model_path=local_model_path,
    n_gpu_layers=n_gpu_layers,
    chat_format="chatml",
    n_ctx=n_ctx,
    logits_all=True,
    verbose=False,
    max_new_tokens=512,
    repetition_penalty=1.1,
    temperature=0.001,
    context_length=n_ctx,
    stream=False,
    draft_model=LlamaPromptLookupDecoding(num_pred_tokens=2),
    use_mmap=True,
    use_mlock=False,
)

desired_extensions = [
    ".py", ".java", ".cpp", ".c", ".cs", ".go", ".php",
    ".ks", ".kts", ".ktx", ".rb", ".rs", ".scala", ".swift",
    ".proto", ".md", ".markdown", ".html", ".tex", ".lua",
    ".perl", ".pm", ".haskell", ".lhs", ".cob", ".cbl", ".cpy",
]

create = instructor.patch(
    create=llama.create_chat_completion_openai_v1,
    mode=instructor.Mode.TOOLS,
)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN DRIVER
# ─────────────────────────────────────────────────────────────────────────────

def _action(path_directory, num, vulnerability_data):
    type_directory = path_identity(path_directory)
    flush_print(f"⚠️ '{path_directory}' is a {type_directory}")
    if type_directory == "directory":
        files = list_files_by_extension(path_directory, desired_extensions)
        if files:
            flush_print(f"📂 Found {len(files)} file(s):")
            for fp in files:
                flush_print(f"  → {fp}")
                file_to_analyze(fp, num, vulnerability_data)
        else:
            flush_print(f"⚠️ No supported files found in '{path_directory}'.")
    elif type_directory == "file":
        _, ext = os.path.splitext(path_directory)
        if ext not in desired_extensions:
            flush_print(f"⚠️ Extension '{ext}' not supported.")
            return
        file_to_analyze(path_directory, num, vulnerability_data)
    else:
        flush_print(f"❌ '{path_directory}' is not a valid file or directory.")


def main():
    while True:
        user_input = input("\n➡️  Enter a Google Drive file or directory path (or 'q' to quit): ").strip()
        if user_input.lower() in {"q", "quit", "exit"}:
            flush_print("👋 Exiting Smart SAST. Goodbye!")
            break
        if not user_input:
            flush_print("⚠️ Empty input. Please try again.")
            continue
        try:
            sanitized = sanitize_google_drive_path(user_input)
            if not sanitized:
                raise ValueError("❌ Invalid path.")
            _action(sanitized, "1", vulnerability_data)
            flush_print("\n✅ Analysis completed successfully.")
        except Exception as e:
            flush_print(f"\n❌ Analysis failed:\n    {type(e).__name__}: {e}")
            retry = input("🔁 Retry? (y/n): ").strip().lower()
            if retry not in {"y", "yes"}:
                break
        again = input("\n➡️  Analyze another file/directory? (y/n): ").strip().lower()
        if again not in {"y", "yes", "1", "continue"}:
            flush_print("👋 Exiting Smart SAST. Goodbye!")
            break


if __name__ == "__main__":
    main()
