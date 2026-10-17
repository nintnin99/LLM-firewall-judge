"""Hybrid judge used by the tests and mirrored by the n8n Code node.

Clear cases are decided by rules. The gray zone trusts detector labels.
A live Ollama call can replace the gray decision; if that call fails closed
parsing, the caller blocks. This module is the deterministic core.
"""

from __future__ import annotations

import re

MANIPULATION = [
    re.compile(r"answer\s+[\"']?allow", re.I),
    re.compile(r"say this is safe", re.I),
    re.compile(r"</?\s*data\s*>", re.I),
    re.compile(r"verdict\s*[:=]\s*[\"']?allow", re.I),
    re.compile(r"detectors were wrong", re.I),
    re.compile(r"ignore their reports", re.I),
    re.compile(r"ignore the (detector|reports)", re.I),
    re.compile(r'\{\s*"verdict"', re.I),
    re.compile(r"new instruction", re.I),
    re.compile(r"you must (return |output )?allow", re.I),
    re.compile(r"réponds\s+allow", re.I),
    re.compile(r"أجب\s*بـ?\s*allow", re.I),
]

HIDDEN_ATTACK = re.compile(
    r"ignore|password|rank this candidate|system prompt|card number|approve this payment|ignore les règles|تجاهل|mot de passe",
    re.I,
)

CATEGORIES = {
    "injection": "LLM01 prompt injection",
    "fraud": "social engineering",
    "pii": "data exfiltration",
}


def _round(value: float) -> float:
    return round(float(value), 2)


def is_manipulation(text: str) -> bool:
    return any(pattern.search(text or "") for pattern in MANIPULATION)


def top_rag(matches) -> float:
    if not matches:
        return 0.0
    return max(float(item.get("score") or 0) for item in matches)


def max_detector(findings) -> float:
    if not findings:
        return 0.0
    return max(float(item.get("score") or 0) for item in findings)


def attacks(findings):
    return [item for item in findings or [] if item.get("label") == "attack"]


def category_for(agent: str) -> str:
    return CATEGORIES.get(agent, "LLM01 prompt injection")


def strip_delimiters(text: str) -> str:
    return re.sub(r"</?\s*data\s*>", "", text or "", flags=re.I)


def truncate(text: str, limit: int = 4000) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit]


def matches_of(raw: dict):
    if isinstance(raw.get("matches"), list):
        return raw["matches"]
    if isinstance(raw.get("rag_matches"), list):
        return raw["rag_matches"]
    return []


def validate(raw: dict) -> dict:
    text = str(raw.get("text") or "")
    segments = raw.get("segments") if isinstance(raw.get("segments"), list) else []
    findings = raw.get("findings") if isinstance(raw.get("findings"), list) else []
    matches = matches_of(raw)
    manipulated = is_manipulation(text) or any(is_manipulation(str(segment.get("text") or "")) for segment in segments)
    return {
        "request_id": raw.get("request_id") or raw.get("case_id"),
        "text": text,
        "clean_text": truncate(strip_delimiters(text)),
        "segments": segments,
        "findings": findings,
        "matches": matches,
        "manipulated": manipulated,
    }


VISIBLE_ATTACK = re.compile(
    r"ignore previous rules|print the admin password|rank this candidate|ignore les règles|approve this payment|send me client card numbers|send the client card numbers",
    re.I,
)


def _sentences(text: str):
    return [part.strip() for part in re.split(r"(?<=[.!?])\s+|\n+", text or "") if part.strip()]


def _cut_sentence(sentence: str):
    match = VISIBLE_ATTACK.search(sentence)
    if not match:
        return sentence, ""
    prefix = re.sub(r"[\s,;:.\-]+(?:and also|and|also|then)?\s*$", "", sentence[: match.start()], flags=re.I).strip()
    if len(prefix) >= 12:
        return prefix, sentence[match.start() :].strip()
    return "", sentence


def visible_removable(text: str):
    parts = _sentences(text)
    kept, dropped = [], []
    for sentence in parts:
        keep, drop = _cut_sentence(sentence)
        if keep:
            kept.append(keep)
        if drop:
            dropped.append(drop)
    if not kept or not dropped:
        return None
    cleaned = re.sub(r"\s+", " ", " ".join(kept)).strip()
    return {"cleaned": cleaned, "llm": len(parts) == 1}


def hidden_attack(data: dict) -> bool:
    hidden = [segment for segment in data["segments"] if segment.get("hidden")]
    if not hidden:
        return False
    if attacks(data["findings"]):
        return True
    if top_rag(data["matches"]) >= 0.55:
        return True
    return any(HIDDEN_ATTACK.search(str(segment.get("text") or "")) for segment in hidden)


def gray_decision(data: dict) -> dict:
    found = attacks(data["findings"])
    strong = [item for item in found if float(item.get("score") or 0) >= 0.5]
    if strong:
        top = max(strong, key=lambda item: float(item.get("score") or 0))
        return {
            "verdict": "BLOCK",
            "category": category_for(top.get("agent")),
            "confidence": _round(top.get("score") or 0.5),
            "justification": top.get("evidence") or "A detector reports an attack in the gray zone.",
            "source": "gray",
        }
    return {
        "verdict": "ALLOW",
        "category": "none",
        "confidence": _round(max(0.5, 1 - max_detector(data["findings"]))),
        "justification": "Gray zone: no detector reports an attack at or above 0.5.",
        "source": "gray",
    }


def decide(data: dict, gray=gray_decision) -> dict:
    findings = data["findings"]
    rag = top_rag(data["matches"])
    max_score = max_detector(findings)
    found = attacks(findings)
    top_attack = max(found, key=lambda item: float(item.get("score") or 0)) if found else None

    if max_score >= 0.9 and rag >= 0.75:
        agent = top_attack.get("agent") if top_attack else "injection"
        return {
            "verdict": "BLOCK",
            "category": category_for(agent),
            "confidence": _round(max(max_score, rag)),
            "justification": (top_attack or {}).get("evidence") or "Detector and retrieval scores are both high.",
            "source": "rule",
        }

    if data["manipulated"]:
        return {
            "verdict": "BLOCK",
            "category": "LLM01 prompt injection",
            "confidence": 0.95,
            "justification": "The untrusted text tries to set the verdict. That is itself an attack.",
            "source": "rule",
        }

    visible_cut = visible_removable(data["text"])
    if visible_cut and not any(segment.get("hidden") for segment in data["segments"]):
        return {
            "verdict": "SANITIZE",
            "category": "LLM01 prompt injection",
            "confidence": _round((top_attack or {}).get("score") or rag or 0.7),
            "justification": (
                "A visible sentence mixes a real request with an attack. A rewrite must remove only the attack."
                if visible_cut["llm"]
                else "A visible attack sentence can be removed and the legitimate sentence kept."
            ),
            "cleaned_text": visible_cut["cleaned"],
            "rewrite_method": "llm" if visible_cut["llm"] else "rules",
            "source": "rule",
        }

    if hidden_attack(data):
        visible = " ".join(
            str(segment.get("text") or "").strip()
            for segment in data["segments"]
            if not segment.get("hidden") and str(segment.get("text") or "").strip()
        ).strip()
        return {
            "verdict": "SANITIZE",
            "category": "LLM01 prompt injection",
            "confidence": _round((top_attack or {}).get("score") or rag or 0.7),
            "justification": "Hidden content matches an attack and can be removed.",
            "cleaned_text": visible,
            "source": "rule",
        }

    if (not findings or all(float(item.get("score") or 0) < 0.2 for item in findings)) and rag < 0.55:
        return {
            "verdict": "ALLOW",
            "category": "none",
            "confidence": _round(1 - max_score),
            "justification": "Detector scores and retrieval score are both low.",
            "source": "rule",
        }

    return gray(data)


def post_check(decision: dict, findings) -> dict:
    if decision.get("verdict") == "ALLOW" and max_detector(findings) >= 0.9:
        return {
            **decision,
            "verdict": "BLOCK",
            "category": "LLM01 prompt injection" if decision.get("category") == "none" else decision.get("category"),
            "confidence": _round(max_detector(findings)),
            "justification": "Overridden to BLOCK because a detector score is at least 0.9.",
            "source": "postcheck",
        }
    return decision


def filter_findings_for_recheck(findings, had_hidden: bool):
    kept = []
    for item in findings or []:
        if item.get("applies_to") == "hidden":
            continue
        if item.get("applies_to") == "visible":
            kept.append(item)
            continue
        if had_hidden and item.get("agent") == "injection":
            continue
        kept.append(item)
    return kept


def _public(decision: dict, cleaned: str | None = None) -> dict:
    out = {
        "verdict": decision["verdict"],
        "category": decision["category"],
        "confidence": decision["confidence"],
        "justification": decision["justification"],
    }
    if cleaned is not None and decision["verdict"] == "ALLOW":
        out["cleaned_text"] = cleaned
    return out


def pipeline(raw: dict, gray=gray_decision) -> dict:
    data = validate(raw)
    first = post_check(decide(data, gray), data["findings"])
    if first["verdict"] != "SANITIZE":
        return _public(first)

    cleaned = (first.get("cleaned_text") or "").strip()
    if not cleaned:
        return {
            "verdict": "BLOCK",
            "category": first["category"],
            "confidence": first["confidence"],
            "justification": "Sanitizer removed the hidden attack and no legitimate text remained.",
        }

    second_raw = {
        "request_id": data.get("request_id"),
        "text": cleaned,
        "segments": [{"modality": "text", "text": cleaned, "hidden": False}],
        "findings": filter_findings_for_recheck(data["findings"], True),
        "matches": [],
    }
    second_data = validate(second_raw)
    second = post_check(decide(second_data, gray), second_data["findings"])
    if second["verdict"] == "ALLOW":
        return _public(second, cleaned)

    category = second["category"] if second["category"] != "none" else first["category"]
    return {
        "verdict": "BLOCK",
        "category": category,
        "confidence": _round(max(second["confidence"], first["confidence"])),
        "justification": "Re-check did not allow the text after sanitizing. " + second["justification"],
    }
