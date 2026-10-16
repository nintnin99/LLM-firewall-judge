"""Write n8n workflow files from the shared Code-node script."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
code = (ROOT / "src" / "n8n_judge_code.js").read_text(encoding="utf-8")
functions, _entry = code.split("/*__ENTRY__*/", 1)

JUDGE_ENTRY = """
const raw = $input.first().json;
const decision = await singlePass.call(this, raw);
if (decision.verdict === "SANITIZE") {
  return [{ json: { ...publicDecision(decision), cleaned_text: decision.cleaned_text || "" } }];
}
return [{ json: publicDecision(decision) }];
"""

SANITIZER_ENTRY = """
const raw = $input.first().json;
const first = await singlePass.call(this, raw);

if (first.verdict !== "SANITIZE") {
  return [{ json: publicDecision(first) }];
}

const cleaned = String(first.cleaned_text || "").trim();
if (!cleaned) {
  return [{
    json: {
      verdict: "BLOCK",
      category: first.category,
      confidence: first.confidence,
      justification: "Sanitizer removed the hidden attack and no legitimate text remained.",
    },
  }];
}

const visibleFindings = (Array.isArray(raw.findings) ? raw.findings : []).filter((item) => {
  if (item.applies_to === "hidden") return false;
  if (item.applies_to === "visible") return true;
  return item.agent !== "injection";
});

const second = await singlePass.call(this, {
  request_id: raw.request_id || raw.case_id || null,
  text: cleaned,
  segments: (Array.isArray(raw.segments) ? raw.segments : []).filter((segment) => !segment.hidden),
  findings: visibleFindings,
  matches: [],
});

if (second.verdict === "ALLOW") {
  return [{ json: publicDecision(second, cleaned) }];
}

return [{
  json: {
    verdict: "BLOCK",
    category: second.category === "none" ? first.category : second.category,
    confidence: round2(Math.max(second.confidence, first.confidence)),
    justification: `Re-check did not allow the text after sanitizing. ${second.justification}`,
  },
}];
"""


def workflow(name, workflow_id, js_code, pinned):
    return {
        "id": workflow_id,
        "name": name,
        "active": False,
        "nodes": [
            {
                "parameters": {},
                "id": "a1b2c3d4-e5f6-7890-abcd-000000000001" if "Judge" in name else "a1b2c3d4-e5f6-7890-abcd-000000000011",
                "name": "When called by M1",
                "type": "n8n-nodes-base.executeWorkflowTrigger",
                "typeVersion": 1.1,
                "position": [240, 300],
            },
            {
                "parameters": {
                    "mode": "runOnceForAllItems",
                    "language": "javaScript",
                    "jsCode": js_code,
                },
                "id": "a1b2c3d4-e5f6-7890-abcd-000000000002" if "Judge" in name else "a1b2c3d4-e5f6-7890-abcd-000000000012",
                "name": "Decide" if "Judge" in name else "Sanitize and re-check",
                "type": "n8n-nodes-base.code",
                "typeVersion": 2,
                "position": [520, 300],
                "onError": "continueErrorOutput",
            },
            {
                "parameters": {
                    "assignments": {
                        "assignments": [
                            {
                                "id": "fail-closed",
                                "name": "verdict",
                                "value": "BLOCK",
                                "type": "string",
                            },
                            {
                                "id": "fail-category",
                                "name": "category",
                                "value": "LLM01 prompt injection",
                                "type": "string",
                            },
                            {
                                "id": "fail-confidence",
                                "name": "confidence",
                                "value": 0.99,
                                "type": "number",
                            },
                            {
                                "id": "fail-why",
                                "name": "justification",
                                "value": "Workflow error. Fail closed.",
                                "type": "string",
                            },
                        ]
                    },
                    "includeOtherFields": False,
                },
                "id": "a1b2c3d4-e5f6-7890-abcd-000000000003" if "Judge" in name else "a1b2c3d4-e5f6-7890-abcd-000000000013",
                "name": "Fail closed",
                "type": "n8n-nodes-base.set",
                "typeVersion": 3.4,
                "position": [800, 480],
            },
        ],
        "connections": {
            "When called by M1": {
                "main": [[{"node": "Decide" if "Judge" in name else "Sanitize and re-check", "type": "main", "index": 0}]]
            },
            "Decide" if "Judge" in name else "Sanitize and re-check": {
                "main": [
                    [],
                    [{"node": "Fail closed", "type": "main", "index": 0}],
                ]
            },
        },
        "pinData": {"When called by M1": [{"json": pinned}]},
        "settings": {"executionOrder": "v1"},
        "staticData": None,
        "meta": {"templateCredsSetupCompleted": True},
        "versionId": workflow_id + "v1",
        "tags": [],
    }


def main():
    pinned = {
        "request_id": "r-102",
        "text": "What are your opening hours?",
        "segments": [{"modality": "text", "text": "What are your opening hours?", "hidden": False}],
        "findings": [
            {"agent": "injection", "label": "benign", "score": 0.06, "evidence": "ordinary question"},
            {"agent": "fraud", "label": "benign", "score": 0.04, "evidence": "no impersonation"},
            {"agent": "pii", "label": "benign", "score": 0.03, "evidence": "no sensitive data"},
        ],
        "matches": [],
    }
    out = ROOT / "workflows"
    out.mkdir(exist_ok=True)
    judge = workflow("M5 Judge", "M5JudgeWorkflow1", functions + JUDGE_ENTRY, pinned)
    sanitizer = workflow("M5 Sanitizer", "M5SanitizerWork1", functions + SANITIZER_ENTRY, pinned)
    (out / "m5_judge.json").write_text(json.dumps(judge, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "m5_sanitizer.json").write_text(json.dumps(sanitizer, indent=2, ensure_ascii=False), encoding="utf-8")
    print("wrote workflows")


if __name__ == "__main__":
    main()
