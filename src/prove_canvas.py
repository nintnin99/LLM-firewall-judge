"""Run the sanitizer second pass, the visible rewrite, and a forced fail-closed path in n8n."""

import csv
import json
import os
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("N8N_BASE", "http://127.0.0.1:5678")


def env(name):
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1].strip()
    raise SystemExit(f"missing {name}")


jar = CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def call(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with opener.open(request, timeout=60) as response:
            body = response.read().decode("utf-8")
            parsed = json.loads(body) if body else {}
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise SystemExit(f"{method} {path} -> {error.code} {detail[:800]}") from error
    if isinstance(parsed, dict) and "data" in parsed and not path.startswith("/rest/login"):
        return parsed["data"]
    return parsed


def unflatten(value):
    if not isinstance(value, str):
        return value
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return value
    if not isinstance(parsed, list):
        return parsed

    def walk(item, seen):
        if isinstance(item, str) and item.isdigit():
            index = int(item)
            if index in seen or index >= len(parsed):
                return item
            seen.add(index)
            return walk(parsed[index], seen)
        if isinstance(item, list):
            return [walk(entry, set(seen)) for entry in item]
        if isinstance(item, dict):
            return {key: walk(entry, set(seen)) for key, entry in item.items()}
        return item

    return walk("0", set())


def login():
    call(
        "POST",
        "/rest/login",
        {"emailOrLdapLoginId": env("N8N_OWNER_EMAIL"), "password": env("N8N_OWNER_PASSWORD")},
    )


def load_cases():
    with (ROOT / "tests" / "m5_cases.csv").open(encoding="utf-8", newline="") as handle:
        return {row["case_id"]: row for row in csv.DictReader(handle)}


def payload(row):
    return {
        "request_id": row["case_id"],
        "text": row["text"],
        "segments": json.loads(row["segments_json"]),
        "findings": json.loads(row["findings_json"]),
        "matches": json.loads(row["rag_json"]),
    }


def editable(workflow):
    keep = ("id", "name", "nodes", "connections", "settings", "staticData", "pinData", "meta", "active")
    return {key: workflow[key] for key in keep if key in workflow}


def push(workflow_id, built):
    current = call("GET", f"/rest/workflows/{workflow_id}")
    current["nodes"] = built["nodes"]
    current["connections"] = built["connections"]
    current["pinData"] = {}
    current["settings"] = built["settings"]
    return call("PATCH", f"/rest/workflows/{workflow_id}", editable(current))


def run(workflow, item, timeout):
    workflow = dict(workflow)
    workflow["pinData"] = {"When called by M1": [{"json": item}]}
    saved = call("PATCH", f"/rest/workflows/{workflow['id']}", editable(workflow))
    started = call(
        "POST",
        f"/rest/workflows/{workflow['id']}/run",
        {"workflowData": saved, "triggerToStartFrom": {"name": "When called by M1"}},
    )
    execution_id = started.get("executionId") or started.get("data", {}).get("executionId")
    if not execution_id:
        raise SystemExit(f"no execution id: {started}")
    deadline = time.time() + timeout
    while time.time() < deadline:
        execution = call("GET", f"/rest/executions/{execution_id}?includeData=true")
        if execution.get("status") in {"success", "error", "crashed", "canceled"}:
            execution["data"] = unflatten(execution.get("data"))
            return execution
        time.sleep(2)
    raise SystemExit(f"execution {execution_id} timed out")


def node_json(execution):
    data = execution.get("data") or {}
    result = (data.get("resultData") or {}) if isinstance(data, dict) else {}
    run_data = result.get("runData") or {}
    found = {}
    for name, runs in run_data.items():
        if not runs:
            continue
        last = runs[-1]
        error = last.get("error")
        main = ((last.get("data") or {}).get("main") or [None])[0] or []
        item = main[0].get("json") if main and isinstance(main[0], dict) else None
        found[name] = {"status": last.get("executionStatus"), "error": (error or {}).get("message") if isinstance(error, dict) else None, "json": item}
    return {
        "status": execution.get("status"),
        "last": (result.get("lastNodeExecuted") if isinstance(result, dict) else None),
        "nodes": found,
    }


def clear_pin(workflow_id):
    current = call("GET", f"/rest/workflows/{workflow_id}")
    current["pinData"] = {}
    call("PATCH", f"/rest/workflows/{workflow_id}", editable(current))


def set_judge_model(workflow, model):
    for node in workflow["nodes"]:
        if node["name"] == "Ollama Chat Model":
            node["parameters"]["model"] = model
    return call("PATCH", f"/rest/workflows/{workflow['id']}", editable(workflow))


def main():
    import sys

    sys.path.insert(0, str(ROOT / "src"))
    from build_workflows import judge, sanitizer

    login()
    credentials = call("GET", "/rest/credentials")
    items = credentials if isinstance(credentials, list) else credentials.get("data", credentials)
    ollama = next(item for item in items if item.get("type") == "ollamaApi")
    judge_wf = push("M5JudgeWorkflow1", judge(ollama["id"]))
    sanitizer_wf = push("M5SanitizerWork1", sanitizer(ollama["id"]))
    (ROOT / "workflows" / "m5_judge.json").write_text(json.dumps(judge(ollama["id"]), indent=2, ensure_ascii=False), encoding="utf-8")
    (ROOT / "workflows" / "m5_sanitizer.json").write_text(json.dumps(sanitizer(ollama["id"]), indent=2, ensure_ascii=False), encoding="utf-8")

    cases = load_cases()
    report = {}
    for case_id, timeout in (("s01", 60), ("s06", 180), ("v01", 60), ("v02", 240)):
        execution = run(sanitizer_wf, payload(cases[case_id]), timeout)
        summary = node_json(execution)
        final = (summary["nodes"].get("Final verdict") or summary["nodes"].get("Pass through") or summary["nodes"].get("Fail closed") or {}).get("json")
        report[case_id] = {
            "execution_status": summary["status"],
            "last_node": summary["last"],
            "visited": sorted(summary["nodes"]),
            "final": final,
            "expected_verdict": cases[case_id]["expected_verdict"],
            "expected_cleaned": cases[case_id]["expected_cleaned"],
        }
        cleaned = (final or {}).get("cleaned_text") or ""
        expected_cleaned = cases[case_id]["expected_cleaned"]
        verdict_ok = (final or {}).get("verdict") == cases[case_id]["expected_verdict"]
        cleaned_ok = (not expected_cleaned) or expected_cleaned in cleaned
        report[case_id]["ok"] = bool(verdict_ok and cleaned_ok)
        print(case_id, "OK" if report[case_id]["ok"] else "FAIL", summary["last"], final)
        sanitizer_wf = call("GET", "/rest/workflows/M5SanitizerWork1")

    clear_pin("M5SanitizerWork1")
    judge_wf = call("GET", "/rest/workflows/M5JudgeWorkflow1")
    judge_wf = set_judge_model(judge_wf, "missing-model-m5")
    try:
        execution = run(judge_wf, payload(cases["g02"]), 90)
        summary = node_json(execution)
        report["fail_closed_judge"] = {"execution_status": summary["status"], "last_node": summary["last"], "visited": sorted(summary["nodes"]), "final": (summary["nodes"].get("Fail closed") or {}).get("json")}
        print("fail_closed_judge", summary["status"], summary["last"], report["fail_closed_judge"]["final"])
        clear_pin("M5JudgeWorkflow1")
        sanitizer_wf = call("GET", "/rest/workflows/M5SanitizerWork1")
        broken = json.loads(json.dumps(sanitizer_wf))
        for node in broken["nodes"]:
            if node["name"] == "Judge first pass":
                node["parameters"]["workflowId"]["value"] = "missing-workflow"
        execution = run(broken, payload(cases["b01"]), 60)
        summary = node_json(execution)
        report["fail_closed_sanitizer"] = {"execution_status": summary["status"], "last_node": summary["last"], "visited": sorted(summary["nodes"]), "final": (summary["nodes"].get("Fail closed") or {}).get("json")}
        print("fail_closed_sanitizer", summary["status"], summary["last"], report["fail_closed_sanitizer"]["final"])
    finally:
        clear_pin("M5JudgeWorkflow1")
        clear_pin("M5SanitizerWork1")
        restored = call("GET", "/rest/workflows/M5JudgeWorkflow1")
        set_judge_model(restored, "llama3.1:8b")
        push("M5SanitizerWork1", sanitizer(ollama["id"]))
        push("M5JudgeWorkflow1", judge(ollama["id"]))

    (ROOT / "tests" / "m5_n8n_results.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print("wrote tests/m5_n8n_results.json")


if __name__ == "__main__":
    main()
