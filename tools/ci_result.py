#!/usr/bin/env python3
"""Write a ci-result/v1 record (docs/architecture.md#results) for one step, as JSON on stdout.

  ci_result.py test --log test.log --rc 0 --started 2026-11-19T12:00:00Z --duration 12

Counts come from JUnit XML when the step leaves one (--junit), else from unittest/pytest output
in the log. Agents read this record; nobody should need to parse a log to find what failed.
"""
import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET


def from_junit(path):
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    total = failed = skipped = 0
    failures = []
    for s in suites:
        for case in s.iter("testcase"):
            total += 1
            bad = case.find("failure") if case.find("failure") is not None else case.find("error")
            if bad is not None:
                failed += 1
                failures.append({"test": f"{case.get('classname')}.{case.get('name')}",
                                 "file": case.get("file"), "line": case.get("line"),
                                 "message": (bad.get("message") or bad.text or "")[:500]})
            elif case.find("skipped") is not None:
                skipped += 1
    return {"total": total, "passed": total - failed - skipped, "failed": failed, "skipped": skipped}, failures


def from_log(text):
    total = failed = skipped = 0
    m = re.search(r"^Ran (\d+) tests? in", text, re.M)                       # unittest
    if m:
        total = int(m.group(1))
        f = re.search(r"^FAILED \((.*)\)", text, re.M)
        if f:
            for k, v in re.findall(r"(failures|errors|skipped)=(\d+)", f.group(1)):
                if k == "skipped":
                    skipped += int(v)
                else:
                    failed += int(v)
        s = re.search(r"^OK \(skipped=(\d+)\)", text, re.M)
        skipped += int(s.group(1)) if s else 0
    else:                                                                     # pytest
        for n, k in re.findall(r"(\d+) (passed|failed|skipped|error)", text):
            total += int(n)
            failed += int(n) if k in ("failed", "error") else 0
            skipped += int(n) if k == "skipped" else 0
    failures = [{"test": t, "message": ""} for t in re.findall(r"^(?:FAIL|ERROR): (\S+ \(\S+\))", text, re.M)]
    return {"total": total, "passed": total - failed - skipped, "failed": failed, "skipped": skipped}, failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("job")
    ap.add_argument("--log", required=True)
    ap.add_argument("--rc", type=int, required=True)
    ap.add_argument("--started", required=True)
    ap.add_argument("--duration", type=int, required=True)
    ap.add_argument("--junit")
    a = ap.parse_args()
    text = open(a.log, errors="replace").read()
    summary, failures = from_junit(a.junit) if a.junit and os.path.exists(a.junit) else from_log(text)
    env = os.environ
    server = env.get("GITHUB_SERVER_URL", "")
    repo = env.get("GITHUB_REPOSITORY", "")
    rec = {
        "schema": "ci-result/v1",
        "repo": repo, "sha": env.get("GITHUB_SHA"), "ref": env.get("GITHUB_REF"),
        "workflow": env.get("GITHUB_WORKFLOW"), "job": a.job,
        "status": "pass" if a.rc == 0 else "fail",
        "started_at": a.started, "duration_s": a.duration,
        "runner": env.get("RUNNER_NAME") or env.get("HOSTNAME"),
        "summary": summary, "failures": failures[:50],
        "log_tail": "\n".join(text.splitlines()[-40:]),
        "run_url": f"{server}/{repo}/actions/runs/{env.get('GITHUB_RUN_NUMBER', '')}" if server else None,
    }
    json.dump(rec, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
