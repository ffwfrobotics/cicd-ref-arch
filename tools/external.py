"""External findings and advisories, evaluated against one commit (docs/oscal.md#external-findings).

The owner's sysadmins import IT Security's findings into the compliance repo's ledger
(ledger/<app>.yaml); vulnerability announcements go in advisories/. Each one carries a check that
can be re-run against any commit, so it is a failing test while it holds and a passing one once
fixed, without the developers merging anything:

  package   {name, ecosystem?, affected}  fails while the commit's SBOM has an affected version
  rule      {rule, tool?}                 fails while a scanner reports that rule for the commit
  endpoint  {path?, header?, status?}     fails while the environment's URL lacks the header/status
  manual    {}                            fails until someone closes it in the ledger

The developers can't suppress a ledger finding (their policy.yaml and VEX don't apply). Only the
owner's security role can accept the risk, in the ledger, with a reason and an expiry; that
acceptance is a claim for the assessor to judge. Advisories are vulnerabilities like grype's:
the app's own records (an ignore with reason and expiry) may say it isn't affected.
"""
from __future__ import annotations

import datetime as dt
import http.client
import json
import re
import socket
import ssl
from pathlib import Path

import yaml

# ---------------------------------------------------------------- versions and the SBOM

_PART = re.compile(r"(\d+|[a-z]+)")
_PRE = {"dev": -4, "a": -3, "alpha": -3, "b": -2, "beta": -2, "rc": -1, "c": -1, "pre": -1, "preview": -1}
_POST = {"post": 1, "p": 1, "r": 1, "rev": 1, "pl": 1}


def version_parts(v: str) -> list[tuple[int, int]]:
    """Numbers as (1, n); pre-release tags (rc, beta...) as (0, -k), before the release; revision
    and post tags (Alpine/Wolfi -r1, .post1) as (2, k), after it."""
    out = []
    for p in _PART.findall(str(v).lower().lstrip("v").split("+")[0]):
        if p.isdigit():
            out.append((1, int(p)))
        elif p in _POST:
            out.append((2, _POST[p]))
        else:
            out.append((0, _PRE.get(p, -5)))
    return out


def vcmp(a: str, b: str) -> int:
    """-1, 0, 1. Good enough for PyPI, npm, Go and apk versions; missing parts count as 0, so
    1.2 == 1.2.0, and 3.0.0rc1 < 3.0.0 < 3.0.0-r1 < 3.0.1."""
    pa, pb = version_parts(a), version_parts(b)
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else (1, 0)
        y = pb[i] if i < len(pb) else (1, 0)
        if x != y:
            return -1 if x < y else 1
    return 0


def affected(version: str, spec: str) -> bool:
    """spec: comma-separated comparisons, all must hold: '<3.1.9', '>=2.0,<2.3', '==1.4.2'."""
    for clause in [c.strip() for c in str(spec).split(",") if c.strip()]:
        m = re.match(r"(<=|>=|==|!=|<|>|=)?\s*(.+)", clause)
        c = vcmp(version, m.group(2))
        op = m.group(1) or "=="
        ok = {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "==": c == 0, "=": c == 0, "!=": c != 0}[op]
        if not ok:
            return False
    return True


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def sbom_packages(path: Path | None) -> list[dict] | None:
    if not path or not Path(path).exists():
        return None
    out = []
    for c in json.loads(Path(path).read_text()).get("components") or []:
        purl = c.get("purl") or ""
        eco = purl[4:].split("/", 1)[0] if purl.startswith("pkg:") else ""
        out.append({"name": c.get("name", ""), "version": c.get("version", ""), "purl": purl, "ecosystem": eco})
    return out


def package_hits(pkgs: list[dict], chk: dict) -> list[dict]:
    want, eco = norm(chk["name"]), chk.get("ecosystem")
    return [p for p in pkgs if norm(p["name"]) == want and (not eco or p["ecosystem"] == eco)
            and affected(p["version"], chk.get("affected", ">=0"))]


# ---------------------------------------------------------------- endpoints, through the gateway


class _Via(http.client.HTTPSConnection):
    """HTTPS to `host` (SNI and Host header), connected through the cluster's gateway address."""

    def __init__(self, host: str, via: str, port: int, timeout: float):
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # headers are checked, not trust
        super().__init__(host, port, timeout=timeout, context=ctx)
        self._via = via

    def connect(self):
        sock = socket.create_connection((self._via, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def probe(host: str, path: str, via: str | None, timeout: float = 20) -> tuple[int, dict]:
    via, _, port = (via or host).partition(":")
    c = _Via(host, via, int(port or 443), timeout)
    try:
        c.request("GET", path or "/", headers={"Host": host, "User-Agent": "cicd-ref-arch endpoint check"})
        r = c.getresponse()
        r.read(65536)
        return r.status, {k.lower(): v for k, v in r.getheaders()}
    finally:
        c.close()


# ---------------------------------------------------------------- evaluation


def load_ledger(path: Path | None) -> list[dict]:
    if not path or not Path(path).exists():
        return []
    return (yaml.safe_load(Path(path).read_text()) or {}).get("findings") or []


def load_advisories(d: Path | None) -> list[dict]:
    if not d or not Path(d).is_dir():
        return []
    out = []
    for p in sorted(Path(d).glob("*.yaml")):
        a = yaml.safe_load(p.read_text()) or {}
        if a.get("id"):
            out.append(a)
    return out


def evaluate(entry: dict, ctx: dict) -> tuple[str, str]:
    """('fail' | 'pass' | 'unknown', detail) for one ledger finding's check."""
    chk = entry.get("check") or {"type": "manual"}
    t = chk.get("type", "manual")
    if t == "package":
        if ctx.get("packages") is None:
            return "unknown", "no SBOM for this commit"
        hits = package_hits(ctx["packages"], chk)
        if hits:
            return "fail", ", ".join(f"{h['name']} {h['version']}" for h in hits[:3]) + f" matches {chk.get('affected')}"
        return "pass", f"no {chk['name']} {chk.get('affected', '')} in the SBOM"
    if t == "rule":
        seen = [f for f in ctx.get("raw_findings", []) if f.get("rule") == chk["rule"] and (not chk.get("tool") or f.get("tool") == chk["tool"])]
        if seen:
            return "fail", f"{chk['rule']} reported at {seen[0].get('location')}" + (f" (+{len(seen) - 1})" if len(seen) > 1 else "")
        return "pass", f"{chk['rule']} no longer reported"
    if t == "endpoint":
        host = ctx.get("host")
        if not host or ctx.get("skip_endpoints"):
            return "unknown", ctx.get("skip_endpoints") or "no URL for this environment"
        try:
            status, headers = probe(host, chk.get("path", "/"), ctx.get("via"))
        except OSError as e:
            return "unknown", f"https://{host}{chk.get('path', '/')}: {type(e).__name__}: {e}"[:200]
        url = f"https://{host}{chk.get('path', '/')}"
        if chk.get("status") and status != int(chk["status"]):
            return "fail", f"{url} answered {status}, expected {chk['status']}"
        if chk.get("header"):
            v = headers.get(chk["header"].lower())
            if v is None:
                return "fail", f"{url} ({status}) has no {chk['header']} header"
            if chk.get("contains") and chk["contains"].lower() not in v.lower():
                return "fail", f"{url}: {chk['header']}: {v!r} lacks {chk['contains']!r}"
            return "pass", f"{url}: {chk['header']}: {v}"
        return "pass", f"{url} answered {status}"
    return "fail", "open until closed in the ledger"


def external_findings(ledger: list[dict], advisories: list[dict], ctx: dict, today: dt.date) -> tuple[list[dict], list[dict]]:
    """(findings for the gate, one test result per ledger entry and matched advisory)."""
    from security import finding  # noqa: PLC0415 (same directory; imported late to avoid a cycle)
    findings, tests = [], []
    for e in ledger:
        status = e.get("status", "open")
        if status == "closed":
            continue
        res, detail = evaluate(e, ctx)
        acc = e.get("accepted") or {}
        accepted = status == "accepted" and acc.get("expires") and dt.date.fromisoformat(str(acc["expires"])) >= today
        test = {"test": f"external/{e['id']}", "title": e.get("title", ""), "check": (e.get("check") or {}).get("type", "manual"),
                "result": "accepted" if (accepted and res != "pass") else ("pass" if res == "pass" else "fail"),
                "detail": detail, "source": (e.get("source") or {}).get("kind", "")}
        tests.append(test)
        if res == "pass":
            continue
        chk = e.get("check") or {}
        loc = e.get("location")
        if not loc and chk.get("type") == "package" and ctx.get("packages"):
            hits = package_hits(ctx["packages"], chk)
            loc = (hits[0]["purl"] or f"{hits[0]['name']}@{hits[0]['version']}") if hits else None
        if not loc and chk.get("type") == "endpoint" and ctx.get("host"):
            loc = f"https://{ctx['host']}{chk.get('path', '/')}"
        f = finding("external", "ledger", f"external/{e['id']}", (e.get("severity") or "high").lower(),
                    loc or ctx.get("app", ""),
                    f"{e.get('title', e['id'])}: {detail}", check=test["check"], ledger_id=e["id"],
                    unknown=(res == "unknown"))
        if accepted:
            f["suppressed"] = {"by": f"risk accepted ({acc.get('by', 'owner')})", "reason": acc.get("reason", ""),
                               "expires": str(acc["expires"])}
        findings.append(f)
    pkgs = ctx.get("packages")
    for a in advisories:
        p = a.get("package") or {}
        if pkgs is None or not p.get("name"):
            continue
        hits = package_hits(pkgs, p)
        if not hits:
            continue
        fixed = [str(p["fixed"])] if p.get("fixed") else []
        for h in hits:
            findings.append(finding("vuln", "advisory", a["id"], (a.get("severity") or "high").lower(),
                                    h["purl"] or f"{h['name']}@{h['version']}",
                                    f"{h['name']} {h['version']}: {a.get('title', a['id'])} (announced {a.get('announced', '')[:10]})",
                                    package=h["name"], version=h["version"], fix_state="fixed" if fixed else "not-fixed",
                                    fixed_in=fixed))
        tests.append({"test": f"advisory/{a['id']}", "title": a.get("title", ""), "check": "package", "result": "fail",
                      "detail": ", ".join(f"{h['name']} {h['version']}" for h in hits[:3]), "source": "advisory"})
    return findings, tests
