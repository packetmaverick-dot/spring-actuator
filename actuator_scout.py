#!/usr/bin/env python3
"""
Actuator Scout — conservative Spring Boot Actuator exposure checker.
Use only on systems you own or are explicitly authorized to assess.
Does not download heap dumps, submit state-changing requests, or print response bodies.
"""
import argparse
import concurrent.futures
import datetime as dt
import html
import json
import re
import sys
import time
from urllib.parse import urljoin, urlparse, urlunparse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Missing dependency. Install with: python -m pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2)

VERSION = "1.0.0"
DEFAULT_PATHS = [
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/metrics",
    "/actuator/prometheus", "/actuator/mappings", "/actuator/beans",
    "/actuator/env", "/actuator/configprops", "/actuator/conditions",
    "/actuator/loggers", "/actuator/threaddump", "/actuator/scheduledtasks",
    "/actuator/caches", "/actuator/auditevents", "/actuator/httpexchanges",
    "/actuator/sessions", "/actuator/flyway", "/actuator/liquibase",
    "/actuator/quartz", "/actuator/startup", "/actuator/features",
    "/actuator/refresh", "/actuator/busrefresh",
    # Common legacy/context-path/custom mappings; heuristic only.
    "/manage", "/manage/health", "/management/health", "/actuator/health/readiness",
    "/actuator/health/liveness",
]
# Endpoints intentionally excluded because requests could retrieve large sensitive artifacts
# or mutate state. They are reported as "not actively probed".
SENSITIVE_NOT_PROBED = [
    "/actuator/heapdump", "/actuator/logfile", "/actuator/shutdown",
    "/actuator/env (write methods)", "/actuator/loggers (write methods)",
    "/actuator/sessions (DELETE)", "/actuator/caches (DELETE)",
    "/actuator/refresh", "/actuator/busrefresh",
]

def norm_base(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty URL")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Use an http:// or https:// URL")
    if p.username or p.password:
        raise ValueError("Credentials in URLs are not supported; use a dedicated test environment.")
    path = p.path.rstrip("/") + "/" if p.path else "/"
    return urlunparse((p.scheme, p.netloc, path, "", "", ""))

def load_paths(pathfile):
    if not pathfile:
        return list(DEFAULT_PATHS)
    out = []
    with open(pathfile, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                if not s.startswith("/"):
                    s = "/" + s
                # Avoid accidentally scanning a different host or injecting query strings.
                if "://" in s or "?" in s or "#" in s:
                    raise ValueError(f"Invalid path entry: {s}")
                out.append(s)
    return list(dict.fromkeys(out))

def classify(status, ctype, body, location):
    b = body[:250000].lower()
    if status in (401, 403):
        return "PROTECTED", "Endpoint responded with an authentication/authorization denial."
    if status == 404:
        return "NOT_FOUND", "Not found at this path; it may be disabled or mapped elsewhere."
    if status in (301, 302, 303, 307, 308):
        return "REDIRECT", "Redirect observed; inspect destination manually."
    if status == 429:
        return "RATE_LIMITED", "Rate limit observed; scanner will not retry aggressively."
    if status >= 500:
        return "SERVER_ERROR", "Server error; not proof of Actuator exposure."
    if status in (200, 206):
        if any(x in b for x in [b'"_links"', b'"_embedded"', b'"status"', b'"propertysources"',
                                 b'"contexts"', b'"bean"', b'"mappings"', b'"names"', b'"measurements"',
                                 b'"availabletags"', b'"scheduledtasks"', b'"loggers"']):
            if "health" in location and (b'"status"' in b):
                return "PUBLIC_HEALTH", "Health endpoint appears publicly readable; assess whether detail is sensitive."
            if any(x in location for x in ["/env", "/configprops", "/beans", "/mappings",
                                            "/threaddump", "/auditevents", "/httpexchanges",
                                            "/sessions", "/scheduledtasks", "/conditions"]):
                return "POTENTIAL_EXPOSURE", "Response resembles a sensitive Actuator endpoint; review impact without collecting secrets."
            if location.endswith("/actuator") or location.endswith("/manage"):
                return "ACTUATOR_INDEX", "Response resembles an Actuator discovery document."
            return "ACTUATOR_RESPONSE", "Response resembles Actuator data; verify endpoint identity and sensitivity."
        if "prometheus" in location and (b"# help" in b or b"# type" in b):
            return "POTENTIAL_EXPOSURE", "Prometheus metrics endpoint appears readable."
        if "json" in ctype and (b'"status"' in b or b'"_links"' in b):
            return "POSSIBLE_ACTUATOR", "JSON response may be an Actuator endpoint; manual validation needed."
        return "HTTP_200_REVIEW", "HTTP success, but Actuator exposure was not confirmed by response markers."
    return "OTHER", "No obvious Actuator signature."

def probe(base, path, timeout, verify_tls, headers, auth):
    url = urljoin(base, path.lstrip("/")) if base.endswith("/") else base + path
    # urljoin with a leading slash would discard a user-supplied context path; intentionally append path.
    start = time.time()
    try:
        r = requests.get(
            url, headers=headers, auth=auth, timeout=timeout, verify=verify_tls,
            allow_redirects=False, stream=True
        )
        # Read only a small bounded sample, never save it to reports.
        chunks, size = [], 0
        for chunk in r.iter_content(chunk_size=4096):
            if not chunk:
                break
            take = chunk[:max(0, 16384-size)]
            chunks.append(take); size += len(take)
            if size >= 16384:
                break
        body = b"".join(chunks)
        ctype = r.headers.get("Content-Type", "")
        loc = r.headers.get("Location", "")
        category, note = classify(r.status_code, ctype, body, path)
        return {
            "path": path, "url": url, "status": r.status_code,
            "content_type": ctype, "bytes_sampled": len(body),
            "elapsed_ms": round((time.time()-start)*1000),
            "category": category, "note": note,
            "redirect_location": loc[:300] if loc else "",
            "server_header": r.headers.get("Server", "")[:120],
        }
    except RequestException as e:
        return {"path": path, "url": url, "status": None, "content_type": "",
                "bytes_sampled": 0, "elapsed_ms": round((time.time()-start)*1000),
                "category": "ERROR", "note": type(e).__name__ + ": " + str(e)[:180],
                "redirect_location": "", "server_header": ""}

def write_html(report, outfile):
    rows = []
    for x in report["results"]:
        rows.append("<tr>" + "".join("<td>" + html.escape(str(x.get(k, ""))) + "</td>"
                     for k in ("status", "category", "path", "elapsed_ms", "content_type", "note")) + "</tr>")
    doc = """<!doctype html><html><head><meta charset="utf-8"><title>Actuator Scout Report</title>
<style>body{font:14px system-ui;margin:2rem;color:#202124}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:.55rem;text-align:left;vertical-align:top}
th{background:#f3f4f6}code{overflow-wrap:anywhere}.warn{padding:1rem;background:#fff4d6}</style></head><body>
<h1>Actuator Scout Report</h1><p>Generated: """ + html.escape(report["generated_at"]) + """</p>
<p>Target: <code>""" + html.escape(report["target"]) + """</code></p>
<div class="warn"><b>Interpretation:</b> automated results are leads, not confirmed vulnerabilities.
No response bodies or secrets are included in this report. Only GET requests were sent.</div>
<p>Requests: """ + str(report["summary"]["total"]) + """; possible exposures: """ + str(report["summary"]["potential"]) + """</p>
<table><thead><tr><th>Status</th><th>Classification</th><th>Path</th><th>ms</th><th>Content-Type</th><th>Assessment</th></tr></thead>
<tbody>""" + "".join(rows) + """</tbody></table>
<h2>Not actively probed</h2><ul>""" + "".join("<li>"+html.escape(x)+"</li>" for x in report["not_probed"]) + """</ul>
<p>For authorized defensive testing only.</p></body></html>"""
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(doc)

def main():
    ap = argparse.ArgumentParser(description="Conservative Spring Boot Actuator exposure checker")
    ap.add_argument("-u", "--url", help="Base URL, e.g. https://lab.example/app/")
    ap.add_argument("--targets", help="File containing one authorized base URL per line")
    ap.add_argument("--paths", help="Optional file of paths (one path per line)")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--delay", type=float, default=0.05, help="Pause between scheduled requests (seconds)")
    ap.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification (lab use only)")
    ap.add_argument("--header", action="append", default=[], help="Extra header, e.g. 'Authorization: Bearer TESTTOKEN'")
    ap.add_argument("--basic-user", help="Basic-auth username for authorized testing")
    ap.add_argument("--basic-pass", help="Basic-auth password for authorized testing")
    ap.add_argument("--json", default="actuator-scout.json", help="JSON report path")
    ap.add_argument("--html", default="actuator-scout.html", help="HTML report path")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args()

    targets = []
    if args.url:
        targets.append(args.url)
    if args.targets:
        with open(args.targets, encoding="utf-8") as f:
            targets.extend(line.strip() for line in f if line.strip() and not line.lstrip().startswith("#"))
    if not targets:
        ap.error("Provide --url or --targets. Only scan assets you own or are authorized to test.")
    if args.workers < 1 or args.workers > 8:
        ap.error("--workers must be between 1 and 8")
    if args.timeout <= 0 or args.timeout > 30:
        ap.error("--timeout must be >0 and <=30")
    paths = load_paths(args.paths)
    headers = {}
    for h in args.header:
        if ":" not in h:
            ap.error("--header must use 'Name: value'")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    auth = (args.basic_user, args.basic_pass or "") if args.basic_user is not None else None

    all_reports = []
    for raw in targets:
        try:
            base = norm_base(raw)
        except ValueError as e:
            print(f"[!] Skipping {raw!r}: {e}", file=sys.stderr); continue
        print(f"\n[*] Target: {base} | paths: {len(paths)} | workers: {args.workers}")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = []
            for p in paths:
                futures.append(pool.submit(probe, base, p, args.timeout, not args.insecure, headers, auth))
                if args.delay > 0:
                    time.sleep(args.delay)
            for fut in concurrent.futures.as_completed(futures):
                item = fut.result(); results.append(item)
                status = item["status"] if item["status"] is not None else "ERR"
                print(f"[{status}] {item['category']:<20} {item['path']}")
        results.sort(key=lambda x: x["path"])
        potential = sum(x["category"] in ("POTENTIAL_EXPOSURE", "ACTUATOR_INDEX", "ACTUATOR_RESPONSE",
                                            "POSSIBLE_ACTUATOR") for x in results)
        report = {
            "tool": "Actuator Scout", "version": VERSION, "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "target": base, "method": "GET only", "results": results,
            "not_probed": SENSITIVE_NOT_PROBED,
            "summary": {"total": len(results), "potential": potential,
                        "protected": sum(x["category"] == "PROTECTED" for x in results),
                        "errors": sum(x["category"] == "ERROR" for x in results)},
            "limitations": ["Heuristic detection; false positives and false negatives are possible.",
                            "Custom management paths, ports, proxies, and context paths may require a custom --paths file.",
                            "No state-changing methods or large sensitive artifacts are requested."]
        }
        all_reports.append(report)
    if not all_reports:
        raise SystemExit(2)
    combined = {"tool": "Actuator Scout", "version": VERSION,
                "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "reports": all_reports,
                "summary": {"targets": len(all_reports),
                            "total": sum(r["summary"]["total"] for r in all_reports),
                            "potential": sum(r["summary"]["potential"] for r in all_reports)}}
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)
    # HTML output is one report per target for clarity; for multi-target scans, write all as separate sections.
    if len(all_reports) == 1:
        write_html(all_reports[0], args.html)
    else:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write("<!doctype html><meta charset='utf-8'><title>Actuator Scout</title><h1>Multi-target JSON report</h1><p>See the JSON report for all results.</p>")
    print(f"\n[+] JSON report: {args.json}\n[+] HTML report: {args.html}")
    print("[!] Review findings manually; HTTP 200 alone is not proof of a vulnerability.")

if __name__ == "__main__":
    main()
