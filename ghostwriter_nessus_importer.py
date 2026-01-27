#!/usr/bin/env python3
import argparse
import json
import time
import html
import sys
import xml.etree.ElementTree as ET

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# --- Constants & GraphQL ---

Q_WHOAMI = """
query Whoami { whoami { username role expires } }
"""

Q_SEVERITIES = """
query ListSeverities { findingSeverity { id severity } }
"""

M_INSERT = """
mutation CreateReportedFinding($obj: reportedFinding_insert_input!) {
  insert_reportedFinding_one(object: $obj) { id title }
}
"""


# --- Helper Functions (Formatting) ---

def to_richtext_html(text: str) -> str:
    """
    Convert plain text to safe HTML that Ghostwriter's DOCX exporter can handle.
    - Escapes <, >, &, quotes
    - Wraps content in <p> blocks
    """
    if text is None:
        return "<p></p>"
    t = text.strip()
    if not t:
        return "<p></p>"

    # Normalize newlines
    t = t.replace("\r\n", "\n").replace("\r", "\n")

    # Split into paragraphs on blank lines
    paras = []
    for chunk in t.split("\n\n"):
        chunk = chunk.strip()
        if not chunk:
            continue
        # Escape special HTML chars
        safe = html.escape(chunk)
        # Keep single newlines as <br/>
        safe = safe.replace("\n", "<br/>")
        paras.append(f"<p>{safe}</p>")

    return "".join(paras) if paras else "<p></p>"


def to_pre_blocks(outputs):
    """
    plugin_output can be long. Render as <pre> blocks and keep it safe.
    """
    if not outputs:
        return "<p></p>"
    blocks = []
    for out in outputs:
        out = (out or "").strip()
        if not out:
            continue
        safe = html.escape(out.replace("\r\n", "\n").replace("\r", "\n"))
        blocks.append(f"<pre>{safe}</pre>")
    return "<hr/>".join(blocks) if blocks else "<p></p>"


def severity_label_from_nessus_num(n):
    # Nessus: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "informational"}.get(n, "informational")


# --- Core Classes ---

class NessusParser:
    """
    Handles parsing of .nessus XML files and grouping findings by Plugin ID.
    Deterministic and offline.
    """
    def __init__(self, source_path):
        self.source_path = source_path
        self.findings = {}  # Dict[plugin_id] -> finding_dict

    def parse(self):
        """
        Parses the Nessus file and populates self.findings.
        """
        try:
            tree = ET.parse(self.source_path)
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse XML: {e}")

        root = tree.getroot()
        report = root.find("Report") or root.find(".//Report")
        if report is None:
            raise ValueError("Could not find <Report> in .nessus file")

        for host in report.findall("ReportHost"):
            host_name = host.get("name") or "unknown-host"
            for item in host.findall("ReportItem"):
                self._process_item(item, host_name)
        
        return self.findings

    def _process_item(self, item, host_name):
        plugin_id = int(item.get("pluginID") or 0)
        plugin_name = item.get("pluginName") or "Unnamed Plugin"
        severity_num = int(item.get("severity") or 0)
        port = item.get("port") or "0"
        proto = item.get("protocol") or "tcp"

        if plugin_id not in self.findings:
            description_text = (item.findtext("description") or "").strip()
            solution_text = (item.findtext("solution") or "").strip()
            
            self.findings[plugin_id] = {
                "plugin_id": plugin_id,
                "title": plugin_name,
                "severity_num": severity_num,
                "description_text": description_text, # Raw for reference/AI
                "description": to_richtext_html(description_text or f"Nessus plugin ID: {plugin_id}"),
                "mitigation_text": solution_text, # Raw for reference/AI
                "mitigation": to_richtext_html(solution_text),
                "risk_factor": (item.findtext("risk_factor") or "").strip(),
                "outputs": [],
                "affected_set": set(),
                # These fields are prepared for Ghostwriter matching
                "impact": "<p>Confidentiality, Availability &amp; Integrity Loss</p>",
                "references": "<p></p>"
            }

        p = self.findings[plugin_id]

        # Update max severity if we see a higher one for the same plugin ID
        if severity_num > p["severity_num"]:
            p["severity_num"] = severity_num

        # Track affected entities
        if port and port != "0":
            p["affected_set"].add(f"{host_name}:{port}/{proto}")
        else:
            p["affected_set"].add(host_name)

        # Collect unique outputs (limit 2 per plugin to avoid bloat)
        out = (item.findtext("plugin_output") or "").strip()
        if out and len(p["outputs"]) < 2 and out not in p["outputs"]:
            p["outputs"].append(out)

    def to_jsonl_iter(self):
        """
        Yields prepared finding objects ready for JSONL serialization.
        """
        for plugin_id in sorted(self.findings.keys()):
            p = self.findings[plugin_id]
            
            # Format affected entities final HTML
            affected_lines = "<br/>".join(html.escape(x) for x in sorted(p["affected_set"]))
            affected_html = f"<p>{affected_lines}</p>" if affected_lines else "<p></p>"

            # Format replication steps (outputs)
            replication_html = to_pre_blocks(p["outputs"])
            
            # Final object structure (superset of what Ghostwriter needs)
            yield {
                "plugin_id": plugin_id,
                "severity_num": p["severity_num"],
                "severity_label": severity_label_from_nessus_num(p["severity_num"]),
                
                # Ghostwriter Target Fields
                "title": p["title"],
                "description": p["description"],
                "mitigation": p["mitigation"],
                "impact": p["impact"],
                "affectedEntities": affected_html,
                "replication_steps": replication_html,
                "references": p["references"],
                
                # Raw metadata for enrichment/debugging
                "raw_description": p["description_text"],
                "raw_mitigation": p["mitigation_text"],
                "risk_factor": p["risk_factor"],
            }


class GhostwriterImporter:
    """
    Handles connection to Ghostwriter and importing of findings.
    """
    def __init__(self, gw_url, token, verify_ssl=False, timeout=60):
        self.gw_url = gw_url
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = self._build_session()
        self.severity_map = {}

    def _build_session(self):
        s = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("POST",),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=20, pool_maxsize=20)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    def _gql(self, op_name, query, variables):
        try:
            r = self.session.post(
                self.gw_url,
                json={"operationName": op_name, "query": query, "variables": variables},
                headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            # Try to grab response text for context
            body = ""
            if 'r' in locals() and r:
                 body = (r.text or "")[:1000]
            raise RuntimeError(f"GraphQL request failed: {e}\nHTTP Body: {body}")

        if "errors" in data:
            raise RuntimeError(json.dumps(data["errors"], indent=2))
        return data["data"]

    def connect_and_check_auth(self):
        me = self._gql("Whoami", Q_WHOAMI, {})
        print(f"[+] Connected as: {me['whoami']['username']} ({me['whoami']['role']})")

    def load_severity_map(self):
        data = self._gql("ListSeverities", Q_SEVERITIES, {})
        rows = data["findingSeverity"]
        self.severity_map = {r["severity"].lower(): int(r["id"]) for r in rows}
        print(f"[+] Loaded severity IDs: {self.severity_map}")

    def import_finding(self, finding_data, report_id, finding_type_id=1, dry_run=False):
        """
        Import a single finding dictionary (structure matching NessusParser.to_jsonl_iter output)
        """
        # Map severity label to ID
        sev_label = finding_data.get("severity_label", "informational")
        severity_id = self.severity_map.get(sev_label, self.severity_map.get("informational"))

        # Construct payload
        obj = {
            "reportId": report_id,
            "findingTypeId": finding_type_id,
            "severityId": severity_id,
            "title": finding_data["title"],
            "description": finding_data["description"],
            "mitigation": finding_data["mitigation"],
            "impact": finding_data["impact"],
            "replication_steps": finding_data["replication_steps"],
            "affectedEntities": finding_data["affectedEntities"],
            "references": finding_data["references"],
            "extraFields": finding_data.get("extraFields", {})
        }
        
        # If extraFields wasn't present in input, provide a default
        if "extraFields" not in finding_data:
             obj["extraFields"] = {
                 "nessus": {
                     "plugin_id": finding_data.get("plugin_id"), 
                     "severity_num": finding_data.get("severity_num")
                 }
             }

        if dry_run:
            print(f"[Dry Run] Would insert: {obj['title']}")
            return

        data = self._gql("CreateReportedFinding", M_INSERT, {"obj": obj})
        rid = data["insert_reportedFinding_one"]["id"]
        rtitle = data["insert_reportedFinding_one"]["title"]
        print(f"[+] Created: {rid} - {rtitle}")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(description="Ghostwriter Nessus Importer Pipeline")
    
    # Common arguments
    parser.add_argument("--nessus", help="Path to .nessus input file")
    parser.add_argument("--jsonl", help="Path to .jsonl input/output file")
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--extract", action="store_true", help="Parse .nessus and save to --jsonl")
    mode_group.add_argument("--import-findings", action="store_true", help="Import findings from --jsonl (or --nessus) to Ghostwriter")
    
    # API args (only needed for import)
    api_group = parser.add_argument_group("Ghostwriter API", "Required for --import-findings")
    api_group.add_argument("--gw-url", help='e.g. "https://gw.example.com/v1/graphql"')
    api_group.add_argument("--token", help="Bearer token (JWT)")
    api_group.add_argument("--report-id", type=int, help="Target Report ID")
    api_group.add_argument("--finding-type-id", type=int, default=1, help="findingTypeId (1=Network)")
    api_group.add_argument("--verify-ssl", action="store_true", help="Verify TLS cert")
    api_group.add_argument("--timeout", type=int, default=60, help="HTTP timeout")
    api_group.add_argument("--sleep", type=float, default=0.0, help="Sleep between inserts")
    api_group.add_argument("--dry-run", action="store_true", help="Simulate import")

    args = parser.parse_args()

    # --- EXTRACT MODE ---
    if args.extract:
        if not args.nessus:
            parser.error("--extract requires --nessus input file")
        
        print(f"[*] Parsing {args.nessus}...")
        parser_obj = NessusParser(args.nessus)
        parser_obj.parse()
        
        output_file = args.jsonl or "nessus_findings.jsonl"
        print(f"[*] Writing fields to {output_file}...")
        
        count = 0
        with open(output_file, "w", encoding="utf-8") as f:
            for finding in parser_obj.to_jsonl_iter():
                f.write(json.dumps(finding) + "\n")
                count += 1
        print(f"[+] Extracted {count} findings.")

    # --- IMPORT MODE ---
    elif args.import_findings:
        if not all([args.gw_url, args.token, args.report_id]):
            parser.error("--import-findings requires --gw-url, --token, and --report-id")

        source_findings = []
        
        # Load from JSONL if provided
        if args.jsonl:
            print(f"[*] Loading findings from {args.jsonl}...")
            with open(args.jsonl, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        source_findings.append(json.loads(line))
        # Or load direct from Nessus (Legacy/Convenience flow)
        elif args.nessus:
            print(f"[*] Parsing {args.nessus} for direct import...")
            parser_obj = NessusParser(args.nessus)
            parser_obj.parse()
            source_findings = list(parser_obj.to_jsonl_iter())
        else:
            parser.error("--import-findings requires either --jsonl or --nessus input")

        if not source_findings:
            print("[-] No findings found to import.")
            return

        print(f"[*] Connecting to {args.gw_url}...")
        importer = GhostwriterImporter(args.gw_url, args.token, args.verify_ssl, args.timeout)
        importer.connect_and_check_auth()
        importer.load_severity_map()
        
        print(f"[*] Importing {len(source_findings)} findings...")
        for i, finding in enumerate(source_findings, 1):
            try:
                importer.import_finding(finding, args.report_id, args.finding_type_id, args.dry_run)
                if args.sleep > 0:
                    time.sleep(args.sleep)
            except Exception as e:
                print(f"[!] Error importing finding '{finding.get('title', 'Unknown')}': {e}")
                # Optional: Continue or break? For bulk imports, often better to continue and log errors.
                # We'll continue for now.

if __name__ == "__main__":
    main()
