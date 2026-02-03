#!/usr/bin/env python3
import argparse
import json
import time
import html
import sys
import logging
import os
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Generator, Any

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger("gw_nessus")


# --- Constants & GraphQL ---

Q_WHOAMI = """
query Whoami { whoami { username role expires } }
"""

Q_SEVERITIES = """
query ListSeverities { findingSeverity { id severity } }
"""

Q_FIND_BY_TITLE = """
query FindByTitle($reportId: bigint!, $title: String!) {
  reportedFinding(where: {reportId: {_eq: $reportId}, title: {_eq: $title}}) {
    id
    title
  }
}
"""

M_INSERT = """
mutation CreateReportedFinding($obj: reportedFinding_insert_input!) {
  insert_reportedFinding_one(object: $obj) { id title }
}
"""

M_UPDATE = """
mutation UpdateReportedFinding($id: bigint!, $obj: reportedFinding_set_input!) {
  update_reportedFinding_by_pk(pk_columns: {id: $id}, _set: $obj) {
    id
    title
  }
}
"""


# --- Helper Functions (Formatting) ---

def to_richtext_html(text: Optional[str]) -> str:
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


def to_pre_blocks(outputs: List[str]) -> str:
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


def severity_label_from_nessus_num(n: int) -> str:
    # Nessus: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "informational"}.get(n, "informational")


# --- Core Classes ---

class NessusParser:
    """
    Handles parsing of .nessus XML files and grouping findings by Plugin ID.
    Deterministic and offline.
    """
    def __init__(self, source_path: str):
        self.source_path = source_path
        self.findings: Dict[int, Dict[str, Any]] = {}  # Dict[plugin_id] -> finding_dict

    def parse(self) -> Dict[int, Dict[str, Any]]:
        """
        Parses the Nessus file and populates self.findings.
        """
        try:
            tree = ET.parse(self.source_path)
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse XML: {e}")

        root = tree.getroot()
        report = root.find("Report")
        if report is None:
            report = root.find(".//Report")
        if report is None:
            raise ValueError("Could not find <Report> in .nessus file")

        for host in report.findall("ReportHost"):
            host_name = host.get("name") or "unknown-host"
            for item in host.findall("ReportItem"):
                self._process_item(item, host_name)
        
        return self.findings

    def _process_item(self, item: ET.Element, host_name: str):
        plugin_id = int(item.get("pluginID") or 0)
        plugin_name = item.get("pluginName") or "Unnamed Plugin"
        severity_num = int(item.get("severity") or 0)
        port = item.get("port") or "0"
        proto = item.get("protocol") or "tcp"
        
        # Skip informational findings (severity 0) - only process Low (1) and above
        if severity_num == 0:
            return

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

    def to_jsonl_iter(self) -> Generator[Dict[str, Any], None, None]:
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
    def __init__(self, gw_url: str, token: str, verify_ssl: bool = False, timeout: int = 60):
        self.gw_url = gw_url
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = self._build_session()
        self.severity_map: Dict[str, int] = {}
        self.existing_findings_cache: Dict[str, int] = {}

    def _build_session(self) -> requests.Session:
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

    def _gql(self, op_name: str, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
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
        logger.info(f"Connected as: {me['whoami']['username']} ({me['whoami']['role']})")

    def load_severity_map(self):
        data = self._gql("ListSeverities", Q_SEVERITIES, {})
        rows = data["findingSeverity"]
        self.severity_map = {r["severity"].lower(): int(r["id"]) for r in rows}
        logger.info(f"Loaded severity IDs: {self.severity_map}")

    def check_existing_finding(self, report_id: int, title: str) -> Optional[int]:
        """
        Check existing findings from cache. O(1).
        If cache is empty (e.g. dry run or first run), it returns None (inserts new).
        """
        return self.existing_findings_cache.get(title)

    def import_finding(self, finding_data: Dict[str, Any], report_id: int, finding_type_id: int = 1, dry_run: bool = False):
        """
        Import a single finding dictionary (structure matching NessusParser.to_jsonl_iter output).
        Checks for duplicates and UPDATES if found.
        """
        # Map severity label to ID
        sev_label = finding_data.get("severity_label", "informational")
        severity_id = self.severity_map.get(sev_label, self.severity_map.get("informational"))
        title = finding_data["title"]

        # Construct payload
        obj = {
            "reportId": report_id,
            "findingTypeId": finding_type_id,
            "severityId": severity_id,
            "title": title,
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
            logger.info(f"[Dry Run] Would insert/update: {title}")
            return

        # Check for existence
        existing_id = self.check_existing_finding(report_id, title)

        if existing_id:
            # UPDATE
            # Can't update everything via 'object' in insert, need specific set
            # For simplicity, we update the main fields. ReportID not needed in set.
            update_obj = obj.copy()
            del update_obj["reportId"] 
            
            data = self._gql("UpdateReportedFinding", M_UPDATE, {"id": existing_id, "obj": update_obj})
            rtitle = data["update_reportedFinding_by_pk"]["title"]
            logger.info(f"Updated: {existing_id} - {rtitle}")
        else:
            # INSERT
            data = self._gql("CreateReportedFinding", M_INSERT, {"obj": obj})
            rid = data["insert_reportedFinding_one"]["id"]
            rtitle = data["insert_reportedFinding_one"]["title"]
            logger.info(f"Created: {rid} - {rtitle}")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(description="Ghostwriter Nessus Importer Pipeline")
    
    # Common arguments
    parser.add_argument("--nessus", help="Path to .nessus input file")
    parser.add_argument("--json", help="Path to .json input/output file")
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--extract", action="store_true", help="Parse .nessus and save to --json")
    mode_group.add_argument("--import-findings", action="store_true", help="Import findings from --json (or --nessus) to Ghostwriter")
    
    # API args (can come from Env)
    api_group = parser.add_argument_group("Ghostwriter API", "Required for --import-findings")
    api_group.add_argument("--gw-url", default=os.getenv("GW_URL"), help='Start with https://...')
    api_group.add_argument("--token", default=os.getenv("GW_TOKEN"), help="Bearer token")
    api_group.add_argument("--report-id", type=int, default=os.getenv("GW_REPORT_ID"), help="Target Report ID")
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
        
        logger.info(f"Parsing {args.nessus}...")
        try:
            parser_obj = NessusParser(args.nessus)
            parser_obj.parse()
        except Exception as e:
            logger.error(f"Failed to parse Nessus file: {e}")
            sys.exit(1)
        
        output_file = args.json or "nessus_findings.json"
        logger.info(f"Writing fields to {output_file}...")
        
        findings = []
        for finding in parser_obj.to_jsonl_iter():
            # Redact sensitive info for AI workflow
            finding["affectedEntities"] = ""
            finding["replication_steps"] = ""
            findings.append(finding)
            
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

        logger.info(f"Extracted {len(findings)} findings.")

    # --- IMPORT MODE ---
    elif args.import_findings:
        # Check required API args manually since ID/Token can be env
        if not all([args.gw_url, args.token, args.report_id]):
            parser.error("--import-findings requires --gw-url, --token, and --report-id (via CLI or ENV)")

        source_findings = []
        
        # Load sources into maps for merging
        jsonl_findings_map = {}
        nessus_findings_map = {}

        # 1. Load JSON (Enrichment Source - AI-edited text)
        if args.json:
            logger.info(f"Loading enrichment data from {args.json}...")
            if not os.path.exists(args.json):
                logger.error(f"File not found: {args.json}")
                sys.exit(1)
            try:
                with open(args.json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if not isinstance(data, list):
                        logger.error("JSON file must contain a list of finding objects")
                        sys.exit(1)
                    
                    for obj in data:
                        if "plugin_id" in obj:
                            jsonl_findings_map[obj["plugin_id"]] = obj
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON format in {args.json}: {e}")
                sys.exit(1)
        
        # 2. Load Nessus (Technical Source - hosts, outputs, etc.)
        if args.nessus:
            logger.info(f"Parsing {args.nessus} for technical data (hosts/outputs)...")
            if not os.path.exists(args.nessus):
                logger.error(f"File not found: {args.nessus}")
                sys.exit(1)
            parser_obj = NessusParser(args.nessus)
            parser_obj.parse()
            for obj in parser_obj.to_jsonl_iter():
                nessus_findings_map[obj["plugin_id"]] = obj

        # 3. Merge Strategy
        if args.json and args.nessus:
            logger.info("Merging Nessus technical data with JSON enrichment...")
            # Nessus provides: affectedEntities, replication_steps (technical data)
            # JSON provides: title, description, mitigation (AI-enriched text)
            
            for pid, tech_finding in nessus_findings_map.items():
                if pid in jsonl_findings_map:
                    enrichment = jsonl_findings_map[pid]
                    merged = tech_finding.copy()
                    
                    # Merge enrichment data
                    for key, value in enrichment.items():
                        # Special handling for technical fields we don't want to wipe out if empty in JSON
                        if key in ["affectedEntities", "replication_steps"]:
                            if value:
                                merged[key] = value
                        # For everything else (title, description, custom fields like remediation_cost), 
                        # we want the enrichment version to take precedence.
                        else:
                            merged[key] = value
                        
                    source_findings.append(merged)
                else:
                    # In Nessus but not in JSON - import as-is
                    source_findings.append(tech_finding)
            
            # Check for findings in JSON but NOT in Nessus (manual additions)
            for pid, enrich in jsonl_findings_map.items():
                if pid not in nessus_findings_map:
                    source_findings.append(enrich)

        # Case: Only JSON provided
        elif args.json:
            source_findings = list(jsonl_findings_map.values())
            
        # Case: Only Nessus provided
        elif args.nessus:
             source_findings = list(nessus_findings_map.values())
             
        else:
            parser.error("--import-findings requires either --json or --nessus input (or both for merge!)")

        Q_GET_REPORT_FINDINGS = """
query GetReportFindings($reportId: bigint!) {
  reportedFinding(where: {reportId: {_eq: $reportId}}) {
    id
    title
  }
}
"""

        M_BULK_INSERT = """
mutation CreateReportedFindings($objects: [reportedFinding_insert_input!]!) {
  insert_reportedFinding(objects: $objects) {
    affected_rows
    returning { id title }
  }
}
"""

        if not source_findings:
            logger.warning("No findings found to import.")
            return

        logger.info(f"Connecting to {args.gw_url}...")
        importer = GhostwriterImporter(args.gw_url, args.token, args.verify_ssl, args.timeout)
        try:
            importer.connect_and_check_auth()
            importer.load_severity_map()
            if not args.dry_run:
                findings_data = importer._gql("GetReportFindings", Q_GET_REPORT_FINDINGS, {"reportId": args.report_id})
                existing = findings_data.get("reportedFinding", [])
                importer.existing_findings_cache = {f["title"]: f["id"] for f in existing}
                logger.info(f"Cached {len(importer.existing_findings_cache)} existing findings for optimization.")
        except Exception as e:
            logger.critical(f"Connection/Setup failed: {e}")
            sys.exit(1)
        
        logger.info(f"Processing {len(source_findings)} findings...")
        
        to_create = []
        to_update = []
        
        # Prepare objects
        for finding in source_findings:
            # Map severity
            sev_label = finding.get("severity_label", "informational")
            severity_id = importer.severity_map.get(sev_label, importer.severity_map.get("informational"))
            title = finding["title"]
            
            # Core required fields
            obj = {
                "reportId": args.report_id,
                "findingTypeId": args.finding_type_id,
                "severityId": severity_id,
                "title": title,
                "description": finding["description"],
                "mitigation": finding["mitigation"],
                "impact": finding["impact"],
                "replication_steps": finding.get("replication_steps", ""),
                "affectedEntities": finding.get("affectedEntities", ""),
                "references": finding.get("references", "<p></p>"),
            }
            
            # Pass through additional custom fields from enriched JSON
            # These are fields like ease_of_detection, remediation_cost, remediation_short, etc.
            # GW schema doesn't have these on root, so we MUST put them in extraFields.
            custom_extra_fields = {}
            core_fields = {
                "plugin_id", "severity_num", "severity_label", "title", "description", 
                "mitigation", "impact", "replication_steps", "affectedEntities", "references",
                "raw_description", "raw_mitigation", "risk_factor", "extraFields"
            }
            for key, value in finding.items():
                if key not in core_fields:
                    custom_extra_fields[key] = value
            
            # Prepare final extraFields
            # 1. Start with any explicit extraFields from JSON
            existing_extra = finding.get("extraFields")
            final_extra_fields = (existing_extra if existing_extra is not None else {}).copy()
            
            # 2. Add Nessus metadata if not present
            if "nessus" not in final_extra_fields:
                final_extra_fields["nessus"] = {
                    "plugin_id": finding.get("plugin_id"), 
                    "severity_num": finding.get("severity_num")
                }
            
            # 3. Merge in our discovered custom fields
            final_extra_fields.update(custom_extra_fields)
            
            obj["extraFields"] = final_extra_fields
            
            existing_id = importer.check_existing_finding(args.report_id, title)
            if existing_id:
                to_update.append((existing_id, obj))
            else:
                to_create.append(obj)

        # Bulk Insert New
        if to_create:
            logger.info(f"Bulk inserting {len(to_create)} new findings...")
            if args.dry_run:
                for obj in to_create:
                    logger.info(f"[Dry Run] Would insert: {obj['title']}")
                    logger.info(f"  > extraFields: {json.dumps(obj.get('extraFields', {}), indent=2)}")
            else:
                try:
                    # GraphQL Mutation for Bulk
                    # We reuse M_BULK_INSERT defined above (ensure it's added to constants)
                    data = importer._gql("CreateReportedFindings", M_BULK_INSERT, {"objects": to_create})
                    count = data["insert_reportedFinding"]["affected_rows"]
                    logger.info(f"Successfully bulk created {count} findings.")
                except Exception as e:
                    logger.error(f"Bulk insert failed: {e}")

        # Sequential Update
        if to_update:
            logger.info(f"Updating {len(to_update)} existing findings...")
            for existing_id, obj in to_update:
                if args.dry_run:
                    logger.info(f"[Dry Run] Would update: {obj['title']}")
                    continue
                
                try:
                    update_obj = obj.copy()
                    del update_obj["reportId"]
                    importer._gql("UpdateReportedFinding", M_UPDATE, {"id": existing_id, "obj": update_obj})
                    logger.info(f"Updated: {existing_id} - {obj['title']}")
                    if args.sleep > 0:
                        time.sleep(args.sleep)
                except Exception as e:
                    logger.error(f"Update failed for '{obj['title']}': {e}")


if __name__ == "__main__":
    main()
