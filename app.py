#!/usr/bin/env python3
import os
import tempfile
import json
import logging
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    request,
    send_file,
    render_template_string,
    redirect,
    url_for,
    flash,
)

from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Import our core logic
from ghostwriter_nessus_importer import NessusParser, GhostwriterImporter

app = Flask(__name__)
app.secret_key = "change-this-secret-key-for-production"

# Reuse the user's styling
STYLE_CSS = """
        :root {
            --bg: #05060a;
            --bg-elevated: #0b0e12;
            --bg-card: #111418;
            --border-soft: #1e242b;
            --border-strong: #2a323c;
            --accent: #2faa71;
            --accent-hover: #289162;
            --text: #f0f3f5;
            --muted: #9aa5b1;
            --radius-lg: 12px;
            --radius-xl: 16px;
            --shadow-soft: 0 2px 6px rgba(0,0,0,0.28);
            --transition-fast: 0.15s ease;
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .wrapper { width: 100%; max-width: 900px; padding: 20px; }

        .card {
            background: var(--bg-card);
            border-radius: var(--radius-xl);
            border: 1px solid var(--border-soft);
            box-shadow: var(--shadow-soft);
            padding: 22px 26px;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
        }
        
        .title { font-size: 1.3rem; font-weight: 600; }
        .subtitle { font-size: 0.9rem; color: var(--muted); }
        .pill { 
            font-size: 0.7rem; background: var(--bg-elevated); 
            border: 1px solid var(--border-soft); border-radius: 999px; 
            padding: 4px 9px; color: var(--muted); 
        }

        .tabs {
            display: flex; gap: 8px; margin: 12px 0 18px; 
            padding-bottom: 10px; border-bottom: 1px solid var(--border-soft);
        }
        .tab {
            text-decoration: none; color: var(--muted); background: var(--bg-elevated);
            border: 1px solid var(--border-soft); border-radius: 999px; padding: 7px 12px;
            font-size: 0.82rem; transition: 0.15s ease;
        }
        .tab:hover { background: #15191f; border-color: var(--border-strong); color: var(--text); }
        .tab.active { background: var(--bg-card); border-color: var(--border-strong); color: var(--text); }

        .grid-layout { display: grid; grid-template-columns: minmax(0, 1.8fr) minmax(0, 1.2fr); gap: 22px; }
        
        .dropzone {
            display: block;
            border: 1px solid var(--border-soft); background: var(--bg-elevated);
            border-radius: var(--radius-lg); padding: 20px; cursor: pointer;
            transition: 0.15s ease;
        }
        .dropzone:hover { background: #15191f; border-color: var(--border-strong); }
        .dropzone.dragover { background: #181d24; border-color: var(--border-strong); }
        
        .dropzone-icon-circle {
            width: 38px; height: 38px; background: var(--bg-card);
            border: 1px solid var(--border-soft); border-radius: 50%;
            display: flex; align-items: center; justify-content: center; margin-bottom: 10px;
        }
        .dropzone-title { font-size: 0.95rem; font-weight: 500; }
        .dropzone-subtitle { font-size: 0.8rem; color: var(--muted); }
        .file-list { margin-top: 10px; font-size: 0.78rem; color: var(--muted); display: flex; flex-wrap: wrap; gap: 6px; }
        .file-pill { background: var(--bg-card); border: 1px solid var(--border-soft); border-radius: 999px; padding: 3px 8px; }
        input[type="file"] { display: none; }

        .side-panel {
            background: var(--bg-elevated); border: 1px solid var(--border-soft);
            border-radius: var(--radius-lg); padding: 16px 18px;
        }
        .side-title { font-size: 0.9rem; font-weight: 500; margin-bottom: 4px; }
        .side-subtitle { font-size: 0.78rem; color: var(--muted); margin-bottom: 12px; }
        
        .field-group { margin-bottom: 12px; }
        .field-label { font-size: 0.78rem; color: var(--muted); margin: 0 0 4px; }
        .text-input {
            width: 100%; background: var(--bg-card); border: 1px solid var(--border-soft);
            border-radius: 8px; padding: 8px 10px; color: var(--text); outline: none;
            font-size: 0.85rem;
        }
        .text-input:focus { border-color: var(--border-strong); }
        
        .checkbox-item { display: flex; align-items: center; gap: 8px; font-size: 0.82rem; margin-top: 6px; }

        .actions { display: flex; justify-content: flex-end; margin-top: 20px; }
        .btn-primary {
            background: var(--accent); border: none; border-radius: 999px;
            padding: 10px 22px; color: #fff; font-size: 0.9rem; cursor: pointer;
            transition: 0.15s ease;
        }
        .btn-primary:hover { background: var(--accent-hover); }

        .flash { margin-top: 10px; font-size: 0.8rem; padding: 10px; border-radius: var(--radius-lg); }
        .flash-error { background: rgba(180,35,35,0.15); border: 1px solid rgba(180,35,35,0.35); color: #ffbaba; }
        .flash-success { background: var(--accent-bg); border: 1px solid var(--accent); color: var(--accent); }
        .flash-info { background: rgba(56, 124, 255, 0.1); border: 1px solid rgba(56, 124, 255, 0.3); color: #a0c4ff; }

        pre { 
            background: #000; padding: 10px; border-radius: 8px; overflow-x: auto; 
            font-size: 0.75rem; color: #ccc; border: 1px solid var(--border-soft);
            max-height: 200px;
        }
        
        @media (max-width: 820px) { .grid-layout { grid-template-columns: 1fr; } }
"""

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Ghostwriter Nessus Importer</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>""" + STYLE_CSS + """</style>
</head>
<body>
<div class="wrapper">
    <div class="card">
        <div class="header">
            <div>
                <div class="title">Ghostwriter Nessus Importer</div>
                <div class="subtitle">Extract findings to JSON or Import directly to Ghostwriter</div>
            </div>
            <div class="pill">v1.1</div>
        </div>

        <div class="tabs">
            <a class="tab active" href="{{ url_for('extract_page') }}">Extract to JSON</a>
            <a class="tab" href="{{ url_for('import_page') }}">Import to Ghostwriter</a>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, msg in messages %}
              <div class="flash flash-{{ category }}">{{ msg|safe }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <form method="POST" action="{{ url_for('extract_submit') }}" enctype="multipart/form-data">
            <div class="grid-layout">
                <label class="dropzone" id="dropzone">
                    <div class="dropzone-icon-circle"><span class="dropzone-icon">📄</span></div>
                    <div>
                        <div class="dropzone-title" id="file-label">Drop .nessus file here</div>
                        <div class="dropzone-subtitle">Generates a JSON file for enrichment.</div>
                        <div class="file-list" id="file-list"></div>
                    </div>
                    <input type="file" id="nessus-file" name="nessus_file" accept=".nessus" required>
                </label>

                <div class="side-panel">
                    <div class="side-title">Extraction Info</div>
                    <div class="side-subtitle">
                        Parses Nessus XML and converts it to a clean JSON format.
                    </div>
                    <div class="info-box" style="font-size:0.8rem; color:var(--muted)">
                        <ul>
                            <li>Excludes informational findings</li>
                            <li>Groups by Plugin ID</li>
                            <li>Redacts sensitive outputs</li>
                        </ul>
                    </div>
                </div>
            </div>

            <div class="actions">
                <button type="submit" class="btn-primary">Download JSON</button>
            </div>
        </form>
    </div>
</div>
<script>
    const fileInput = document.getElementById('nessus-file');
    const fileLabel = document.getElementById('file-label');
    const fileListEl = document.getElementById('file-list');
    const dropzone = document.getElementById('dropzone');

    function updateFileList(files) {
        fileListEl.innerHTML = '';
        if (!files || files.length === 0) {
            fileLabel.textContent = "Drop .nessus file here";
            return;
        }
        fileLabel.textContent = files[0].name;
        const pill = document.createElement('span');
        pill.className = 'file-pill';
        pill.textContent = files[0].name;
        fileListEl.appendChild(pill);
    }

    fileInput.addEventListener('change', () => updateFileList(fileInput.files));

    ['dragenter', 'dragover'].forEach(evt => {
        dropzone.addEventListener(evt, (e) => {
            e.preventDefault(); e.stopPropagation(); dropzone.classList.add('dragover');
        });
    });
    ['dragleave', 'dragend', 'drop'].forEach(evt => {
        dropzone.addEventListener(evt, (e) => {
            e.preventDefault(); e.stopPropagation(); dropzone.classList.remove('dragover');
        });
    });
    dropzone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files;
            updateFileList(files);
        }
    });
</script>
</body>
</html>
"""

IMPORT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Ghostwriter Nessus Importer</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>""" + STYLE_CSS + """</style>
</head>
<body>
<div class="wrapper">
    <div class="card">
        <div class="header">
            <div>
                <div class="title">Ghostwriter Nessus Importer</div>
                <div class="subtitle">Import findings (Nessus and/or JSON) into Ghostwriter</div>
            </div>
            <div class="pill">v1.2</div>
        </div>

        <div class="tabs">
            <a class="tab" href="{{ url_for('extract_page') }}">Extract to JSON</a>
            <a class="tab active" href="{{ url_for('import_page') }}">Import to Ghostwriter</a>
        </div>

        <div id="flash-container">
            {% with messages = get_flashed_messages(with_categories=true) %}
              {% if messages %}
                {% for category, msg in messages %}
                  <div class="flash flash-{{ category }}">{{ msg|safe }}</div>
                {% endfor %}
              {% endif %}
            {% endwith %}
        </div>

        <form id="import-form" method="POST" action="{{ url_for('import_submit') }}" enctype="multipart/form-data">
            <div class="grid-layout">
                <div style="display:flex; flex-direction:column; gap:15px;">
                    <label class="dropzone" id="dz-nessus">
                        <div class="dropzone-icon-circle"><span class="dropzone-icon">N</span></div>
                        <div>
                            <div class="dropzone-title" id="lbl-nessus">Drop .nessus file (Optional)</div>
                            <div class="dropzone-subtitle">Technical data source</div>
                        </div>
                        <input type="file" id="nessus-file" name="nessus_file" accept=".nessus">
                    </label>

                    <label class="dropzone" id="dz-json">
                        <div class="dropzone-icon-circle"><span class="dropzone-icon">J</span></div>
                        <div>
                            <div class="dropzone-title" id="lbl-json">Drop .json file (Optional)</div>
                            <div class="dropzone-subtitle">Enriched data source</div>
                        </div>
                         <input type="file" id="json-file" name="json_file" accept=".json">
                    </label>
                    <div style="font-size:0.8rem; color:var(--muted)">* Upload at least one file. Combined upload enables merge mode.</div>
                </div>

                <div class="side-panel">
                    <div class="side-title">Ghostwriter Credentials</div>
                    <div class="side-subtitle">Leave blank if using uploaded .env</div>
                    
                    <div class="field-group">
                        <div class="field-label">GraphQL URL</div>
                        <input type="text" class="text-input" id="inp-url" name="gw_url" placeholder="https://gw.example.com/v1/graphql" value="{{ default_url }}">
                    </div>
                     <div class="field-group">
                        <div class="field-label">Bearer Token</div>
                        <input type="password" class="text-input" id="inp-token" name="gw_token" placeholder="Bearer Token">
                    </div>
                     <div class="field-group">
                        <div class="field-label">Report ID</div>
                        <input type="number" class="text-input" id="inp-rid" name="report_id" placeholder="123" value="{{ default_rid }}">
                    </div>
                    
                    <div class="side-title" style="margin-top:15px">Options</div>
                    <div class="checkbox-item">
                        <input type="checkbox" id="dry_run" name="dry_run">
                        <label for="dry_run">Dry Run (Simulate only)</label>
                    </div>
                     <div class="field-group" style="margin-top:10px">
                        <div class="field-label">Or drop .env file here to auto-fill</div>
                        <label class="dropzone" id="dz-env" style="padding: 10px; border-style: dashed; min-height: 60px;">
                            <div style="font-size: 0.8rem; text-align: center; color: var(--muted);" id="lbl-env">
                                Drop .env
                            </div>
                            <!-- Hidden input purely for drag-drop logic, not sent to server now we parse client side -->
                            <input type="file" id="env-file-input" accept=".env"> 
                        </label>
                    </div>
                </div>
            </div>

            <div class="actions">
                <button type="submit" id="btn-submit" class="btn-primary">Start Import</button>
            </div>
        </form>
    </div>
</div>
<script>
    function setupDropzone(id, inputId, labelId, defaultText) {
        const dz = document.getElementById(id);
        const inp = document.getElementById(inputId);
        const lbl = document.getElementById(labelId);
        
        inp.addEventListener('change', () => {
            if(inp.files.length > 0) {
                lbl.textContent = inp.files[0].name;
                dz.classList.add('active-file'); 
            } else {
                lbl.textContent = defaultText;
                dz.classList.remove('active-file');
            }
        });
        
        ['dragenter', 'dragover'].forEach(evt => {
            dz.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); dz.classList.add('dragover'); });
        });
         ['dragleave', 'dragend', 'drop'].forEach(evt => {
            dz.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); dz.classList.remove('dragover'); });
        });
        dz.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if(files.length > 0) {
                inp.files = files;
                lbl.textContent = files[0].name;
                dz.classList.add('active-file');
            }
        });
    }
    
    setupDropzone('dz-nessus', 'nessus-file', 'lbl-nessus', 'Drop .nessus file (Optional)');
    setupDropzone('dz-json', 'json-file', 'lbl-json', 'Drop .json file (Optional)');

    // --- .ENV Parsing Logic ---
    const dzEnv = document.getElementById('dz-env');
    const lblEnv = document.getElementById('lbl-env');

    ['dragenter', 'dragover'].forEach(evt => {
        dzEnv.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); dzEnv.classList.add('dragover'); });
    });
     ['dragleave', 'dragend', 'drop'].forEach(evt => {
        dzEnv.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); dzEnv.classList.remove('dragover'); });
    });

    dzEnv.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if(files.length > 0) {
            parseEnvFile(files[0]);
        }
    });
    
    // Also support clicking to select
    document.getElementById('env-file-input').addEventListener('change', (e) => {
        if(e.target.files.length > 0) parseEnvFile(e.target.files[0]);
    });

    function parseEnvFile(file) {
        lblEnv.textContent = "Parsing " + file.name + "...";
        const reader = new FileReader();
        reader.onload = function(e) {
            const text = e.target.result;
            const lines = text.split(/\\r?\\n/);
            let found = 0;
            lines.forEach(line => {
                const match = line.match(/^\\s*([A-Z_]+)\\s*=\\s*(.*)$/);
                if(match) {
                    const key = match[1];
                    let val = match[2].trim();
                    // Remove quotes if present
                    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
                        val = val.slice(1, -1);
                    }
                    
                    if(key === 'GW_URL') document.getElementById('inp-url').value = val;
                    if(key === 'GW_TOKEN') document.getElementById('inp-token').value = val;
                    if(key === 'GW_REPORT_ID') document.getElementById('inp-rid').value = val;
                    found++;
                }
            });
            lblEnv.textContent = `Loaded ${found} vars from ${file.name}`;
            setTimeout(() => lblEnv.textContent = "Drop .env", 3000);
        };
        reader.readAsText(file);
    }

    // --- AJAX Form Submission ---
    const form = document.getElementById('import-form');
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = document.getElementById('btn-submit');
        const flashContainer = document.getElementById('flash-container');
        
        // Reset UI
        btn.disabled = true;
        btn.textContent = "Processing...";
        flashContainer.innerHTML = "";

        const formData = new FormData(form);
        // Add ajax flag
        formData.append('ajax', '1');

        try {
            const response = await fetch(form.action, {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            // Render message
            const div = document.createElement('div');
            div.className = `flash flash-${data.category}`;
            div.innerHTML = data.message;
            flashContainer.appendChild(div);
            
            // Scroll to top
            window.scrollTo({ top: 0, behavior: 'smooth' });
            
        } catch (err) {
            const div = document.createElement('div');
            div.className = 'flash flash-error';
            div.textContent = "Request failed: " + err;
            flashContainer.appendChild(div);
        } finally {
            btn.disabled = false;
            btn.textContent = "Start Import";
        }
    });

</script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def extract_page():
    return render_template_string(INDEX_HTML)

@app.route("/import", methods=["GET"])
def import_page():
    # Pre-fill defaults if present in system env (optional convenience)
    default_url = os.getenv("GW_URL", "")
    default_rid = os.getenv("GW_REPORT_ID", "")
    return render_template_string(IMPORT_HTML, default_url=default_url, default_rid=default_rid)

@app.route("/extract", methods=["POST"])
def extract_submit():
    f = request.files.get("nessus_file")
    if not f or not f.filename:
        flash("Please upload a .nessus file.", "error")
        return redirect(url_for("extract_page"))
    
    temp_dir = tempfile.mkdtemp(prefix="gw_nessus_")
    nessus_path = os.path.join(temp_dir, secure_filename(f.filename))
    f.save(nessus_path)
    
    output_path = os.path.join(temp_dir, "extracted_findings.json")
    
    try:
        # Reusing the existing classes logic manually 
        # to avoid calling the full main() arg parser
        parser_obj = NessusParser(nessus_path)
        parser_obj.parse()
        
        findings = []
        for finding in parser_obj.to_jsonl_iter():
            finding["affectedEntities"] = ""
            finding["replication_steps"] = ""
            findings.append(finding)
            
        with open(output_path, "w", encoding="utf-8") as out_f:
            json.dump(findings, out_f, indent=2)
            
        return send_file(output_path, as_attachment=True, download_name="findings.json")
        
    except Exception as e:
        flash(f"Extraction failed: {str(e)}", "error")
        return redirect(url_for("extract_page"))

@app.route("/import_run", methods=["POST"])
def import_submit():
    # Helper for response logic
    is_ajax = request.form.get("ajax") == "1"
    
    def respond(msg, category="success"):
        if is_ajax:
            return {"message": msg, "category": category}
        else:
            flash(msg, category)
            return redirect(url_for("import_page"))

    # 1. Handle Credentials (Form > Env File > System Env)
    env_vars = {}
    
    # Check for uploaded .env (Legacy server-side support, though client now preferred)
    env_file = request.files.get("env_file")
    if env_file and env_file.filename:
        from io import TextIOWrapper
        # Simple parse of .env line by line
        for line in TextIOWrapper(env_file, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k, v = line.split("=", 1)
            env_vars[k.strip()] = v.strip().strip("'").strip('"')

    gw_url = request.form.get("gw_url") or env_vars.get("GW_URL")
    gw_token = request.form.get("gw_token") or env_vars.get("GW_TOKEN")
    report_id = request.form.get("report_id") or env_vars.get("GW_REPORT_ID")
    
    if not all([gw_url, gw_token, report_id]):
        return respond("Missing Credentials: GW URL, Token, and Report ID are required.", "error")

    # 2. Handle Inputs
    nessus_f = request.files.get("nessus_file")
    json_f = request.files.get("json_file")
    
    if (not nessus_f or not nessus_f.filename) and (not json_f or not json_f.filename):
        return respond("Please upload at least one file (.nessus or .json).", "error")
        
    temp_dir = tempfile.mkdtemp(prefix="gw_import_")
    
    json_findings_map = {} # plugin_id -> obj
    nessus_findings_map = {} # plugin_id -> obj
    
    try:
        # Load JSON if present
        if json_f and json_f.filename:
            json_path = os.path.join(temp_dir, secure_filename(json_f.filename))
            json_f.save(json_path)
            with open(json_path, "r", encoding="utf-8") as jf:
                data = json.load(jf)
                for obj in data:
                    if "plugin_id" in obj:
                        json_findings_map[obj["plugin_id"]] = obj
                        
        # Load Nessus if present
        if nessus_f and nessus_f.filename:
            nessus_path = os.path.join(temp_dir, secure_filename(nessus_f.filename))
            nessus_f.save(nessus_path)
            parser = NessusParser(nessus_path)
            parser.parse()
            for obj in parser.to_jsonl_iter():
                nessus_findings_map[obj["plugin_id"]] = obj
                
        # Merge Strategy (Replicating main logic)
        source_findings = []
        
        # Helper to merge everything
        def do_merge(pid, tech_finding, enrichment):
            merged = tech_finding.copy()
            for key, value in enrichment.items():
                if key in ["affectedEntities", "replication_steps"]:
                    if value: merged[key] = value
                else:
                    merged[key] = value
            return merged

        # 1. Scan Nessus findings
        for pid, tech in nessus_findings_map.items():
            if pid in json_findings_map:
                source_findings.append(do_merge(pid, tech, json_findings_map[pid]))
            else:
                source_findings.append(tech)
                
        # 2. Add remaining JSON-only findings
        for pid, enrich in json_findings_map.items():
            if pid not in nessus_findings_map:
                source_findings.append(enrich)
        
        # Initialize Importer
        importer = GhostwriterImporter(gw_url, gw_token, verify_ssl=False)
        importer.load_severity_map()
        
        # KEY FIX: Populate cache to prevent duplicates!
        # Always populate cache even in dry run to correctly simulate "Would update"
        try:
             importer.populate_existing_findings_cache(int(report_id))
        except Exception as e:
             # If connection fails, log it but maybe continue?
             print(f"Cache population warning: {e}")
             pass
        
        processed_count = 0
        created_count = 0
        updated_count = 0
        dry_run_log = ""
        
        to_create = []
        to_update = []
        
        for finding in source_findings:
            sev_label = finding.get("severity_label", "informational")
            severity_id = importer.severity_map.get(sev_label, importer.severity_map.get("informational"))
            title = finding["title"]
            
            obj = {
                "reportId": int(report_id),
                "findingTypeId": 1,
                "severityId": severity_id,
                "title": title,
                "description": finding["description"],
                "mitigation": finding["mitigation"],
                "impact": finding["impact"],
                "replication_steps": finding.get("replication_steps", ""),
                "affectedEntities": finding.get("affectedEntities", ""),
                "references": finding.get("references", "<p></p>"),
            }
            
            # Custom Fields Logic (Copied from main)
            custom_extra_fields = {}
            core_fields = {
                "plugin_id", "severity_num", "severity_label", "title", "description", 
                "mitigation", "impact", "replication_steps", "affectedEntities", "references",
                "raw_description", "raw_mitigation", "risk_factor", "extraFields"
            }
            for key, value in finding.items():
                if key not in core_fields:
                    custom_extra_fields[key] = value
            
            existing_extra = finding.get("extraFields")
            final_extra_fields = (existing_extra if existing_extra is not None else {}).copy()
            
            if "nessus" not in final_extra_fields:
                final_extra_fields["nessus"] = {
                    "plugin_id": finding.get("plugin_id"), 
                    "severity_num": finding.get("severity_num")
                }
            final_extra_fields.update(custom_extra_fields)
            obj["extraFields"] = final_extra_fields
            
            existing_id = importer.check_existing_finding(int(report_id), title)
            if existing_id:
                to_update.append((existing_id, obj))
            else:
                to_create.append(obj)
                
            processed_count += 1
            
        is_dry = "dry_run" in request.form
        
        if to_create:
            if is_dry:
                dry_run_log += f"Would Create {len(to_create)} findings:\n"
                for o in to_create:
                    dry_run_log += f" - [NEW] {o['title']}\n"
            else:
                importer.bulk_insert_findings(to_create)
                created_count = len(to_create)
        
        if to_update:
            if is_dry:
                dry_run_log += f"\nWould Update {len(to_update)} findings:\n"
                for eid, o in to_update:
                    dry_run_log += f" - [UPDATE] {o['title']} (ID: {eid})\n"
            else:
                counter = 0
                for eid, o in to_update:
                    importer.update_finding(eid, o)
                    counter += 1
                updated_count = counter

        if is_dry:
            msg = f"""<b>Dry Run Complete</b><br>
                      Processed: {processed_count}<br>
                      New: {len(to_create)}<br>
                      Updates: {len(to_update)}<br>
                      <pre>{dry_run_log}</pre>"""
            return respond(msg, "info")
        else:
            return respond(f"<b>Import Complete!</b><br>Created: {created_count}<br>Updated: {updated_count}", "success")
            
    except Exception as e:
        return respond(f"Import Failed: {str(e)}", "error")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
