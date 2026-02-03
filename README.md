# Ghostwriter Nessus Importer

A Python-based pipeline for importing Nessus vulnerability scan results into the Ghostwriter platform via GraphQL API.

## Features

- Parse Nessus XML files and extract vulnerability findings
- Group findings by Plugin ID with aggregated affected entities
- Filter findings by severity (Low and above; informational findings excluded)
- Export findings to standard JSON format for review and enrichment
- Import findings to Ghostwriter with automatic duplicate detection
- Merge technical data from Nessus with enriched content from JSON
- Bulk insert operations for optimized performance
- Update existing findings instead of creating duplicates
- **Custom Field Support**: Automatically maps non-standard fields (e.g., `ease_of_detection`, `remediation_cost`) to Ghostwriter's `extraFields` JSONB column.

## Requirements

- Python 3.x
- Dependencies: `requests`, `python-dotenv`

Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Set environment variables or use a `.env` file:

```
GW_URL=https://your-ghostwriter-instance/graphql
GW_TOKEN=your-bearer-token
GW_REPORT_ID=your-report-id
```

## Web Interface (GUI)

The tool now includes a user-friendly Web UI.

1.  **Install Web Dependencies**:
    ```bash
    pip install -r requirements-web.txt
    ```

2.  **Start the Server**:
    ```bash
    python app.py
    ```

3.  **Use**:
    Open your browser to `http://localhost:5001`.
    - **Extract Tab**: Drag-and-drop .nessus files to convert them to JSON.
    - **Import Tab**: Upload .nessus and/or .json files to import into Ghostwriter.

## Usage (CLI)

This tool has two main modes:

### Extract Mode

Parse a Nessus file and export findings to JSON:

```bash
python ghostwriter_nessus_importer.py --extract --nessus scan.nessus --json findings.json
```

### Import Mode

Import findings from JSON to Ghostwriter:

```bash
python ghostwriter_nessus_importer.py --import-findings --json findings.json --gw-url https://... --token ... --report-id 123
```

Import directly from Nessus file:

```bash
python ghostwriter_nessus_importer.py --import-findings --nessus scan.nessus --gw-url https://... --token ... --report-id 123
```

Merge Nessus technical data with enriched JSON content:

```bash
python ghostwriter_nessus_importer.py --import-findings --nessus scan.nessus --json enriched.json --gw-url https://... --token ... --report-id 123
```

### Additional Options

- `--finding-type-id`: Specify finding type (default: 1 for Network)
- `--verify-ssl`: Enable SSL certificate verification
- `--timeout`: Set HTTP timeout in seconds (default: 60)
- `--sleep`: Add delay between update operations
- `--dry-run`: Simulate import without making changes

## Workflow

1. **Extract**: Parse Nessus file and generate standard JSON for review
2. **Enrich** (Optional): Edit the JSON file to improve descriptions, mitigation steps, or add custom fields. Ensure `plugin_id` is preserved.
3. **Import**: Upload findings to Ghostwriter with merge support (nessus + json) for enriched content

## Data Processing

- Findings are grouped by Nessus Plugin ID
- Affected entities are aggregated across all instances
- Maximum severity is retained when multiple instances exist
- Plugin outputs are limited to 2 samples per finding
- HTML formatting is applied for compatibility with Ghostwriter DOCX export
- Only findings with severity Low (1) or higher are processed
- **Custom Fields**: Any fields in the JSON that are not part of the standard Ghostwriter schema (e.g. `remediation_cost`) will be automatically moved to the `extraFields` property during import.

## License

This project is provided as-is for use with Ghostwriter vulnerability management platform.
