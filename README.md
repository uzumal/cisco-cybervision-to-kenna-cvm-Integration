# Cisco Cyber Vision to Kenna Security Integration

This repository provides a complete toolset to extract vulnerability data from Cisco Cyber Vision, transform it into Kenna Security KDI (Kenna Data Importer) format, and upload it to Kenna Security.

---

## Preview

<p align="center">
  <img width = "400" alt="Kenna Security/CVM" src="https://github.com/user-attachments/assets/66de3461-4fe1-40a1-9fa3-6d774bf9c168">
  <img width = "550"　alt="CyberVision" src="https://github.com/user-attachments/assets/492bde21-9bef-45eb-8549-7fed7805997a">
</p>

---

## Overview

The integration consists of the following key components:

| Component                             | Description                                                       |
|-------------------------------------|-------------------------------------------------------------------|
| **Cyber Vision Vulnerability Exporter** | Extracts vulnerabilities from Cyber Vision API and outputs them to CSV. |
| **CSV to KDI Converter**            | Converts the CSV file to Kenna Security's KDI JSON format.        |
| **Kenna KDI Uploader**              | Uploads the KDI JSON to Kenna Security via API.                   |
| **KDI Validator**                   | Validates the generated KDI JSON file against required specifications. |

---

## Environment Variables

All environment-specific parameters are managed via a `.env` file.

**Example `.env` file:**

```env
# Cyber Vision API
CV_API_BASE_URL=https://198.18.135.164/api/3.0
CV_API_TOKEN=ics-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
CV_VERIFY_SSL=False

# Kenna Security API
KENNA_API_KEY=e-xxxxxxxxxxxxxxxxxxxxxxxxxxxx
KENNA_CONNECTOR_ID=165204
KENNA_API_HOST=https://api.labs.us.kennasecurity.com
KDI_FILENAME=cybervision_vulns_kdi.json
CHECK_INTERVAL=30
TIMEOUT=180
```

---

## Usage

### 1. Export Vulnerability Data from Cyber Vision

Extract vulnerability and device information from Cisco Cyber Vision and output to a CSV file.

```bash
python export_vuln_csv.py
```

**Output:**  
`cybervision_vulns.csv`

---

### 2. Convert CSV to KDI JSON Format

Converts the exported CSV to Kenna Security's KDI JSON format.

```bash
python csv_to_kdi.py cybervision_vulns.csv -m default_meta.csv -o cybervision_vulns_kdi_fixed.json -s
```

**Parameters:**

| Parameter | Description                                     |
|---------|-------------------------------------------------|
| `-m`    | Meta mapping file (required)                    |
| `-o`    | Output KDI JSON file name                       |
| `-s`    | Skip autoclose option (optional)                |

**Output:**  
`cybervision_vulns_kdi_fixed.json`

---

### 3. Upload KDI File to Kenna Security

Uploads the generated KDI JSON file to Kenna Security and optionally triggers and monitors the connector run.

```bash
python upload_kdi_to_kenna.py upload cybervision_vulns_kdi_fixed.json --run --monitor
```

**Parameters:**

| Parameter    | Description                                        |
|------------|----------------------------------------------------|
| `upload`   | Upload action                                      |
| `<file>`   | KDI file to upload                                 |
| `--run`    | Trigger the connector run immediately after upload |
| `--monitor`| Monitor connector run status until completion      |

---

### 4. Validate KDI JSON File

Validates the structure and required fields of the generated KDI JSON file.

```bash
python kdi_validator.py cybervision_vulns_kdi_fixed.json
```

This validation includes:

- `mac_address` and `os` fields are of type `string`
- `findings` field exists and is a `list`
- Each `vuln_def` entry contains both `scanner_identifier` and `scanner_type`

---

## Directory Structure

```
├── export_vuln_csv.py                # Cyber Vision Vulnerability Exporter
├── csv_to_kdi.py                     # CSV to KDI Converter
├── upload_kdi_to_kenna.py            # KDI Uploader
├── kdi_validator.py                  # KDI Validator
├── default_meta.csv                  # Field mapping file
├── .env                              # Environment variables file
├── cybervision_vulns.csv             # Example: Exported vulnerability CSV
├── cybervision_vulns_kdi_fixed.json  # Example: Converted KDI JSON file
```

---

## Requirements

- Python 3.8+
- Dependencies:
  - `requests`
  - `python-dotenv`

---

## License

This project is licensed under the Cisco Sample Code License.
