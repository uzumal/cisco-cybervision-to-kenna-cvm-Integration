![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-blue)
![Last Commit](https://img.shields.io/github/last-commit/uzumal/cisco-kenna-cvm-cybervision-importer)
# 🚀 Cisco Cyber Vision to Kenna Security Integration

A complete, ready-to-use toolkit to **extract vulnerabilities from Cisco Cyber Vision**, convert them into **Kenna Security's KDI (Kenna Data Importer) format**, and seamlessly **upload and validate them**.

<p align="center">
  <img width="400" height="207" alt="Kenna Security Integration" src="https://github.com/user-attachments/assets/66de3461-4fe1-40a1-9fa3-6d774bf9c168">
  <img width="400" height="207" alt="Cisco Cyber Vision" src="https://github.com/user-attachments/assets/492bde21-9bef-45eb-8549-7fed7805997a">
</p>

---

## ⭐ Why this project?

This toolset automates the **time-consuming and error-prone process** of integrating Cyber Vision vulnerability data into Kenna Security, following the KDI specification.  
If you're managing **OT/IT convergence security** and struggling with data conversion and API integration, this is for you.

---

## 🔥 Quick Start

1. **Clone this repository**
    ```bash
    git clone https://github.com/uzumal/cisco-kenna-cvm-cybervision-importer.git
    cd cisco-kenna-cvm-cybervision-importer
    ```

2. **Prepare `.env` file**
    ```bash
    cp .env.sample .env
    # Edit your API keys & endpoint info in .env
    ```

3. **Install dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4. **Run end-to-end integration**
    ```bash
    python src/export_vuln_csv.py
    python src/csv_to_kdi.py data/cybervision_vulns.csv -m data/default_meta.csv -o data/cybervision_vulns_kdi_fixed.json -s
    python src/kdi_validator.py data/cybervision_vulns_kdi_fixed.json
    python src/upload_kdi_to_kenna.py upload data/cybervision_vulns_kdi_fixed.json --run --monitor
    ```

---

## 🗂️ Project Structure

```
cisco-kenna-cvm-cybervision-importer/
├── src/
│   ├── csv_to_kdi.py
│   ├── export_vuln_csv.py
│   ├── kdi_validator.py
│   └── upload_kdi_to_kenna.py
├── data/
│   ├── sample_vulns.csv
│   ├── default_meta.csv
│   └── sample_kdi_output.json
├── .env.sample
├── requirements.txt
├── README.md
├── LICENSE
└── SECURITY.md
```

---

## 🌐 Environment Variables

All parameters are configured in a `.env` file.

Example:

```bash
# Cisco Cyber Vision API
CV_API_BASE_URL=https://198.18.135.164/api/3.0
CV_API_TOKEN=ics-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
CV_VERIFY_SSL=False

# Kenna Security API
KENNA_API_KEY=e-xxxxxxxxxxxxxxxxxxxxxxxxxxxx
KENNA_CONNECTOR_ID=165204
KENNA_API_HOST=https://api.labs.us.kennasecurity.com
KDI_FILENAME=data/cybervision_vulns_kdi_fixed.json
CHECK_INTERVAL=30
TIMEOUT=180
```

---

## ⚙️ Usage

### 1. Export Vulnerabilities from Cyber Vision

```bash
python src/export_vuln_csv.py
```
**Output:** `data/cybervision_vulns.csv`

---

### 2. Convert CSV to KDI Format

```bash
python src/csv_to_kdi.py data/cybervision_vulns.csv -m data/default_meta.csv -o data/cybervision_vulns_kdi_fixed.json -s
```

**Output:** `data/cybervision_vulns_kdi_fixed.json`

---

### 3. Validate KDI JSON

```bash
python src/kdi_validator.py data/cybervision_vulns_kdi_fixed.json
```

---

### 4. Upload KDI to Kenna Security

```bash
python src/upload_kdi_to_kenna.py upload data/cybervision_vulns_kdi_fixed.json --run --monitor
```

---

## 📄 Requirements

- Python 3.8+
- Dependencies:
    - `requests`
    - `python-dotenv`

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!  
Feel free to fork this project and submit a Pull Request.

If you find this repository useful, **please give it a ⭐️ Star!**  
Your support motivates us to maintain and improve this tool.

---

## 🛡️ License

This project is licensed under the **MIT License**.  
See [LICENSE](./LICENSE) for details.

---

## 🙌 Acknowledgement

Special thanks to the Cyber Vision and Kenna Security communities for their ongoing efforts in security vulnerability management.
