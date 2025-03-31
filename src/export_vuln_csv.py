#!/usr/bin/python3
import requests
import csv
import json
import urllib3
import os
import sys
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
API_BASE_URL = os.getenv("CV_API_BASE_URL")
API_TOKEN = os.getenv("CV_API_TOKEN")
VERIFY_SSL = os.getenv("CV_VERIFY_SSL", "False").lower() == "true"

if not API_BASE_URL or not API_TOKEN:
    print("❌ CV_API_BASE_URL or CV_API_TOKEN is not set in .env")
    sys.exit(1)

HEADERS = {
    "x-token-id": API_TOKEN
}

def make_api_request(url, method="GET", json_data=None, max_retries=3, retry_delay=5):
    for attempt in range(max_retries):
        try:
            if method == "GET":
                response = requests.get(url, headers=HEADERS, verify=VERIFY_SSL, timeout=30)
            elif method == "POST":
                response = requests.post(url, headers=HEADERS, json=json_data, verify=VERIFY_SSL, timeout=30)
            elif method == "PUT":
                response = requests.put(url, headers=HEADERS, json=json_data, verify=VERIFY_SSL, timeout=30)
            else:
                raise ValueError(f"Unknown HTTP method: {method}")
                
            if response.status_code >= 400:
                print(f"⚠️ API {method} error {url}: {response.status_code} - {response.text}")
                if attempt < max_retries - 1:
                    print(f"   Retrying {attempt+1}/{max_retries}... {retry_delay}seconds later")
                    time.sleep(retry_delay)
                    continue
            
            return response
            
        except requests.exceptions.RequestException as e:
            print(f"⚠️ API request exception {url}: {e}")
            if attempt < max_retries - 1:
                print(f"   Retrying {attempt+1}/{max_retries}... {retry_delay}seconds later")
                time.sleep(retry_delay)
            else:
                print(f"❌ 最大Retrying回数に達しました")
                raise
    
    raise Exception(f"Failed to connect to API endpoint {url}")

def get_all_devices(max_retries=3, retry_delay=5):
    print("🔍 Retrieving preset list...")
    
    try:
        presets_url = f"{API_BASE_URL}/presets"
        response = make_api_request(presets_url)
        if response.status_code != 200:
            raise Exception(f"Preset retrieval error: {response.status_code}")
        
        presets = response.json()
        print(f"✅ {len(presets)}presets retrieved")
        
        all_data_preset = next((p for p in presets if p["label"] == "All data"), None)
        if not all_data_preset:
            if presets:
                all_data_preset = presets[0]
                print(f"⚠️ Preset 'All data' not found。Using instead '{all_data_preset['label']}'")
            else:
                raise Exception("No available presets found")

        preset_id = all_data_preset["id"]
        print(f"✅ Preset ID: {preset_id} '{all_data_preset['label']}'")
        
        # デバイス一覧を取得
        devices_url = f"{API_BASE_URL}/presets/{preset_id}/visualisations/networknode-list"
        print(f"🔍 Retrieving device list: {devices_url}")
        
        response = make_api_request(devices_url)
        if response.status_code != 200:
            raise Exception(f"Device list retrieval error: {response.status_code}")
        
        devices = response.json()
        print(f"✅ {len(devices)}devices/components retrieved")
        return devices
        
    except Exception as e:
        print(f"❌ デバイス取得中にAn error occurred: {e}")
        # エラーを上位に伝播
        raise

def get_device_vulnerabilities(device_id, is_device=True, with_details=True):
    try:
        if is_device:
            url = f"{API_BASE_URL}/devices/{device_id}/vulnerabilities"
        else:
            url = f"{API_BASE_URL}/components/{device_id}/vulnerabilities"
        
        print(f"🔍 Retrieving vulnerability information: {device_id}")
        response = make_api_request(url)
        
        if response.status_code != 200:
            print(f"⚠️ Vulnerability information retrieval error: {response.status_code}")
            return []
        
        vulns = response.json()
        print(f"✅ vulnerability information {len(vulns)}retrieved successfully: {device_id}")
        
        if with_details and vulns:
            enhanced_vulns = []
            for vuln in vulns:
                if "cve" in vuln:
                    vuln_detail_url = f"{API_BASE_URL}/vulnerabilities?filter=cve:{vuln['cve']}"
                    try:
                        detail_response = make_api_request(vuln_detail_url)
                        if detail_response.status_code == 200:
                            details = detail_response.json()
                            if details:
                                vuln.update(details[0])
                    except Exception as e:
                        print(f"⚠️ Detailed vulnerability information retrieval error {vuln['cve']}: {e}")
                
                enhanced_vulns.append(vuln)
            return enhanced_vulns
        
        return vulns
    
    except Exception as e:
        print(f"❌ Vulnerability information retrieval error: {e}")
        raise
        
        if with_details and vulns:
            enhanced_vulns = []
            for vuln in vulns:
                if "cve" in vuln:
                    vuln_detail_url = f"{API_BASE_URL}/vulnerabilities?filter=cve:{vuln['cve']}"
                    try:
                        detail_response = make_api_request(vuln_detail_url)
                        if detail_response.status_code == 200:
                            details = detail_response.json()
                            if details:
                                vuln.update(details[0])
                    except Exception as e:
                        print(f"⚠️ Detailed vulnerability information retrieval error {vuln['cve']}: {e}")
                
                enhanced_vulns.append(vuln)
            return enhanced_vulns
        
        return vulns
    
    except Exception as e:
        print(f"❌ Vulnerability information retrieval error: {e}")
        raise

def get_device_details(device_id, is_device=True):
    try:
        if is_device:
            url = f"{API_BASE_URL}/devices/{device_id}"
        else:
            url = f"{API_BASE_URL}/components/{device_id}"
        
        print(f"🔍 Retrieving device details: {device_id}")
        response = make_api_request(url)
        
        if response.status_code != 200:
            print(f"⚠️ Device details retrieval error: {response.status_code}")
            return {}
        
        device_data = response.json()
        print(f"✅ Device details retrieved successfully: {device_id}")
        return device_data
        
    except Exception as e:
        print(f"❌ Device details retrieval error: {e}")
        return {}

def get_device_risk_score_details(device_id, is_device=True):
    try:
        if not is_device:
            return {}
            
        url = f"{API_BASE_URL}/devices/{device_id}/riskScore"
        
        print(f"🔍 Retrieving risk score details: {device_id}")
        response = make_api_request(url)
        
        if response.status_code != 200:
            print(f"⚠️ Risk score details retrieval error: {response.status_code}")
            return {}
        
        risk_data = response.json()
        print(f"✅ Risk score details retrieved successfully: {device_id}")
        return risk_data
        
    except Exception as e:
        print(f"❌ Risk score details retrieval error: {e}")
        return {}

def convert_numeric_cvss_to_text(cvss_float):
    try:
        val = float(cvss_float)
    except (TypeError, ValueError):
        return "Low"
    if val >= 9.0:
        return "Critical"
    elif val >= 7.0:
        return "High"
    elif val >= 4.0:
        return "Medium"
    else:
        return "Low"

def extract_normalized_property(props, key):
    if not props:
        return "None"
    for p in props:
        if p.get("key") == key:
            return p.get("value", "None")
    return "None"

def extract_os_info(props):
    os_name = "None"
    os_version = "None"
    
    if not props:
        return os_name, os_version
    
    for p in props:
        if p.get("key") == "os-name":
            os_name = p.get("value", "None")
            break
    
    for p in props:
        if p.get("key") == "os-version":
            os_version = p.get("value", "None")
            break
    
    return os_name, os_version

def extract_tags(tags):
    return ",".join([t.get("label", "") for t in tags]) if tags else "None"

def safe_get(d, key):
    val = d.get(key)
    return str(val) if val is not None and val != "" else "None"

def get_device_ip(device):
    ip = device.get("ip", ["None"])
    if isinstance(ip, list) and len(ip) > 0:
        return ip[0]
    return safe_get(device, "ip")

def get_formatted_date():
    return datetime.now().strftime("%d/%m/%Y")

def generate_finding_id(device_id, cve_id):
    return f"{device_id}_{cve_id}_{get_formatted_date()}"

def export_to_csv(devices, output_file = "data/cybervision_vulns.csv"):
    current_date = get_formatted_date()
    
    if os.path.exists(output_file):
        backup_file = f"{output_file}.{int(time.time())}.bak"
        try:
            import shutil
            shutil.copy2(output_file, backup_file)
            print(f"✅ Created a backup of the existing file: {backup_file}")
        except Exception as e:
            print(f"⚠️ Error while creating backup: {e}")
    
    try:
        with open(output_file, mode="w", encoding="utf-8", newline="") as csvfile:
            fieldnames = [
                "locator", 
                "scanner_source", 
                "scanner_type", 
                "scanner_id",
                "last_seen", 
                "status",
                
                "CVE", 
                "CVE-title", 
                
                "CVSS", 
                "CVSS-Text", 
                "CVSS-temporal", 
                "CVSS-vector-string",
                
                "device-id", 
                "device-name", 
                "device-ip", 
                "device-mac", 
                "device-custom-name",
                "device-tags", 
                
                "OS", 
                "OS-Version",
                
                "CVE-description", 
                "CVE-solution",
                
                "finding_id",
                "finding_scanner_type",
                "finding_created",
                "finding_severity",

                "risk_score",
                "risk_score_best_achievable"
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            count = 0
            total_devices = len(devices)
            
            for idx, d in enumerate(devices, 1):
                device_id = d["id"]
                is_device = d.get("isDevice", True)
                device_type = "デバイス" if is_device else "コンポーネント"
                
                print(f"💻 [{idx}/{total_devices}] {device_type}処理中: {device_id} ({safe_get(d, 'originalLabel')})")
                
                vulns = get_device_vulnerabilities(device_id, is_device)
                
                device_details = {}
                if not all(key in d for key in ["normalizedProperties", "riskScore"]):
                    device_details = get_device_details(device_id, is_device)
                    if device_details:
                        for key in ["normalizedProperties", "riskScore", "tags"]:
                            if key in device_details and key not in d:
                                d[key] = device_details[key]
                
                risk_score_details = {}
                if is_device and d.get("riskScore"):
                    risk_score_details = get_device_risk_score_details(device_id, is_device)
                
                norm_props = d.get("normalizedProperties", [])
                os_name, os_version = extract_os_info(norm_props)
                vendor_name = extract_normalized_property(norm_props, "vendor-name")
                model_name = extract_normalized_property(norm_props, "model-name")
                
                tags = extract_tags(d.get("tags", []))
                
                device_ip = get_device_ip(d)
                
                risk_score = safe_get(d, "riskScore")
                risk_score_best = "None"
                if risk_score_details:
                    risk_score_best = safe_get(risk_score_details, "bestAchievableScore")
                
                for vuln in vulns:
                    cvss = vuln.get("CVSS", "None")
                    cvss_text = convert_numeric_cvss_to_text(cvss)
                    cve_id = safe_get(vuln, "cve")
                    
                    finding_id = generate_finding_id(device_id, cve_id)
                    
                    row = {
                        "locator": device_ip, 
                        "scanner_source": "Cisco Cyber Vision",
                        "scanner_type": "CyberVision",
                        "scanner_id": f"CyberVision-{cve_id}", 
                        "last_seen": current_date, 
                        "status": "open", 
                        
                        "CVE": cve_id,
                        "CVE-title": safe_get(vuln, "title"),
                        
                        "CVSS": cvss,
                        "CVSS-Text": cvss_text,
                        "CVSS-temporal": safe_get(vuln, "CVSS_temporal"),
                        "CVSS-vector-string": safe_get(vuln, "CVSS_vector_string"),
                        
                        "device-id": device_id,
                        "device-name": safe_get(d, "originalLabel"),
                        "device-ip": device_ip,
                        "device-mac": safe_get(d, "mac"),
                        "device-custom-name": safe_get(d, "customLabel"),
                        "device-tags": tags,
                        
                        "OS": os_name,
                        "OS-Version": os_version,
                        
                        "CVE-description": f"{vuln.get('full_description') or ''} {vuln.get('summary') or ''}".strip() or "None",
                        "CVE-solution": safe_get(vuln, "solution"),
                        
                        "finding_id": finding_id,
                        "finding_scanner_type": "CyberVision",
                        "finding_created": current_date,
                        "finding_severity": cvss_text,
                        
                        "risk_score": risk_score,
                        "risk_score_best_achievable": risk_score_best
                    }
                    
                    writer.writerow(row)
                    count += 1
            
            print(f"✅ {count}件のVulnerability information has been exported：{output_file}")
            return count
            
    except Exception as e:
        print(f"❌ CSV file export error: {e}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    try:
        print("🚀 Cisco Cyber Vision Vulnerability CSV Export Tool")
        print(f"📅 Execution date: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        print(f"🔌 API URL: {API_BASE_URL}")
        
        output_file = "data/cybervision_vulns.csv"
        print(f"📁 Output file: {output_file}")
        
        print("🔍 Testing API connectivity...")
        try:
            test_url = f"{API_BASE_URL}/version"
            response = make_api_request(test_url)
            if response.status_code == 200:
                version_info = response.json()
                print(f"✅ API connection successful - Cyber Vision : {version_info.get('version', 'Unknown')}")
            else:
                print(f"⚠️ API connectivity test - status code: {response.status_code}")
        except Exception as e:
            print(f"⚠️ API connectivity test failed: {e}")
            print("⚠️ Continuing the process...")
        
        print("🔍 Retrieving device information...")
        devices = get_all_devices()
        
        if not devices:
            print("⚠️ No devices found. Terminating the process.")
            sys.exit(1)
            
        print(f"✅ Number of devices: {len(devices)}")
        
        vuln_devices = []
        for device in devices:
            if device.get("vulnerabilitiesCount", 0) > 0:
                vuln_devices.append(device)
        
        if not vuln_devices:
            print("⚠️ No devices with vulnerabilities were found。")
            print(f"💡 Reference: In {len(devices)} Devices、vulnerability information Number of devices is 0")
            
            print("📝 Exporting an empty CSV file...")
            count = export_to_csv([], output_file)
            print(f"✅ Exported an empty CSV file: {output_file}")
            sys.exit(0)
        
        print(f"🔍 vulnerability information Number of devices: {len(vuln_devices)}/{len(devices)}")
        print("📝 Starting export to CSV file...")
        count = export_to_csv(vuln_devices, output_file)
        
        print(f"🎉 Completed！{count}vulnerability records exported to {output_file}")
        sys.exit(0)
        
    except KeyboardInterrupt:
        print("\n⚠️ Process interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ An error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)