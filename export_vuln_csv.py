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
    print("❌ .env に CV_API_BASE_URL または CV_API_TOKEN が設定されていません")
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
                raise ValueError(f"不明なHTTPメソッド: {method}")
                
            if response.status_code >= 400:
                print(f"⚠️ API {method} エラー {url}: {response.status_code} - {response.text}")
                if attempt < max_retries - 1:
                    print(f"   リトライ {attempt+1}/{max_retries}... {retry_delay}秒後")
                    time.sleep(retry_delay)
                    continue
            
            return response
            
        except requests.exceptions.RequestException as e:
            print(f"⚠️ APIリクエスト例外 {url}: {e}")
            if attempt < max_retries - 1:
                print(f"   リトライ {attempt+1}/{max_retries}... {retry_delay}秒後")
                time.sleep(retry_delay)
            else:
                print(f"❌ 最大リトライ回数に達しました")
                raise
    
    raise Exception(f"APIエンドポイント {url} への接続に失敗しました")

def get_all_devices(max_retries=3, retry_delay=5):
    print("🔍 プリセット一覧を取得中...")
    
    try:
        presets_url = f"{API_BASE_URL}/presets"
        response = make_api_request(presets_url)
        if response.status_code != 200:
            raise Exception(f"プリセット取得エラー: {response.status_code}")
        
        presets = response.json()
        print(f"✅ {len(presets)}個のプリセットを取得しました")
        
        all_data_preset = next((p for p in presets if p["label"] == "All data"), None)
        if not all_data_preset:
            if presets:
                all_data_preset = presets[0]
                print(f"⚠️ プリセット 'All data' が見つかりません。代わりに '{all_data_preset['label']}' を使用します")
            else:
                raise Exception("利用可能なプリセットが見つかりません")

        preset_id = all_data_preset["id"]
        print(f"✅ プリセットID: {preset_id} '{all_data_preset['label']}'")
        
        # デバイス一覧を取得
        devices_url = f"{API_BASE_URL}/presets/{preset_id}/visualisations/networknode-list"
        print(f"🔍 デバイス一覧を取得中: {devices_url}")
        
        response = make_api_request(devices_url)
        if response.status_code != 200:
            raise Exception(f"デバイス一覧取得エラー: {response.status_code}")
        
        devices = response.json()
        print(f"✅ {len(devices)}個のデバイス/コンポーネントを取得しました")
        return devices
        
    except Exception as e:
        print(f"❌ デバイス取得中にエラーが発生しました: {e}")
        # エラーを上位に伝播
        raise

def get_device_vulnerabilities(device_id, is_device=True, with_details=True):
    try:
        if is_device:
            url = f"{API_BASE_URL}/devices/{device_id}/vulnerabilities"
        else:
            url = f"{API_BASE_URL}/components/{device_id}/vulnerabilities"
        
        print(f"🔍 脆弱性情報取得中: {device_id}")
        response = make_api_request(url)
        
        if response.status_code != 200:
            print(f"⚠️ 脆弱性情報取得エラー: {response.status_code}")
            return []
        
        vulns = response.json()
        print(f"✅ 脆弱性情報 {len(vulns)}件 取得完了: {device_id}")
        
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
                        print(f"⚠️ 脆弱性詳細情報取得エラー {vuln['cve']}: {e}")
                
                enhanced_vulns.append(vuln)
            return enhanced_vulns
        
        return vulns
    
    except Exception as e:
        print(f"❌ 脆弱性情報取得エラー: {e}")
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
                        print(f"⚠️ 脆弱性詳細情報取得エラー {vuln['cve']}: {e}")
                
                enhanced_vulns.append(vuln)
            return enhanced_vulns
        
        return vulns
    
    except Exception as e:
        print(f"❌ 脆弱性情報取得エラー: {e}")
        raise

def get_device_details(device_id, is_device=True):
    try:
        if is_device:
            url = f"{API_BASE_URL}/devices/{device_id}"
        else:
            url = f"{API_BASE_URL}/components/{device_id}"
        
        print(f"🔍 デバイス詳細情報取得中: {device_id}")
        response = make_api_request(url)
        
        if response.status_code != 200:
            print(f"⚠️ デバイス詳細情報取得エラー: {response.status_code}")
            return {}
        
        device_data = response.json()
        print(f"✅ デバイス詳細情報取得完了: {device_id}")
        return device_data
        
    except Exception as e:
        print(f"❌ デバイス詳細情報取得エラー: {e}")
        return {}

def get_device_risk_score_details(device_id, is_device=True):
    try:
        if not is_device:
            return {}
            
        url = f"{API_BASE_URL}/devices/{device_id}/riskScore"
        
        print(f"🔍 リスクスコア詳細情報取得中: {device_id}")
        response = make_api_request(url)
        
        if response.status_code != 200:
            print(f"⚠️ リスクスコア詳細情報取得エラー: {response.status_code}")
            return {}
        
        risk_data = response.json()
        print(f"✅ リスクスコア詳細情報取得完了: {device_id}")
        return risk_data
        
    except Exception as e:
        print(f"❌ リスクスコア詳細情報取得エラー: {e}")
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

def export_to_csv(devices, output_file="cybervision_vulns.csv"):
    current_date = get_formatted_date()
    
    if os.path.exists(output_file):
        backup_file = f"{output_file}.{int(time.time())}.bak"
        try:
            import shutil
            shutil.copy2(output_file, backup_file)
            print(f"✅ 既存ファイルのバックアップを作成しました: {backup_file}")
        except Exception as e:
            print(f"⚠️ バックアップ作成エラー: {e}")
    
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
            
            print(f"✅ {count}件の脆弱性情報を出力しました：{output_file}")
            return count
            
    except Exception as e:
        print(f"❌ CSVファイル出力エラー: {e}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    try:
        print("🚀 Cisco Cyber Vision 脆弱性CSVエクスポートツール")
        print(f"📅 実行日時: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        print(f"🔌 API URL: {API_BASE_URL}")
        
        output_file = "cybervision_vulns.csv"
        print(f"📁 出力ファイル: {output_file}")
        
        print("🔍 API接続テスト中...")
        try:
            test_url = f"{API_BASE_URL}/version"
            response = make_api_request(test_url)
            if response.status_code == 200:
                version_info = response.json()
                print(f"✅ API接続成功 - Cyber Vision バージョン: {version_info.get('version', 'Unknown')}")
            else:
                print(f"⚠️ API接続テスト - ステータスコード: {response.status_code}")
        except Exception as e:
            print(f"⚠️ API接続テスト失敗: {e}")
            print("⚠️ 処理を続行します...")
        
        print("🔍 デバイス情報を取得中...")
        devices = get_all_devices()
        
        if not devices:
            print("⚠️ デバイスが見つかりませんでした。処理を中止します。")
            sys.exit(1)
            
        print(f"✅ デバイス数: {len(devices)}")
        
        vuln_devices = []
        for device in devices:
            if device.get("vulnerabilitiesCount", 0) > 0:
                vuln_devices.append(device)
        
        if not vuln_devices:
            print("⚠️ 脆弱性情報を持つデバイスが見つかりませんでした。")
            print(f"💡 参考: 全{len(devices)}デバイス中、脆弱性ありは0デバイスです。")
            
            print("📝 空のCSVファイルを出力します...")
            count = export_to_csv([], output_file)
            print(f"✅ 空のCSVファイルを出力しました: {output_file}")
            sys.exit(0)
        
        print(f"🔍 脆弱性情報を持つデバイス数: {len(vuln_devices)}/{len(devices)}")
        print("📝 CSVファイルへの出力を開始します...")
        count = export_to_csv(vuln_devices, output_file)
        
        print(f"🎉 完了しました！{count}件の脆弱性情報を {output_file} に出力しました。")
        sys.exit(0)
        
    except KeyboardInterrupt:
        print("\n⚠️ 処理がユーザーにより中断されました")
        sys.exit(1)
    except Exception as e:
        print(f"❌ エラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)