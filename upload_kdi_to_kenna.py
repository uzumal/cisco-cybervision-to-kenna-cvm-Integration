import requests
import sys
import os
import time
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("KENNA_API_KEY")
CONNECTOR_ID = os.getenv("KENNA_CONNECTOR_ID")
KENNA_HOST = os.getenv("KENNA_API_HOST")
KDI_FILENAME = os.getenv("KDI_FILENAME", "cybervision_vulns_kdi.json")
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", 30))
TIMEOUT = int(os.getenv("TIMEOUT", 180))

if not API_KEY or not CONNECTOR_ID or not KENNA_HOST:
    print("❌ .env に KENNA_API_KEY, KENNA_CONNECTOR_ID, KENNA_API_HOST が設定されていません")
    sys.exit(1)

def print_timestamp(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if level == "INFO":
        print(f"[{timestamp}] ℹ️ {message}")
    elif level == "SUCCESS":
        print(f"[{timestamp}] ✅ {message}")
    elif level == "ERROR":
        print(f"[{timestamp}] ❌ {message}")
    elif level == "WARNING":
        print(f"[{timestamp}] ⚠️ {message}")
    else:
        print(f"[{timestamp}] {message}")

def upload_kdi_file(file_path):
    if not os.path.exists(file_path):
        print_timestamp(f"ファイルが見つかりません: {file_path}", "ERROR")
        return None
    
    url = f"{KENNA_HOST}/connectors/{CONNECTOR_ID}/data_file"
    headers = {
        "X-Risk-Token": API_KEY,
        "accept": "application/json"
    }
    
    print_timestamp(f"ファイル {file_path} をアップロード中...")
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/json')}
            response = requests.post(
                url, 
                headers=headers,
                files=files,
                timeout=TIMEOUT
            )
        
        if response.status_code in [200, 201, 202]:
            print_timestamp(f"ファイルのアップロードに成功しました。ステータスコード: {response.status_code}", "SUCCESS")
            try:
                result = response.json()
                print_timestamp(f"レスポンス: {json.dumps(result, indent=2)}")
                return result
            except:
                print_timestamp("レスポンスのJSONパースに失敗しました", "WARNING")
                return {"success": "true"}
        else:
            print_timestamp(f"アップロードに失敗しました。ステータスコード: {response.status_code}", "ERROR")
            print_timestamp(f"レスポンス: {response.text}", "ERROR")
            return None
    
    except Exception as e:
        print_timestamp(f"エラーが発生しました: {str(e)}", "ERROR")
        return None

def run_connector():
    url = f"{KENNA_HOST}/connectors/{CONNECTOR_ID}/run"
    headers = {
        "X-Risk-Token": API_KEY,
        "Content-Type": "application/json",
        "accept": "application/json"
    }
    
    print_timestamp(f"コネクタID {CONNECTOR_ID} を実行中...")
    
    try:
        response = requests.post(
            url, 
            headers=headers,
            json={}, 
            timeout=TIMEOUT
        )
        
        if response.status_code in [200, 201, 202]:
            print_timestamp(f"コネクタの実行が開始されました。ステータスコード: {response.status_code}", "SUCCESS")
            try:
                result = response.json()
                print_timestamp(f"レスポンス: {json.dumps(result, indent=2)}")
                return result
            except:
                print_timestamp("レスポンスのJSONパースに失敗しました", "WARNING")
                return {"success": "true"}
        else:
            print_timestamp(f"コネクタの実行に失敗しました。ステータスコード: {response.status_code}", "ERROR")
            print_timestamp(f"レスポンス: {response.text}", "ERROR")
            return None
            
    except Exception as e:
        print_timestamp(f"エラーが発生しました: {str(e)}", "ERROR")
        return None

def get_connector_run_status(connector_run_id):
    url = f"{KENNA_HOST}/connectors/{CONNECTOR_ID}/connector_runs/{connector_run_id}"
    headers = {
        "X-Risk-Token": API_KEY,
        "accept": "application/json"
    }
    
    try:
        response = requests.get(
            url, 
            headers=headers,
            timeout=TIMEOUT
        )
        
        if response.status_code == 200:
            try:
                return response.json()
            except:
                print_timestamp("レスポンスのJSONパースに失敗しました", "WARNING")
                return None
        else:
            print_timestamp(f"ステータス取得に失敗しました。ステータスコード: {response.status_code}", "ERROR")
            return None
            
    except Exception as e:
        print_timestamp(f"ステータス取得中にエラーが発生しました: {str(e)}", "ERROR")
        return None

def monitor_connector_run(connector_run_id, max_checks=30):
    print_timestamp(f"コネクタ実行ID {connector_run_id} のステータスを監視中...")
    
    checks = 0
    status = None
    is_running = True
    
    while is_running and checks < max_checks:
        try:
            status = get_connector_run_status(connector_run_id)
            
            if status is None:
                print_timestamp("ステータス情報を取得できませんでした", "ERROR")
                time.sleep(CHECK_INTERVAL)
                checks += 1
                continue
                
            start_time = status.get('start_time')
            end_time = status.get('end_time')
            
            print_timestamp(f"実行ステータス [{checks+1}/{max_checks}]: 開始={start_time}, 終了={end_time}")
            
            try:
                print_progress_info(status)
            except Exception as e:
                print_timestamp(f"進捗情報の表示中にエラーが発生しました: {str(e)}", "WARNING")
            
            if end_time:
                is_running = False
                print_timestamp("コネクタの実行が完了しました", "SUCCESS")
            else:
                print_timestamp(f"{CHECK_INTERVAL}秒後に再確認します...")
                time.sleep(CHECK_INTERVAL)
                checks += 1
                
        except Exception as e:
            print_timestamp(f"監視中にエラーが発生しました: {str(e)}", "ERROR")
            time.sleep(CHECK_INTERVAL)
            checks += 1
    
    if checks >= max_checks and is_running:
        print_timestamp(f"最大確認回数（{max_checks}回）に達しました。処理は継続中の可能性があります。", "WARNING")
    
    try:
        final_status = get_connector_run_status(connector_run_id)
        if final_status:
            print_final_status(final_status)
        return final_status
    except Exception as e:
        print_timestamp(f"最終ステータスの取得中にエラーが発生しました: {str(e)}", "ERROR")
        return None

def print_progress_info(status):
    """進捗情報を表示"""
    if not status:
        return
        
    total = status.get('total_payload_count')
    if total is None:
        total = 0
    else:
        try:
            total = int(total)
        except (ValueError, TypeError):
            total = 0
            
    processed = status.get('processed_payload_count')
    if processed is None:
        processed = 0
    else:
        try:
            processed = int(processed)
        except (ValueError, TypeError):
            processed = 0
            
    failed = status.get('failed_payload_count')
    if failed is None:
        failed = 0
    else:
        try:
            failed = int(failed)
        except (ValueError, TypeError):
            failed = 0
    
    if total > 0:
        percent = (processed / total) * 100
        print_timestamp(f"進捗状況: {processed}/{total} 処理済み ({percent:.1f}%), 失敗: {failed}")
    else:
        print_timestamp(f"進捗状況: 処理中... (総数未定), 処理済み: {processed}, 失敗: {failed}")
    
    assets = status.get('processed_assets_count')
    if assets is None:
        assets = 0
    else:
        try:
            assets = int(assets)
        except (ValueError, TypeError):
            assets = 0
            
    vulns = status.get('processed_scanner_vuln_count')
    if vulns is None:
        vulns = 0
    else:
        try:
            vulns = int(vulns)
        except (ValueError, TypeError):
            vulns = 0
    
    if assets > 0 or vulns > 0:
        print_timestamp(f"処理済みアセット: {assets}, 処理済み脆弱性: {vulns}")

def print_final_status(status):
    if not status:
        return
    
    print_timestamp("\n==== コネクタ実行の詳細情報 ====")
    print_timestamp(f"実行ID: {status.get('id')}")
    print_timestamp(f"開始時間: {status.get('start_time')}")
    print_timestamp(f"終了時間: {status.get('end_time')}")
    
    success = status.get('success')
    if success is None:
        success_text = "不明"
    elif isinstance(success, bool):
        success_text = "はい" if success else "いいえ"
    elif isinstance(success, str):
        if success.lower() in ["true", "yes", "1"]:
            success_text = "はい"
        elif success.lower() in ["false", "no", "0"]:
            success_text = "いいえ"
        else:
            success_text = success
    else:
        success_text = str(success)
        
    print_timestamp(f"成功: {success_text}")
    
    print_timestamp("\n--- 処理情報 ---")
    for key in ['total_payload_count', 'processed_payload_count', 'failed_payload_count']:
        value = status.get(key)
        if value is not None:
            try:
                value = int(value)
            except (ValueError, TypeError):
                pass
        else:
            value = 0
        print_timestamp(f"{key}: {value}")
    
    print_timestamp("\n--- アセット情報 ---")
    for key in ['processed_assets_count', 'assets_with_tags_reset_count']:
        value = status.get(key)
        if value is not None:
            try:
                value = int(value)
            except (ValueError, TypeError):
                pass
        else:
            value = 0
        print_timestamp(f"{key}: {value}")
    
    print_timestamp("\n--- 脆弱性情報 ---")
    vuln_keys = [
        'processed_scanner_vuln_count', 'updated_scanner_vuln_count', 
        'created_scanner_vuln_count', 'closed_scanner_vuln_count',
        'autoclosed_scanner_vuln_count', 'reopened_scanner_vuln_count'
    ]
    for key in vuln_keys:
        value = status.get(key)
        if value is not None:
            try:
                value = int(value)
            except (ValueError, TypeError):
                pass
        else:
            value = 0
        print_timestamp(f"{key}: {value}")
    
    print_timestamp("\n--- Kenna脆弱性情報 ---")
    for key in ['closed_vuln_count', 'autoclosed_vuln_count', 'reopened_vuln_count']:
        value = status.get(key)
        if value is not None:
            try:
                value = int(value)
            except (ValueError, TypeError):
                pass
        else:
            value = 0
        print_timestamp(f"{key}: {value}")
    
    if success_text.lower() in ["いいえ", "no", "false", "0"]:
        print_timestamp("\n⚠️ エラー情報 ⚠️", "ERROR")
        error_msg = status.get('error_message')
        if error_msg:
            print_timestamp(f"エラーメッセージ: {error_msg}", "ERROR")
        else:
            error_fields = {}
            for k, v in status.items():
                if 'error' in k.lower() or 'fail' in k.lower() or 'exception' in k.lower():
                    error_fields[k] = v
                    
            if error_fields:
                for k, v in error_fields.items():
                    print_timestamp(f"{k}: {v}", "ERROR")
            else:
                print_timestamp("エラーの詳細は提供されていません", "WARNING")

def monitor_single_run(connector_run_id):
    if not connector_run_id:
        print_timestamp("コネクタ実行IDが指定されていません", "ERROR")
        return
    
    try:
        run_id = int(connector_run_id)
        monitor_connector_run(run_id)
    except ValueError:
        print_timestamp(f"無効なコネクタ実行ID: {connector_run_id}", "ERROR")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Kenna KDIファイルのアップロードと実行ステータスの監視')
    subparsers = parser.add_subparsers(dest='command', help='実行するコマンド')
    
    upload_parser = subparsers.add_parser('upload', help='KDIファイルをアップロード')
    upload_parser.add_argument('file', nargs='?', default=KDI_FILENAME, help='アップロードするKDIファイル')
    upload_parser.add_argument('--run', action='store_true', help='アップロード後にコネクタを実行する')
    upload_parser.add_argument('--monitor', action='store_true', help='実行をモニタリングする（--runと一緒に使用）')
    
    run_parser = subparsers.add_parser('run', help='コネクタを実行')
    run_parser.add_argument('--monitor', action='store_true', help='実行をモニタリングする')
    
    monitor_parser = subparsers.add_parser('monitor', help='既存の実行をモニタリング')
    monitor_parser.add_argument('run_id', help='モニタリングするコネクタ実行ID')
    
    status_parser = subparsers.add_parser('status', help='コネクタ実行の現在のステータスを表示')
    status_parser.add_argument('run_id', help='ステータスを表示するコネクタ実行ID')
    
    args = parser.parse_args()
    if args.command == 'upload':
        upload_result = upload_kdi_file(args.file)
        
        if not upload_result:
            sys.exit(1)
            
        if args.run:
            run_result = run_connector()
            
            if not run_result:
                sys.exit(1)
                
            if args.monitor and 'connector_run_id' in run_result:
                monitor_connector_run(run_result['connector_run_id'])
                
    elif args.command == 'run':
        run_result = run_connector()
        
        if not run_result:
            sys.exit(1)
            
        if args.monitor and 'connector_run_id' in run_result:
            monitor_connector_run(run_result['connector_run_id'])
            
    elif args.command == 'monitor':
        monitor_single_run(args.run_id)
        
    elif args.command == 'status':
        try:
            run_id = int(args.run_id)
            status = get_connector_run_status(run_id)
            
            if status:
                print_final_status(status)
            else:
                print_timestamp(f"実行ID {run_id} のステータスを取得できませんでした", "ERROR")
                sys.exit(1)
        except ValueError:
            print_timestamp(f"無効なコネクタ実行ID: {args.run_id}", "ERROR")
            sys.exit(1)
            
    else:
        parser.print_help()
        
    sys.exit(0)

if __name__ == "__main__":
    main()