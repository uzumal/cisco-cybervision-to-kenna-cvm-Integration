import json

CHECKS = [
    "mac_address_is_string",
    "os_is_string",
    "findings_is_list",
    "scanner_identifier_present",
    "scanner_type_present"
]


def validate_kdi_file(kdi_file_path):
    with open(kdi_file_path, "r", encoding="utf-8") as f:
        kdi_data = json.load(f)

    errors = []

    # Assetチェック
    for idx, asset in enumerate(kdi_data.get("assets", []), 1):
        if not isinstance(asset.get("mac_address"), str):
            errors.append(f"Asset {idx}: mac_address が string型ではありません")
        if not isinstance(asset.get("os"), str):
            errors.append(f"Asset {idx}: os が string型ではありません")
        if not isinstance(asset.get("findings"), list):
            errors.append(f"Asset {idx}: findings が list型ではありません")

    # vuln_defsチェック
    for idx, vuln_def in enumerate(kdi_data.get("vuln_defs", []), 1):
        if "scanner_identifier" not in vuln_def:
            errors.append(f"vuln_def {idx}: scanner_identifier が欠落しています")
        if "scanner_type" not in vuln_def:
            errors.append(f"vuln_def {idx}: scanner_type が欠落しています")

    if errors:
        print("❌ 検証エラーが見つかりました:\n")
        for err in errors:
            print(f"- {err}")
    else:
        print("✅ KDIファイルはすべてのチェック項目に準拠しています")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="KDIファイルの仕様チェックツール")
    parser.add_argument("kdi_file", help="検証対象のKDI JSONファイルパス")
    args = parser.parse_args()

    validate_kdi_file(args.kdi_file)
