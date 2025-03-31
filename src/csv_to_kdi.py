import os
import sys
import re
import csv
import json
import argparse
from datetime import datetime

DATE_FORMAT_KDI = "%Y-%m-%d-%H:%M:%S"
verbose = 0

def print_json(json_obj):
    print(json.dumps(json_obj, sort_keys=True, indent=2))

def normalize_to_string(value):
    if isinstance(value, list):
        return value[0] if len(value) > 0 else "None"
    if isinstance(value, str) and value.startswith("[") and value.endswith("]"):
        try:
            parsed = json.loads(value.replace("'", '"'))
            if isinstance(parsed, list) and len(parsed) > 0:
                return parsed[0]
        except Exception:
            pass
    return str(value) if value else "None"

def get_command_line_options():
    parser = argparse.ArgumentParser(description="CSV to KDI JSON Full Version (Tag Supported)")
    parser.add_argument("csv_in", help="CSV input file")
    parser.add_argument("-m", "--meta_file", dest="meta_file_name", required=True, help="Meta mapping file")
    parser.add_argument("-o", "--output_file", dest="output_file_name", required=True, help="Output KDI JSON file")
    parser.add_argument("--domain_suffix", dest="domain_suffix", required=False, default="", help="Optional domain suffix")
    parser.add_argument("-s", "--skip_autoclose", dest="skip_autoclose", action="store_true")
    parser.add_argument("-v", "--verbose", type=int, default=0)
    return parser.parse_args()

def read_meta(meta_file):
    field_map = {}
    with open(meta_file, newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            field_map[row[0]] = row[1]

    if 'tags' in field_map and field_map['tags']:
        field_map['tags'] = [t.strip() for t in field_map['tags'].split(',') if t.strip()]

    if 'score_map' in field_map and field_map['score_map']:
        field_map['score_map'] = json.loads(field_map['score_map'])

    return field_map

def verify_value(row, field_map, a_field):
    return a_field in field_map and field_map[a_field] in row and row[field_map[a_field]]

def set_value(a_dict, row, field_map, a_field, to_field=None):
    if not verify_value(row, field_map, a_field):
        return None
    to_field = a_field if to_field is None else to_field
    a_dict[to_field] = row[field_map[a_field]]
    return a_dict[to_field]

def set_datetime_value(a_dict, row, field_map, a_field, to_field=None):
    if not verify_value(row, field_map, a_field):
        return None
    date_in = datetime.strptime(row[field_map[a_field]], field_map['date_format'])
    a_dict[to_field or a_field] = date_in.strftime(DATE_FORMAT_KDI)
    return a_dict[to_field or a_field]

def set_tag_value(asset, row, tags, tag_prefixes):
    if tags is None or len(tags) == 0:
        return False

    asset_tags = []
    for tag_field in tags:
        if tag_field not in row:
            continue
        tag_value = row[tag_field]
        if tag_value:
            tag_list = [t.strip() for t in tag_value.split(",") if t.strip()]
            asset_tags.extend(tag_list)

    if len(asset_tags) > 0:
        asset['tags'] = asset_tags
    return True

def asset_exists(locator_type, primary_locator, assets):
    for asset in assets:
        if asset.get(locator_type) == primary_locator:
            return asset
    return None

def vuln_exists(scanner_type, scanner_id, vuln_defs):
    for v in vuln_defs:
        if v.get('scanner_type') == scanner_type and v.get('scanner_identifier') == scanner_id:
            return v
    return None

def add_vuln_to_asset(asset, row, field_map):
    vuln = {}
    vuln['scanner_type'] = field_map['scanner_type'] if field_map['scanner_source'] == "static" else row[field_map['scanner_type']]
    vuln['scanner_identifier'] = row[field_map['scanner_id']]
    try:
        score_key = row[field_map['scanner_score']]
        vuln['scanner_score'] = int(field_map['score_map'].get(score_key, score_key))
    except Exception:
        vuln['scanner_score'] = 0
    set_datetime_value(vuln, row, field_map, "last_seen", "last_seen_at")
    vuln['status'] = row[field_map['status']]
    asset['vulns'].append(vuln)

def create_vuln_def(row, kdi_json, field_map):
    vuln_def = {
        'scanner_type': field_map['scanner_type'] if field_map['scanner_source'] == "static" else row[field_map['scanner_type']],
        'scanner_identifier': row[field_map['scanner_id']]
    }
    if vuln_exists(vuln_def['scanner_type'], vuln_def['scanner_identifier'], kdi_json['vuln_defs']):
        return
    for f in ['cve_id', 'name', 'description', 'solution']:
        set_value(vuln_def, row, field_map, f, {
            'cve_id': 'cve_identifiers',
            'name': 'name',
            'description': 'description',
            'solution': 'solution'
        }[f])
    kdi_json['vuln_defs'].append(vuln_def)

def create_asset(row, kdi_json, field_map, domain_suffix):
    asset = {}
    locator_type = field_map['locator']
    primary_locator = row[field_map[locator_type]]
    existing = asset_exists(locator_type, primary_locator, kdi_json['assets'])
    if existing:
        asset = existing
    else:
        for f in ['file', 'ip_address', 'mac_address', 'hostname']:
            set_value(asset, row, field_map, f)
        if 'hostname' in asset and domain_suffix:
            asset['hostname'] += f".{domain_suffix}"
        asset['mac_address'] = normalize_to_string(asset.get('mac_address'))
        set_value(asset, row, field_map, 'os')
        asset['os'] = normalize_to_string(asset.get('os'))
        set_value(asset, row, field_map, 'os_version')
        set_tag_value(asset, row, field_map['tags'], field_map.get('tag_prefix', []))
        asset['vulns'] = []
        asset['findings'] = []
        kdi_json['assets'].append(asset)
    add_vuln_to_asset(asset, row, field_map)

def process_input(csv_file, kdi_json, field_map, domain_suffix):
    with open(csv_file, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            create_asset(row, kdi_json, field_map, domain_suffix)
            create_vuln_def(row, kdi_json, field_map)

if __name__ == "__main__":
    args = get_command_line_options()
    field_map = read_meta(args.meta_file_name)
    kdi_json = {"skip_autoclose": args.skip_autoclose, "assets": [], "vuln_defs": []}
    process_input(args.csv_in, kdi_json, field_map, args.domain_suffix)
    with open(f"data/{os.path.basename(args.output_file_name)}", 'w') as f:
        json.dump(kdi_json, f, indent=2)
    print(f"✅ KDI JSON file has been exported: {args.output_file_name}")