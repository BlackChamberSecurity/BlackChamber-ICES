#!/usr/bin/env python3

# Copyright (c) 2026 John Earle
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Compile resmoio/app-catalog YAML files into:
  1. JSONL for HuggingFace upload (preserves nested objects)
  2. JSON for runtime domain lookup (optimized for O(1) email sender matching)

Drops: security, compliance (per user preference)
Keeps: everything else including company info, labels, description, etc.

Usage:
    # Clone resmo catalog first:
    git clone --depth 1 https://github.com/resmoio/app-catalog.git .app-catalog-tmp
    
    # Run compiler:
    python scripts/compile_saas_catalog.py
"""

import json
import os
import sys


def parse_yaml_file(filepath):
    """Parse resmo YAML files without pyyaml dependency.
    
    Handles:
      - top-level scalars (key: value)
      - top-level lists (key:\n  - item)
      - one-level nested dicts (key:\n  subkey: value)
      - deeper nesting for appRelations (key:\n  subkey:\n    subsubkey:\n    - item)
    """
    result = {}
    current_key = None
    current_list = None
    current_dict = None
    current_sub_key = None
    current_sub_list = None
    prev_indent = 0

    with open(filepath) as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].rstrip('\n')
        i += 1

        if not line or line.lstrip().startswith('#'):
            continue

        indent = len(line) - len(line.lstrip())
        content = line.lstrip()

        # Flush deeper nested sub-list
        if indent <= 2 and current_sub_key and current_sub_list is not None:
            if current_dict is not None:
                current_dict[current_sub_key] = current_sub_list
            current_sub_key = None
            current_sub_list = None

        # Top-level key
        if indent == 0 and ':' in content:
            # Flush previous state
            if current_key and current_list is not None:
                result[current_key] = current_list
                current_list = None
            if current_key and current_dict is not None:
                result[current_key] = current_dict
                current_dict = None

            parts = content.split(':', 1)
            key = parts[0].strip()
            val = parts[1].strip() if len(parts) > 1 else ''

            current_key = key

            if val == '[]':
                result[key] = []
                current_key = None
            elif val == '':
                pass  # list or dict follows
            elif val in ('true', 'false'):
                result[key] = val == 'true'
                current_key = None
            elif val.isdigit():
                result[key] = int(val)
                current_key = None
            else:
                # Handle multi-line descriptions (lines starting with spaces that are continuations)
                full_val = val
                while i < len(lines):
                    next_line = lines[i].rstrip('\n')
                    next_indent = len(next_line) - len(next_line.lstrip())
                    next_content = next_line.lstrip()
                    if next_indent >= 2 and not next_content.startswith('-') and ':' not in next_content:
                        full_val += ' ' + next_content
                        i += 1
                    else:
                        break
                result[key] = full_val
                current_key = None
            continue

        # List item at indent 0–2
        if content.startswith('- ') and current_key and indent <= 2:
            if current_sub_key is None:
                if current_list is None:
                    current_list = []
                current_list.append(content[2:].strip())
            else:
                if current_sub_list is None:
                    current_sub_list = []
                current_sub_list.append(content[2:].strip())
            continue

        # Nested key: value
        if indent > 0 and ':' in content and not content.startswith('-'):
            parts = content.split(':', 1)
            nkey = parts[0].strip()
            nval = parts[1].strip() if len(parts) > 1 else ''

            if indent == 2:
                if current_key and current_dict is None:
                    current_dict = {}
                if current_dict is not None:
                    if nval == '':
                        # Could be a sub-dict or sub-list
                        current_sub_key = nkey
                        current_sub_list = None
                    elif nval in ('true', 'false'):
                        current_dict[nkey] = nval == 'true'
                    elif nval.isdigit():
                        current_dict[nkey] = int(nval)
                    else:
                        current_dict[nkey] = nval
            elif indent >= 4 and current_sub_key:
                # Deep nesting — store as sub-dict
                if current_sub_list is None:
                    current_sub_list = {}
                if isinstance(current_sub_list, dict):
                    current_sub_list[nkey] = nval
            continue

    # Flush last
    if current_sub_key and current_sub_list is not None and current_dict is not None:
        current_dict[current_sub_key] = current_sub_list
    if current_key and current_list is not None:
        result[current_key] = current_list
    if current_key and current_dict is not None:
        result[current_key] = current_dict

    return result


def build_hf_entry(app):
    """Build a HuggingFace-ready entry with full data, dropping security/compliance."""
    entry = {
        "id": app.get("id", ""),
        "name": app.get("name", ""),
        "description": app.get("description", ""),
        "category": app.get("category", ""),
        "labels": app.get("labels", []),
    }

    # Company info as nested object
    # founded must be int or null (never string) for Arrow/Parquet type consistency
    company = app.get("company", {})
    if isinstance(company, dict) and company:
        founded_raw = company.get("founded", "")
        founded = int(founded_raw) if isinstance(founded_raw, int) or (isinstance(founded_raw, str) and founded_raw.isdigit()) else None
        entry["company"] = {
            "organization": company.get("organization", ""),
            "headquarters": company.get("headquarters", ""),
            "founded": founded,
            "homepage": company.get("homepage", ""),
        }
    else:
        entry["company"] = {
            "organization": "",
            "headquarters": "",
            "founded": None,
            "homepage": "",
        }

    # Domain/email data
    entry["app_domains"] = app.get("appDomains", []) or []
    entry["related_domains"] = app.get("relatedDomains", []) or []
    entry["registration_emails"] = app.get("registrationEmails", []) or []
    entry["oauth_display_names"] = app.get("oauthDisplayNames", []) or []

    return entry


def build_runtime_entry(app):
    """Build a runtime lookup entry optimized for the email analyzer."""
    entry = {
        "name": app.get("name", ""),
        "category": app.get("category", ""),
    }

    all_domains = set()
    for d in (app.get("appDomains", []) or []):
        all_domains.add(d.lower().strip())
    for d in (app.get("relatedDomains", []) or []):
        all_domains.add(d.lower().strip())

    if all_domains:
        entry["domains"] = sorted(all_domains)

    reg_emails = app.get("registrationEmails", []) or []
    if reg_emails:
        entry["registration_emails"] = reg_emails

    oauth = app.get("oauthDisplayNames", []) or []
    if isinstance(oauth, list) and oauth:
        entry["oauth_display_names"] = oauth

    company = app.get("company", {})
    if isinstance(company, dict) and company.get("organization"):
        entry["organization"] = company["organization"]

    return entry, all_domains


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    apps_dir = os.path.join(base_dir, '.app-catalog-tmp', 'apps')
    data_dir = os.path.join(base_dir, 'analysis', 'src', 'analysis', 'data')

    if not os.path.isdir(apps_dir):
        print(f"ERROR: {apps_dir} not found.")
        print("Clone resmo catalog first:")
        print("  git clone --depth 1 https://github.com/resmoio/app-catalog.git .app-catalog-tmp")
        sys.exit(1)

    os.makedirs(data_dir, exist_ok=True)

    # Parse all YAML files
    raw_apps = []
    errors = 0
    for fname in sorted(os.listdir(apps_dir)):
        if not fname.endswith('.yml'):
            continue
        try:
            app = parse_yaml_file(os.path.join(apps_dir, fname))
            if app and 'id' in app:
                raw_apps.append(app)
        except Exception as e:
            errors += 1

    print(f"Parsed {len(raw_apps)} apps ({errors} errors)")

    # --- Output 1: JSONL for HuggingFace ---
    hf_path = os.path.join(data_dir, 'saas_vendors_hf.jsonl')
    with open(hf_path, 'w') as f:
        for app in raw_apps:
            entry = build_hf_entry(app)
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    hf_size = os.path.getsize(hf_path)
    print(f"HuggingFace JSONL: {hf_size:,} bytes ({hf_size/1024:.0f} KB)")

    # --- Output 2: JSON for runtime lookup ---
    domain_index = {}
    apps_dict = {}

    for app in raw_apps:
        app_id = app.get('id', '')
        if not app_id:
            continue

        entry, all_domains = build_runtime_entry(app)
        apps_dict[app_id] = entry

        for domain in all_domains:
            domain_index[domain] = app_id

        # Also index notification email domains
        for email in (app.get('registrationEmails', []) or []):
            if '@' in email:
                nd = email.split('@')[1].lower()
                if nd not in domain_index:
                    domain_index[nd] = app_id

    runtime_output = {
        "_meta": {
            "version": "2.0",
            "source": "resmoio/app-catalog",
            "app_count": len(apps_dict),
            "domain_count": len(domain_index),
        },
        "domain_index": dict(sorted(domain_index.items())),
        "apps": dict(sorted(apps_dict.items())),
    }

    runtime_path = os.path.join(data_dir, 'saas_vendors.json')
    with open(runtime_path, 'w') as f:
        json.dump(runtime_output, f, indent=2)

    runtime_size = os.path.getsize(runtime_path)
    print(f"Runtime JSON:      {runtime_size:,} bytes ({runtime_size/1024:.0f} KB)")

    # Stats
    print(f"\nApps: {len(apps_dict)}")
    print(f"Domain index entries: {len(domain_index)}")

    cats = {}
    for v in apps_dict.values():
        cats[v['category']] = cats.get(v['category'], 0) + 1
    print(f"\nTop categories ({len(cats)}):")
    for c, n in sorted(cats.items(), key=lambda x: -x[1])[:10]:
        print(f"  {c:35s} {n:4d}")

    # Show sample HF entry
    sample = build_hf_entry(raw_apps[0])
    print(f"\nSample HF entry ({sample['id']}):")
    print(json.dumps(sample, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
