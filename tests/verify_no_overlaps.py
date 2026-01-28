#!/usr/bin/env python3
"""Final verification: check for any overlaps in all example files."""

import json
import subprocess
import sys


def main():
    print("🔍 Verifying no overlaps across all example files...\n")
    
    result = subprocess.run(
        ['python', '-m', 'coderisk_ai.cli', 'analyze', 'examples/'],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        print(f"❌ Analyzer failed: {result.stderr}")
        return 1
    
    data = json.loads(result.stdout)
    
    # Group findings by file
    files_checked = {}
    
    for finding in data['findings']:
        if finding['category'] != 'A07_identification_authentication_failures':
            continue
        
        rule_id = finding['rule_id']
        
        for inst in finding['instances']:
            file_path = inst['file']
            line_num = inst['line_start']
            
            if file_path not in files_checked:
                files_checked[file_path] = {}
            
            if line_num not in files_checked[file_path]:
                files_checked[file_path][line_num] = []
            
            files_checked[file_path][line_num].append(rule_id)
    
    # Check for overlaps
    total_overlaps = 0
    
    for file_path, lines in files_checked.items():
        file_overlaps = []
        for line_num, rules in lines.items():
            if len(rules) > 1:
                file_overlaps.append((line_num, rules))
                total_overlaps += 1
        
        if file_overlaps:
            print(f"❌ {file_path}:")
            for line_num, rules in file_overlaps:
                print(f"   Line {line_num}: {', '.join(rules)}")
        else:
            print(f"✅ {file_path}: No overlaps")
    
    print()
    
    if total_overlaps > 0:
        print(f"❌ Found {total_overlaps} overlapping line(s) across all files")
        return 1
    else:
        print("✅ SUCCESS: No overlaps found in any file!")
        print(f"   Checked {len(files_checked)} files with A07 findings")
        return 0


if __name__ == "__main__":
    sys.exit(main())
