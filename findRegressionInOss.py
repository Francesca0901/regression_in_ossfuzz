import csv
import os
import yaml

introduced_commits = {}
fixed_commits = {}

base_dir = 'oss-fuzz-vulns/vulns'

for root, dirs, files in os.walk(base_dir):
    for file in files:
        if file.endswith('.yaml'):
            file_path = os.path.join(root, file)
            with open(file_path, 'r') as f:
                try:
                    data = yaml.safe_load(f)
                except yaml.YAMLError as e:
                    print(f"Error parsing YAML file {file_path}: {e}")
                    continue

                affected = data.get("affected") or []
                if not affected:
                    continue

                ranges = affected[0].get("ranges") or []
                if not ranges:
                    continue

                events = ranges[0].get("events") or []

                for event in events:
                    if event.get("introduced"):
                        introduced_commits[event["introduced"]] = file_path

                    if event.get("fixed"):
                        fixed_commits[event["fixed"]] = file_path

# cross-reference the introduced and fixed commits, and store the results

with open('regression.csv', 'w') as output_file:
    writer = csv.writer(output_file)
    writer.writerow(["repo","buggy_fix","fix0_file","fix1_file"])
    for introduced_commit, introduced_file in introduced_commits.items():
        if introduced_commit in fixed_commits:
            fixed_file = fixed_commits[introduced_commit]
            repo = introduced_file.split('/')[2]
            if introduced_file != fixed_file:
                writer.writerow([repo, introduced_commit, fixed_file, introduced_file])
                print(f"Introduced commit {introduced_commit} in {introduced_file} was aiming at fixing bug in {fixed_commits[introduced_commit]}")