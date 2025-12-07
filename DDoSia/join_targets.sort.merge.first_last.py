#!/usr/bin/env python3
# Author: Copilot / SC
# parses raw get_target files and merges results into CSV rows by server, attack start / end time , target_id, ... 
# Example
# server_ip,first_seen,last_seen,target_id,request_id,host,ip,type,method,port,use_ssl
# 195.35.19.138,1706420267,1706503610,642fe3c5318a95e39142647a,642c31e545eef2551df4c284,www.hsl.fi,52.137.3.174,http,GET,443,True
# 195.35.19.138,1706420267,1706503610,642fe3c5318a95e39142647a,642c31e545eef2551df4c286,www.hsl.fi,52.137.3.174,http,,443,True

import os
import gzip
import json
import csv
import sys
import re
from collections import defaultdict

def enumerate_get_targets_files():
    dir_path = os.path.dirname(os.path.abspath(__file__))

    # Regex to extract timestamp from filename, e.g. get_targets.1729094169.json.gz
    ts_regex = re.compile(r"get_targets\.(\d+)\.json\.gz")
    # Regex to extract IP address from a folder name, e.g. logs_212.192.31.34
    ip_folder_regex = re.compile(r"logs_(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?$")

    # Data structure: per server_ip, group by request_id
    merged_targets = defaultdict(lambda: defaultdict(list))
    # To collect any targets=null events
    null_targets_notes = []

    for root, dirs, files in os.walk(dir_path):
        # Determine parent folder IP address for this root, if present
        ip_address = ""
        split_root = root.split(os.sep)
        if split_root:
            last_folder = split_root[-1]
            m_ip = ip_folder_regex.match(last_folder)
            if m_ip:
                ip_address = m_ip.group(1)

        for filename in files:
            m = ts_regex.match(filename)
            if m:
                epoch_ts = int(m.group(1))
            else:
                continue  # skip files that don't match the pattern

            file_path = os.path.join(root, filename)
            try:
                with gzip.open(file_path, 'rt', encoding="utf-8") as f:
                    data = json.load(f)
                    targets = data.get("targets", [])
                    # Handle case where targets is None
                    if targets is None:
                        null_targets_notes.append({
                            "server_ip": ip_address,
                            "first_seen": epoch_ts,
                            "last_seen": epoch_ts,
                            "target_id": "",
                            "request_id": "",
                            "host": "",
                            "ip": "",
                            "type": "",
                            "method": "",
                            "port": "",
                            "use_ssl": "",
                            # "path": ""
                        })
                        continue

                    for entry in targets:
                        # Group by server_ip + request_id
                        reqid = entry.get("request_id", "")
                        tid = entry.get("target_id", "")

                        merged_targets[ip_address][reqid].append({
                            "timestamp": epoch_ts,
                            "target_id": tid,
                            "request_id": reqid,
                            "host": entry.get("host", ""),
                            "ip": entry.get("ip", ""),
                            "type": entry.get("type", ""),
                            "method": entry.get("method", ""),      # Output gets noisy
                            "port": entry.get("port", ""),
                            "use_ssl": entry.get("use_ssl", ""),    # Output gets noisy
                            # "path": entry.get("path", "")           # Output gets noisy
                        })
            except Exception as e:
                print(f"Failed to read {file_path}: {e}", file=sys.stderr)

    all_rows = []
    # For each server_ip, each request_id, calculate first/last seen
    for server_ip, reqid_group in merged_targets.items():
        for request_id, records in reqid_group.items():
            timestamps = [rec["timestamp"] for rec in records]
            first_seen = min(timestamps)
            last_seen = max(timestamps)
            # Make a merged row using the first record, but replace timestamps
            first_record = records[0].copy()
            first_record.update({
                "server_ip": server_ip,
                "first_seen": first_seen,
                "last_seen": last_seen
            })
            # Remove original single timestamp field
            if "timestamp" in first_record:
                del first_record["timestamp"]
            all_rows.append(first_record)

    # Also append any null targets notes
    all_rows.extend(null_targets_notes)

    # Print as CSV to stdout
    if all_rows:
        fieldnames = [
            "server_ip",
            "first_seen",
            "last_seen",
            "target_id", "request_id", "host", "ip", 
            "type", "method", 
            "port", 
            "use_ssl", 
            # "path"
        ]
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_rows:
            writer.writerow(row)

if __name__ == "__main__":
    enumerate_get_targets_files()