#!/usr/bin/env python3
# Author: Copilot / SC
# parses raw get_target files and merges results into CSV rows by attack start / end time , target_id, ... - with issuing C2 servers as a list 
# Example
# first_seen,last_seen,target_id,request_id,host,ip,type,method,port,use_ssl,server_ips
# 1687762013,1706507219,64959e7b1b90cdf03714de8c,64959e7b1b90cdf03714de8d,privatbank24.com.ua,91.234.35.40,http,POST,443,True,"195.35.19.138,94.140.114.239,94.140.115.89"
# 1687762013,1706507219,64959e7b1b90cdf03714de8c,64959e7b1b90cdf03714de8e,privatbank24.com.ua,91.234.35.40,http,GET,443,True,"195.35.19.138,94.140.114.239,94.140.115.89"

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

    # Data structure: group by request_id (across all server_ip)
    merged_requests = defaultdict(list)
    # Store all unique server_ips seen for each request_id
    request_id_to_ips = defaultdict(set)
    # To collect any targets=null events, now also per request_id for consistency
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
                    # Handle case where targets is None, assign to special entry with server_ip and timestamp
                    if targets is None:
                        # Use a special request_id for these rows
                        null_targets_notes.append({
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
                            # "path": "",
                            "server_ips": [ip_address] if ip_address else []
                        })
                        continue

                    for entry in targets:
                        reqid = entry.get("request_id", "")
                        tid = entry.get("target_id", "")

                        # Collect all records for this request_id
                        merged_requests[reqid].append({
                            "server_ip": ip_address,
                            "timestamp": epoch_ts,
                            "target_id": tid,
                            "request_id": reqid,
                            "host": entry.get("host", ""),
                            "ip": entry.get("ip", ""),
                            "type": entry.get("type", ""),
                            "method": entry.get("method", ""),
                            "port": entry.get("port", ""),
                            "use_ssl": entry.get("use_ssl", ""),
                            # "path": entry.get("path", "")
                        })
                        # Track which IPs have seen this request_id
                        if ip_address:
                            request_id_to_ips[reqid].add(ip_address)
            except Exception as e:
                print(f"Failed to read {file_path}: {e}", file=sys.stderr)

    all_rows = []
    # For each request_id, merge IPs and calculate first/last seen
    for reqid, records in merged_requests.items():
        timestamps = [rec["timestamp"] for rec in records]
        first_seen = min(timestamps)
        last_seen = max(timestamps)
        ips = sorted(request_id_to_ips[reqid])  # sorted for consistency

        # Use first record as template
        first_record = records[0].copy()
        first_record.update({
            "first_seen": first_seen,
            "last_seen": last_seen,
            "server_ips": ips
        })
        # Remove original singular IP and timestamp
        if "server_ip" in first_record:
            del first_record["server_ip"]
        if "timestamp" in first_record:
            del first_record["timestamp"]
        all_rows.append(first_record)

    # Append any null targets notes (these will have blank fields except server_ips, first/last_seen)
    all_rows.extend(null_targets_notes)

    # Print as CSV to stdout
    if all_rows:
        fieldnames = [
            "first_seen",
            "last_seen",
            "target_id", "request_id", "host", "ip", 
            "type","method", 
            "port", 
            "use_ssl", 
            # "path",
            "server_ips"
        ]
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_rows:
            # server_ips as comma-joined string
            if isinstance(row.get("server_ips"), list):
                row["server_ips"] = ",".join(row["server_ips"])
            writer.writerow(row)

if __name__ == "__main__":
    enumerate_get_targets_files()