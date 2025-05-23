import os
import re
import json
import shutil
from datetime import datetime, timedelta
from time import gmtime, strftime
from collections import defaultdict

LABELS_DIR = "russellmitchell/labels"
COLLECTED_LOGS_DIR = "./collected_logs"
SEARCH_ROOT = "./russellmitchell"
FORMAT_PATTERN = "%Y-%m-%d %H:%M:%S"

class Batch:
    def __init__(self, lines, reference_timestamp):
        self.lines = [line for _, line in lines]
        self.line_indexes = [i for i, _ in lines]
        self.reference_timestamp = reference_timestamp
        self.labels = self.extract_labels()
        self.sources = self.extract_sources()

    def __repr__(self):
        return (
            f"Batch:\n\tTimestamp: {self.reference_timestamp}\n\t"
            f"Sources: {self.sources}\n\tLabels: {self.labels}\n\t"
            f"Lines: {len(self.lines)}"
        )
        
    def __str__(self):
        return (
            f"Batch:\n\tTimestamp: {self.reference_timestamp}\n\t"
            f"Sources: {self.sources}\n\tLabels: {self.labels}\n\t"
            f"Lines: {[l for l in self.lines]}"
        )

    def get_batch_as_string(self):
        return ''.join(self.lines)

    def extract_sources(self):
        sources = set()
        for line in self.lines:
            match = re.search(r'LOG NAME= ([^|]+)', line)
            if match:
                sources.add(match.group(1).strip())
        return list(sources)

    def extract_labels(self):
        labels = set()
        label_cache = {}

        # Map each source to its line indexes
        source_to_lines = defaultdict(set)
        for idx, line in zip(self.line_indexes, self.lines):
            match = re.search(r'LOG NAME= ([^|]+)', line)
            if match:
                source = match.group(1).strip()
                source_to_lines[source].add(idx)

        for source, indexes in source_to_lines.items():
            path = os.path.join(LABELS_DIR, source.replace("_", os.sep))
            if not os.path.isfile(path):
                continue

            if path not in label_cache:
                with open(path) as f:
                    label_cache[path] = [json.loads(l) for l in f]

            for obj in label_cache[path]:
                if obj.get("line") in indexes:
                    labels.update(obj.get("labels", []))

        return list(labels)

def divide_by_host_and_timeframe(start_time, end_time, overlap_minutes, max_overlap_logs):
    hosts = defaultdict(list)

    # Group logs by host
    for filename in os.listdir(COLLECTED_LOGS_DIR):
        host = filename.split("_")[0]
        filepath = os.path.join(COLLECTED_LOGS_DIR, filename)
        hosts[host].append(filepath)

    windows = defaultdict(list)
    overlap_dict = defaultdict(list)
    for host, filepaths in hosts.items():
        for path in filepaths:
            with open(path) as f:
                lines = f.readlines()

            for i, line in enumerate(lines):
                try:
                    timestamp = line.split("|")[1].split("=")[1].strip()
                    dt = datetime.strptime(timestamp, FORMAT_PATTERN)
                    if start_time < dt < end_time:
                        windows[host].append((i, line))
                    if start_time - timedelta(minutes=overlap_minutes) < dt < start_time:
                        overlap_dict[host].append((i, line))
                except (IndexError, ValueError):
                    continue
    
    for host, lines in overlap_dict.items():
        if len(lines) > max_overlap_logs:
            lines = lines[:-max_overlap_logs]
    
    return windows, overlap_dict

def prepare_batches(reference_time, lookback_minutes, batch_size, overlap_minutes, overlap_percentage, multihost):
    start_time = reference_time - timedelta(minutes=lookback_minutes) #todo rename lookback to qualcosa che ha senso, è la dim temporale di una batch
    overlap_size=round(overlap_percentage * batch_size)
    host_logs, overlap_logs = divide_by_host_and_timeframe(start_time, reference_time, overlap_minutes, overlap_size)
    batches = []

    # if multihost:
    #     all_lines = [entry for lines in host_logs.values() for entry in lines]
    #     for i in range(0, len(all_lines), batch_size):
    #         if 
    #         batches.append(Batch(all_lines[i:i + batch_size], reference_time))
    # else:
    #     for host, lines in host_logs.items():
    #         for i in range(0, len(lines), batch_size):
    #             batches.append(Batch(lines[i:i + batch_size], reference_time))
    if multihost:
        all_lines = [entry for lines in host_logs.values() for entry in lines]
        c=0
        temp=[]
        first = True
        actual_batch=0
        
        for i in range(all_lines):
            if(actual_batch<batch_size):
                temp.append(all_lines[i])
                actual_batch+=1
            else:
                batches.append(Batch(temp, reference_time))
                actual_batch=0
                temp=[]
                if not first:
                    i-= overlap
                else:
                    first=False
        if(temp):
            batches.append(Batch(temp, reference_time))    
    else:
        for host, lines in host_logs.items():
            c=0
            temp=[]
            first = True
            actual_batch=0
            overlap=round(overlap_percentage * batch_size)
            for i in range(lines):
                if(actual_batch<batch_size):
                    temp.append(all_lines[i])
                    actual_batch+=1
                else:
                    batches.append(Batch(temp, reference_time))
                    actual_batch=0
                    temp=[]
                    if not first:
                        i-= overlap
                    else:
                        first=False
            if(temp):
                batches.append(Batch(temp, reference_time))  
    return batches

def copy_rename_preprocess(paths):
    os.makedirs(COLLECTED_LOGS_DIR, exist_ok=True)

    for path in paths:
        full_path = os.path.normpath(os.path.join(SEARCH_ROOT, path))
        parts = [p.replace("_", "-") for p in full_path.split(os.sep)[2:]]
        new_name = "_".join(parts)
        new_path = os.path.join(COLLECTED_LOGS_DIR, new_name)

        shutil.copy(full_path, COLLECTED_LOGS_DIR)
        shutil.move(os.path.join(COLLECTED_LOGS_DIR, os.path.basename(full_path)), new_path)
        fix_format(new_path)

def fix_format(file_path):
    with open(file_path) as f:
        lines = f.readlines()

    host_path = file_path.split(os.sep)[2]
    formatted_lines = []

    for line in lines:
        try:
            formatted_time = extract_timestamp(file_path, line)
            formatted_line = f"LOG NAME= {host_path} | TIMESTAMP= {formatted_time} | {line}"
            formatted_lines.append(formatted_line)
        except Exception:
            continue

    with open(file_path, 'w') as f:
        f.writelines(formatted_lines)

def extract_timestamp(file_path, line):
    if "audit" in file_path:
        unix_time = re.search(r'\(([^:]+):', line).group(1)
        return strftime(FORMAT_PATTERN, gmtime(float(unix_time)))

    if "suricata" in file_path:
        ts = re.search(r'\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}', line).group(0)
        return datetime.strptime(ts, "%m/%d/%Y-%H:%M:%S").strftime(FORMAT_PATTERN)

    if any(x in file_path for x in ["auth", "syslog", "dnsmasq"]):
        ts = re.search(r'\w{3} \d{1,2} \d{2}:\d{2}:\d{2}', line).group(0)
        return datetime.strptime(ts, "%b %d %H:%M:%S").replace(year=2022).strftime(FORMAT_PATTERN)

    if "apache2" in file_path:
        if "access" in file_path:
            ts = re.search(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})', line).group(1)
            return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S").strftime(FORMAT_PATTERN)
        if "error" in file_path and line.startswith("["):
            ts = re.search(r'\[([A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}\.\d+ \d{4})\]', line).group(1)
            return datetime.strptime(ts, "%a %b %d %H:%M:%S.%f %Y").strftime(FORMAT_PATTERN)

    if "logstash" in file_path:
        obj = json.loads(line)
        ts = obj["@timestamp"]
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
        cpu = obj["system"]["cpu"]

        def pct(field): return f"{cpu[field]['pct'] * 100:.1f}%"

        parts = [
            f"host={obj['host']['name']} ",
            f"total={pct('total')} ",
            f"user={pct('user')} ",
            f"system={pct('system')} ",
            f"idle={pct('idle')} ",
            f"nice={pct('nice')} ",
            f"iowait={pct('iowait')} ",
            f"steal={pct('steal')}"
        ]
        return dt.strftime(FORMAT_PATTERN), "".join(parts) + "\n"

    raise ValueError(f"Unsupported format: {file_path}")


        
if __name__ == "__main__":
    paths = [
    "gather/intranet-server/logs/apache2/access.log",
    "gather/intranet-server/logs/apache2/error.log.1",
    "gather/intranet-server/logs/apache2/error.log.2",
    "gather/intranet-server/logs/apache2/error.log.3",
    "gather/intranet-server/logs/apache2/error.log.4",
    "gather/intranet-server/logs/apache2/intranet.smith.russellmitchell.com-access.log",
    "gather/intranet-server/logs/apache2/intranet.smith.russellmitchell.com-access.log.1",
    "gather/intranet-server/logs/apache2/intranet.smith.russellmitchell.com-access.log.2",
    "gather/intranet-server/logs/apache2/intranet.smith.russellmitchell.com-access.log.3",
    "gather/intranet-server/logs/apache2/intranet.smith.russellmitchell.com-access.log.4",
    "gather/intranet-server/logs/apache2/intranet.smith.russellmitchell.com-error.log",
    "gather/intranet-server/logs/apache2/intranet.smith.russellmitchell.com-error.log.1",
    "gather/intranet-server/logs/apache2/intranet.smith.russellmitchell.com-error.log.2",
    "gather/intranet-server/logs/apache2/intranet.smith.russellmitchell.com-error.log.3",
    "gather/intranet-server/logs/audit/audit.log",
    "gather/intranet-server/logs/suricata/fast.log",
    "gather/intranet-server/logs/auth.log",
    "gather/intranet-server/logs/auth.log.1",
    "gather/intranet-server/logs/syslog.1",
    "gather/intranet-server/logs/syslog.2",
    "gather/intranet-server/logs/syslog.3",
    "gather/intranet-server/logs/syslog.4",

    "gather/internal-share/logs/audit/audit.log",
    "gather/internal-share/logs/suricata/fast.log",
    "gather/internal-share/logs/auth.log",
    "gather/internal-share/logs/auth.log.1",
    "gather/internal-share/logs/syslog.1",
    "gather/internal-share/logs/syslog.2",
    "gather/internal-share/logs/syslog.3",
    "gather/internal-share/logs/syslog.4",

    "gather/inet-firewall/logs/suricata/fast.log",
    "gather/inet-firewall/logs/auth.log",
    "gather/inet-firewall/logs/auth.log.1",
    "gather/inet-firewall/logs/dnsmasq.log",
    "gather/inet-firewall/logs/syslog.1",
    "gather/inet-firewall/logs/syslog.2",
    "gather/inet-firewall/logs/syslog.3",
    "gather/inet-firewall/logs/syslog.4",

    "gather/inet-dns/logs/auth.log",
    "gather/inet-dns/logs/auth.log.1",
    "gather/inet-dns/logs/dnsmasq.log",
    "gather/inet-dns/logs/syslog",
    "gather/inet-dns/logs/syslog.1",
    "gather/inet-dns/logs/syslog.2",
    "gather/inet-dns/logs/syslog.3",
    "gather/inet-dns/logs/syslog.4",

    "gather/monitoring/logs/logstash/intranet-server/2022-01-20-system.cpu.log",
    "gather/monitoring/logs/logstash/intranet-server/2022-01-21-system.cpu.log",
    "gather/monitoring/logs/logstash/intranet-server/2022-01-22-system.cpu.log",
    "gather/monitoring/logs/logstash/intranet-server/2022-01-23-system.cpu.log",
    "gather/monitoring/logs/logstash/intranet-server/2022-01-24-system.cpu.log",
    "gather/monitoring/logs/logstash/intranet-server/2022-01-25-system.cpu.log"
    ]
    
    
    #copy_rename_preprocess(paths)
    dt1 = datetime(2022, 1, 21, 11, 12, 0, 0)
    dt2 = datetime(2022, 1, 23, 11, 20, 0, 0)
    batches = prepare_batches(dt2,10,10,True)
    for batch in batches:
        if batch.labels:
            print(batch)
    