import os                # Operating system interactions (file paths, directory listing, etc.)
import re                # Regular expressions for pattern matching in strings
import json              # For parsing JSON files (used for labels)
import shutil            # For copying and moving files
from datetime import datetime, timedelta  # For date and time manipulation
from time import gmtime, strftime           # For converting timestamps
from collections import defaultdict       # Simplifies dictionary use with default types

# Constants and configurations
LABELS_DIR = "russellmitchell/labels"       # Directory where label data is stored
COLLECTED_LOGS_DIR = "./collected_logs"       # Directory where selected and pre-processed logs will be stored
SEARCH_ROOT = "./russellmitchell"             # Root folder for searching original logs
FORMAT_PATTERN = "%Y-%m-%d %H:%M:%S"          # Standard format for timestamps

class BatchRussell:
    """
    BatchRussell represents a processed batch of log lines with metadata.
    It extracts the sources and labels for each batch based on the provided lines.
    """
    def __init__(self, lines, reference_timestamp):
        # Initialize batch with only log line data and indexes
        self.lines = [line for _, line in lines]
        self.line_indexes = [i for i, _ in lines]
        self.reference_timestamp = reference_timestamp  # The timestamp for the batch
        self.labels = self.extract_labels()  # Extracts any attached labels from log lines
        self.sources = self.extract_sources()  # Extracts log sources from log lines

    def __repr__(self):
        # Provide a shortened string representation for debugging
        short_lines = []
        for l in self.lines:
            line_parts = l.split("|") 
            short_lines.append(f"{line_parts[0]} | {line_parts[1]} | {line_parts[2][:10]}....{line_parts[2][-10:]}")
        line_with_index = list(zip(self.line_indexes, short_lines))
        lines_to_print = []
        for i, l in line_with_index:
            lines_to_print.append(f"{i} | {l}")
        return_string =(
            f"Batch:\n\tTimestamp: {self.reference_timestamp}\n\t"
            f"Sources: {self.sources}\n\tLabels: {self.labels}\n"
        )
        for l in lines_to_print:
            return_string += f"\t{l}"
        return return_string.strip()
        
    def __str__(self):
        # Same as __repr__ for a simple string conversion
        short_lines = []
        for l in self.lines:
            line_parts = l.split("|")
            short_lines.append(f"{line_parts[0]} | {line_parts[1]} | {line_parts[2][:10]}....{line_parts[2][-10:]}")
        line_with_index = list(zip(self.line_indexes, short_lines))
        lines_to_print = []
        for i, l in line_with_index:
            lines_to_print.append(f"{i} | {l}")
        return_string =(
            f"Batch:\n\tTimestamp: {self.reference_timestamp}\n\t"
            f"Sources: {self.sources}\n\tLabels: {self.labels}\n"
        )
        for l in lines_to_print:
            return_string += f"\t{l}"
        return return_string.strip()

    def get_batch_as_string(self):
        # Returns all log lines into a single string
        return ''.join(self.lines)

    def extract_sources(self):
        """
        Extracts unique sources from the batch.
        Looks for a pattern like 'LOG NAME= <source>' in each line.
        """
        sources = set()
        for line in self.lines:
            match = re.search(r'LOG NAME= ([^|]+)', line)
            if match:
                sources.add(match.group(1).strip())
        return list(sources)

    def extract_labels(self):
        """
        Extract labels by mapping each source to its corresponding label file.
        The label file is expected to be found in the LABELS_DIR.
        """
        labels = set()
        label_cache = {}

        # Map each source to its line indexes for matching
        source_to_lines = defaultdict(set)
        for idx, line in zip(self.line_indexes, self.lines):
            match = re.search(r'LOG NAME= ([^|]+)', line)
            if match:
                source = match.group(1).strip()
                source_to_lines[source].add(idx)

        for source, indexes in source_to_lines.items():
            # Convert underscores in the source to OS-specific path separators
            path = os.path.join(LABELS_DIR, source.replace("_", os.sep))
            if not os.path.isfile(path):
                continue  # Skip if label file does not exist

            # Cache file content to avoid re-reading if used by multiple lines
            if path not in label_cache:
                with open(path) as f:
                    label_cache[path] = [json.loads(l) for l in f]

            for obj in label_cache[path]:
                if obj.get("line") in indexes:
                    labels.update(obj.get("labels", []))

        return list(labels)

def divide_by_host_and_timeframe(start_time, end_time, overlap_minutes, max_overlap_logs):
    """
    Groups log lines by host and divides them into two time frames: 
    one for the main window (between start_time and end_time) and an overlap window (before start_time).
    """
    hosts = defaultdict(list)

    # Group files from the collected logs directory by host (assumes host in filename as prefix)
    for filename in os.listdir(COLLECTED_LOGS_DIR):
        host = filename.split("_")[0]
        filepath = os.path.join(COLLECTED_LOGS_DIR, filename)
        hosts[host].append(filepath)

    windows = defaultdict(list)
    overlap_dict = defaultdict(list)
    overlap_time = start_time - timedelta(minutes=overlap_minutes)
    for host, filepaths in hosts.items():
        for path in filepaths:
            with open(path) as f:
                lines = f.readlines()

            for i, line in enumerate(lines):
                try:
                    # Extract timestamp from line assuming format "LOG NAME= ... | TIMESTAMP= <timestamp> | ..."
                    timestamp = line.split("|")[1].split("=")[1].strip()
                    dt = datetime.strptime(timestamp, FORMAT_PATTERN)
                    if start_time < dt < end_time:
                        windows[host].append((i, line))
                    if overlap_time <= dt <= start_time:
                        overlap_dict[host].append((i, line))
                except (IndexError, ValueError):
                    # Skips broken or unexpected log lines
                    continue
                
    return windows, overlap_dict

def prepare_batches_russell(reference_time, lookback_minutes, batch_size, overlap_minutes, overlap_percentage, multihost):
    """
    Prepares batches of log entries based on the provided timeframe.
    If multihost is True, it sorts and combines logs from all hosts.
    Otherwise, it creates batches for each host separately.
    """
    # Calculate start of the window (lookback duration) example if request time is 2022-01-23 11:20:00 and lookback is 10 minutes then start_time will be 2022-01-23 11:10:00
    start_time = reference_time - timedelta(minutes=lookback_minutes)
    
    overlap_size = round(overlap_percentage * batch_size)
    host_logs, overlap_logs = divide_by_host_and_timeframe(start_time, reference_time, overlap_minutes, max_overlap_logs=overlap_size)
    batches = []
    
    if multihost:
        # Collect and sort all lines from all hosts by timestamp.
        all_lines = [entry for lines in host_logs.values() for entry in lines]
        all_lines.sort(key=lambda entry: datetime.strptime(entry[1].split("|")[1].split("=")[1].strip(), FORMAT_PATTERN))
        
        # Similarly sort the overlap logs.
        all_lines_overlap = [entry for lines in overlap_logs.values() for entry in lines]
        all_lines_overlap.sort(key=lambda entry: datetime.strptime(entry[1].split("|")[1].split("=")[1].strip(), FORMAT_PATTERN))
        if len(all_lines_overlap) > overlap_size: # we cut the overlap logs to the last overlap_size entries
            temp = all_lines_overlap[-overlap_size:]
        else:
            temp = all_lines_overlap
        actual_batch = len(temp)
        i = 0
        # Iterate through all lines and create batches
        while i < len(all_lines): 
            if actual_batch < batch_size - 1:
                temp.append(all_lines[i])
                actual_batch += 1
            else:
                temp.append(all_lines[i])
                # Create a new batch once the batch size is nearly reached
                batches.append(BatchRussell(temp, reference_time))
                actual_batch = 0
                temp = []
                i -= overlap_size  # subtract overlap_size from index for batch overlapping
            i += 1
        if temp:  # Create a final batch for remaining log lines
            batches.append(BatchRussell(temp, reference_time))    
    else:
        # Create batches per host, as above but for each host separately
        for host, lines in host_logs.items():
            if len(overlap_logs[host]) > overlap_size:
                temp = overlap_logs[host][-overlap_size:]
            else:
                temp = overlap_logs[host]
            actual_batch = len(temp)
            i = 0
            while i < len(lines): 
                if actual_batch < batch_size - 1:
                    temp.append(lines[i])
                    actual_batch += 1
                else:
                    temp.append(lines[i])
                    batches.append(BatchRussell(temp, reference_time))
                    actual_batch = 0
                    temp = []
                    i -= overlap_size  # subtract overlap_size from index for batch overlapping
                i += 1
            if temp:
                batches.append(BatchRussell(temp, reference_time))  
    return batches

def copy_rename_preprocess(paths):
    """
    Processes log files from given paths:
    - Copies them into COLLECTED_LOGS_DIR.
    - Renames them with underscores replaced.
    - Calls fix_format to adjust file formatting.
    """
    os.makedirs(COLLECTED_LOGS_DIR, exist_ok=True)

    for path in paths: #dataset files specific code
        full_path = os.path.normpath(os.path.join(SEARCH_ROOT, path))
        parts = [p.replace("_", "-") for p in full_path.split(os.sep)[2:]]
        new_name = "_".join(parts)
        new_path = os.path.join(COLLECTED_LOGS_DIR, new_name)

        shutil.copy(full_path, COLLECTED_LOGS_DIR)
        shutil.move(os.path.join(COLLECTED_LOGS_DIR, os.path.basename(full_path)), new_path)
        fix_format(new_path)

def fix_format(file_path):
    """
    Opens a log file and reformats each line by pre-pending the log name and a corrected timestamp.
    """
    with open(file_path) as f:
        lines = f.readlines()

    host_path = file_path.split(os.sep)[2]  # extracting the host name from the path
    formatted_lines = []

    for line in lines:
        try:
            # Extract a correctly formatted timestamp from the log line
            formatted_time = extract_timestamp(file_path, line)
            formatted_line = f"LOG NAME= {host_path} | TIMESTAMP= {formatted_time} | {line}"
            formatted_lines.append(formatted_line)
        except Exception:
            # Silently skip lines that cannot be formatted
            continue

    with open(file_path, 'w') as f:
        f.writelines(formatted_lines)

def extract_timestamp(file_path, line):
    """
    Determines the correct timestamp for a log line based on the file type.
    Supports formats for audit, suricata, auth/syslog/dnsmasq, apache2, openvpn, and logstash logs.
    Can be easily extended for additional log formats.
    """
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
        
    if "openvpn" in file_path:
        ts = line[0:19].strip()  # Expected fixed width timestamp at the start of the line
        return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S").strftime(FORMAT_PATTERN)

    if "logstash" in file_path:
        obj = json.loads(line)
        ts = obj["@timestamp"]
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
        cpu = obj["system"]["cpu"]

        def pct(field): 
            return f"{cpu[field]['pct'] * 100:.1f}%"

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

    # If the file type is unsupported, raise an error.
    raise ValueError(f"Unsupported format: {file_path}")

        
if __name__ == "__main__":
    # List of paths (relative to SEARCH_ROOT) to the gathered log files.
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
        "gather/monitoring/logs/logstash/intranet-server/2022-01-25-system.cpu.log",
        
        "gather/vpn/logs/openvpn.log",
        "gather/vpn/logs/suricata/fast.log",
    ]
    
    # Process and prepare logs by copying, renaming and fixing format.
    copy_rename_preprocess(paths)
    
    #test and debug code
    # dt1 = datetime(2022, 1, 21, 11, 12, 0, 0)
    # dt2 = datetime(2022, 1, 23, 11, 20, 0, 0)
    # batches = prepare_batches_russell(dt2, 10, 10, overlap_minutes=10, overlap_percentage=0.2, multihost=True)
    # for batch in batches:
    #     if batch.labels:
    #         print(batch)