import re
import json
import os
import shutil
from datetime import datetime
from time import gmtime, strftime



def divide_by_host_and_timeframe(start_time, end_time):
    directory = "./collected_logs"
    hosts_dict = {}
    
    for filename in os.listdir(directory):
        host = filename.split("_")[0]
        if host not in hosts_dict:
            hosts_dict[host] = [os.path.join(directory, filename)]
        else:
            hosts_dict[host].append(os.path.join(directory, filename))
    
    windows_dict = {}
    for host, file_list in hosts_dict.items():
        for file_path in file_list:
            with open(file_path, 'r') as file:
                lines = file.readlines()
            for line in lines:
                line_timestamp = line.split("|")[1]
                line_timestamp = line_timestamp.split("=")[1].strip()
                dt = datetime.strptime(line_timestamp, "%Y-%m-%d %H:%M:%S")
                if dt > start_time and dt < end_time:
                    if host not in windows_dict:
                        windows_dict[host] = []
                    windows_dict[host].append(line)
    
    return windows_dict
                


def copy_rename_preprocess(target_paths):
    
    search_root = "./russellmitchell"
    destination_dir = "./collected_logs"

    # Ensure destination exists
    os.makedirs(destination_dir, exist_ok=True)

    for path in target_paths:
        full_path = os.path.normpath(os.path.join(search_root, path))
        
        parts = full_path.split(os.sep)
        parts = parts[2:]
        parts = [p.replace("_", "-") for p in parts]
        new_name = "_".join(parts)
        new_path = os.path.join(destination_dir, new_name)
        
        shutil.copy(full_path, destination_dir)
        shutil.move(os.path.join(destination_dir, os.path.basename(full_path)), new_path)
        
        fix_format(new_path)
    



def fix_format(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    intro_time="TIMESTAMP= "
    intro_name="LOG NAME= "
    
    format_pattern = "%Y-%m-%d %H:%M:%S"
    
    host_path = file_path.split(os.sep)[2]
    
    new_lines = ""
    for line in lines:
        formatted_time = ""
        if("audit" in file_path):
            unix_time = re.search(r'\(([^:]+):[^)]+\)', line).group(1)
            formatted_time=strftime(format_pattern, gmtime(float(unix_time)))
        elif("suricata" in file_path):
            ts = re.search(r'\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+', line).group(0)
            dt = datetime.strptime(ts, "%m/%d/%Y-%H:%M:%S.%f")
            formatted_time=dt.strftime(format_pattern)
        elif(("auth" in file_path) or ("syslog" in file_path) or ("dnsmasq" in file_path)): # Jan 21 00:14:21 # Jan 23 06:25:05
            ts = re.search(r'\w{3} \d{1,2} \d{2}:\d{2}:\d{2}', line).group(0)
            dt = datetime.strptime(ts, "%b %d %H:%M:%S")
            dt = dt.replace(year=2022)
            formatted_time=dt.strftime(format_pattern)
        elif("apache2" in file_path): # apache2 access 10.143.2.91 - - [24/Jan/2022:07:34:57 +0000] #apache2 errors [Sun Jan 23 06:25:13.569352 2022] 
            if("access" in file_path):
                ts = re.search(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}) [+\-]\d{4}\]', line).group(1)
                dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
                formatted_time=dt.strftime(format_pattern)
            elif "error" in file_path:
            # matches: [Sat Jan 22 06:25:04.223068 2022]
                if line.startswith("["):
                    ts = re.search(r'\[([A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}\.\d+ \d{4})\]', line).group(1)
                    # parse weekday, month, day, time.microsec, year
                    dt = datetime.strptime(ts, "%a %b %d %H:%M:%S.%f %Y")
                    formatted_time = dt.strftime(format_pattern)
                else:
                    continue
            else:
                print("heck no: ", file_path)
        elif "logstash" in file_path:
            obj = json.loads(line)
            # 1) parse & reformat @timestamp
            ts_iso = obj.get("@timestamp")
            dt = datetime.strptime(ts_iso, "%Y-%m-%dT%H:%M:%S.%fZ")
            formatted_time = dt.strftime(format_pattern)

            # 2) pull out the host name
            # Metricbeat puts it under "host.name"
            host_name = obj.get("host", {}).get("name", "unknown-host")

            # 3) pull out the CPU fields
            cpu = obj["system"]["cpu"]
            def pct(field):
                return f"{cpu[field]['pct'] * 100:.1f}%"

            parts = [
                f"host={host_name} ",
                f"total={pct('total')} ",
                f"user={pct('user')} ",
                f"system={pct('system')} ",
                f"idle={pct('idle')} ",
                f"nice={pct('nice')} ",
                f"iowait={pct('iowait')} ",
                f"steal={pct('steal')}",
            ]

            # 4) build the final simplified line
            line = "".join(parts)
            line += "\n"
            

        
        new_lines+=f"{intro_name}{host_path} | {intro_time}{formatted_time} | {line}"
        
    with open(file_path, 'w') as file:
        file.write(new_lines)
        
        
if __name__ == "__main__":
    paths = [
    "gather/intranet_server/logs/apache2/access.log",
    "gather/intranet_server/logs/apache2/error.log.1",
    "gather/intranet_server/logs/apache2/error.log.2",
    "gather/intranet_server/logs/apache2/error.log.3",
    "gather/intranet_server/logs/apache2/error.log.4",
    "gather/intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log",
    "gather/intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.1",
    "gather/intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.2",
    "gather/intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.3",
    "gather/intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.4",
    "gather/intranet_server/logs/apache2/intranet.smith.russellmitchell.com-error.log",
    "gather/intranet_server/logs/apache2/intranet.smith.russellmitchell.com-error.log.1",
    "gather/intranet_server/logs/apache2/intranet.smith.russellmitchell.com-error.log.2",
    "gather/intranet_server/logs/apache2/intranet.smith.russellmitchell.com-error.log.3",
    "gather/intranet_server/logs/audit/audit.log",
    "gather/intranet_server/logs/suricata/fast.log",
    "gather/intranet_server/logs/auth.log",
    "gather/intranet_server/logs/auth.log.1",
    "gather/intranet_server/logs/syslog.1",
    "gather/intranet_server/logs/syslog.2",
    "gather/intranet_server/logs/syslog.3",
    "gather/intranet_server/logs/syslog.4",

    "gather/internal_share/logs/audit/audit.log",
    "gather/internal_share/logs/suricata/fast.log",
    "gather/internal_share/logs/auth.log",
    "gather/internal_share/logs/auth.log.1",
    "gather/internal_share/logs/syslog.1",
    "gather/internal_share/logs/syslog.2",
    "gather/internal_share/logs/syslog.3",
    "gather/internal_share/logs/syslog.4",

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
    dt1 = datetime(2022, 1, 20, 11, 12, 0, 0)
    dt2 = datetime(2022, 1, 20, 11, 14, 0, 0)
    dic = divide_by_host_and_timeframe(dt1,dt2)
    for host, lines in dic.items():
        print(f"Host: {host}")
        for line in lines:
            print(line)