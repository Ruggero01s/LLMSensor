import re
import datetime
from datetime import datetime, strftime, gmtime
import json

def fix_timestamp_format(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    intro="TIMESTAMP: "
    new_lines = ""
    for line in lines:
        formatted_time = ""
        if("audit" in file_path):
            unix_time = re.search(r'\(([^:]+):[^)]+\)', line).group(1)
            formatted_time=strftime('%Y-%m-%d %H:%M:%S', gmtime(float(unix_time)))
        elif("suricata" in file_path):
            ts = re.search(r'\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+', line).group(0)
            dt = datetime.strptime(ts, "%m/%d/%Y-%H:%M:%S.%f")
            formatted_time=dt.strftime('%Y-%m-%d %H:%M:%S')
        elif(("auth" in file_path) or ("syslog" in file_path) or ("dnsmasq" in file_path)): # Jan 21 00:14:21 # Jan 23 06:25:05
            ts = re.search(r'\w{3} \d{1,2} \d{2}:\d{2}:\d{2}', line).group(0)
            dt = datetime.strptime(ts, "%b %d %H:%M:%S")
            dt = dt.replace(year=2022)
            formatted_time=dt.strftime('%Y-%m-%d %H:%M:%S')
        elif("apache2" in file_path): # apache2 access 10.143.2.91 - - [24/Jan/2022:07:34:57 +0000] #apache2 errors [Sun Jan 23 06:25:13.569352 2022] 
            if("access" in file_path):
                ts = re.search(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}) [+\-]\d{4}\]', line).group(1)
                dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
                formatted_time=dt.strftime('%Y-%m-%d %H:%M:%S')
            elif "error" in file_path:
            # matches: [Sat Jan 22 06:25:04.223068 2022]
                ts = re.search(r'\[([A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}\.\d+ \d{4})\]', line).group(1)
                # parse weekday, month, day, time.microsec, year
                dt = datetime.strptime(ts, "%a %b %d %H:%M:%S.%f %Y")
                formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            else:
                print("heck no: ", file_path)
        elif "logstash" in file_path:
            obj = json.loads(line)
            # 1) parse & reformat @timestamp
            ts_iso = obj.get("@timestamp")
            dt = datetime.strptime(ts_iso, "%Y-%m-%dT%H:%M:%S.%fZ")
            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")

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
            
            
        new_lines+=intro + formatted_time + " | " + line
        
    with open(file_path, 'w') as file:
        file.write(new_lines)