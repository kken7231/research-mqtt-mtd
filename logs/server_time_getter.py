import re
import pandas as pd
from datetime import datetime
import yaml
import matplotlib.pyplot as plt

# Regex patterns
issuer_start_pattern = re.compile(r"^(.{26})\| authserver    \| Issuer - Accepted mTLS connection from 192\.168\.11\.19:[\d]+$")
# issuer_end_pattern = re.compile(r"^(.{26})\| authserver    \| Issuer - Closed mTLS connection with 192\.168\.11\.19:[\d]+$")
mqttif_start_pattern = re.compile(r"^(.{26})\| mqttinterface \| \*\*\(192\.168\.11\.19:[\d]+\)> 10 \(1 bytes\)$")
mqttif_end_pattern = re.compile(r"^(.{26})\| mqttinterface \| Closed connection with 192\.168\.11\.19:[\d]+ \(client\)$")
tls_start_pattern = re.compile(r"^(.{26})\| mosquitto-tls \| [\d]+: New connection from 192\.168\.11\.19:[\d]+ on port 8883.$")
tls_end_pattern = re.compile(r"^(.{26})\| mosquitto-tls \| [\d]+: Client esp32-tls-cli disconnected\.$")

# Initialize variables
issuer_start_time = None
mqttif_start_time = None
tls_start_time = None

def parse_duration(start, end):
    start_time = datetime.strptime(start, "%Y-%m-%d %H:%M:%S.%f")
    end_time = datetime.strptime(end, "%Y-%m-%d %H:%M:%S.%f")
    duration = (end_time - start_time).total_seconds()
    return duration

def process_log_line(line):
    global issuer_start_pattern, mqttif_start_pattern, mqttif_end_pattern, tls_start_pattern, tls_end_pattern
    global issuer_start_time, mqttif_start_time, tls_start_time
    match = issuer_start_pattern.match(line)
    if match:
        assert not mqttif_start_time
        assert not tls_start_time
        issuer_start_time = match.group(1).strip()
        print(f"  - start: \"{issuer_start_time}\"")
        return
    
    match = mqttif_start_pattern.match(line)
    if match:
        if issuer_start_time:
            return
        assert not tls_start_time
        mqttif_start_time = match.group(1).strip()
        print(f"  - start: \"{mqttif_start_time}\"")
        return
    
    match = mqttif_end_pattern.match(line)
    if match:
        assert issuer_start_time or mqttif_start_pattern
        assert not tls_start_time
        issuer_start_time = None
        mqttif_start_time = None
        print(f"    end: \"{match.group(1).strip()}\"")
        return
    

    match = tls_start_pattern.match(line)
    if match:
        assert not issuer_start_time
        assert not mqttif_start_time
        tls_start_time = match.group(1).strip()
        print(f"  - start: \"{tls_start_time}\"")
        return
    
    match = tls_end_pattern.match(line)
    if match:
        assert not issuer_start_time
        assert not mqttif_start_time
        assert tls_start_time
        tls_start_time = None
        print(f"    end: \"{match.group(1).strip()}\"")
        return

        
# Process log file
with open('combined.log', 'r') as file:
    for line in file:
        process_log_line(line.strip())
