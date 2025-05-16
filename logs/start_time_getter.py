import re
import pandas as pd
from datetime import datetime
import yaml
import matplotlib.pyplot as plt

# Regex patterns
testcase_start_pattern = re.compile(r"^(.*?) Test Start: (.*)")
testcase_end_pattern = re.compile(r"^(.*?) Test End:")
summary_start_pattern = re.compile(r"^Time Record Summary:")
summary_divider_pattern = re.compile(r"^====================")
event_pattern = re.compile(r"^(.{26}?) (.*?) (started|ended)")
iteration_summary_pattern = re.compile(r"\(\d+\)\[(\d+)\] \d+\.\d+ sec \(avg\. \d+\.\d+\)")

# Initialize variables
summary_just_started = False
previous_event_timestamp = None
previous_event_status = None

def parse_duration(start, end):
    start_time = datetime.strptime(start, "%Y-%m-%d %H:%M:%S.%f")
    end_time = datetime.strptime(end, "%Y-%m-%d %H:%M:%S.%f")
    duration = (end_time - start_time).total_seconds()
    return duration

def process_log_line(line):
    global summary_just_started, previous_event_timestamp, previous_event_status
    # Match for testcase start
    match = testcase_start_pattern.match(line)
    if match:
        testcase_name = match.group(1).strip()
        print(f"{testcase_name}: ")
        return

    # Match for summary start
    if summary_start_pattern.match(line):
        summary_just_started = True
        return
    
        # Match for summary start
    if summary_divider_pattern.match(line) and not summary_just_started:
        assert previous_event_status.startswith("ended")
        print(f"    end: \"{previous_event_timestamp}\"")
        previous_event_status = None
        previous_event_timestamp = None
        return


    # Match for event lines
    match = event_pattern.match(line)
    if match:
        timestamp = match.group(1).strip()
        event_name = match.group(2).strip()
        event_status = match.group(3).strip()
        # Skip tokenmgr_init and tokenmgr_deinit events
        if event_name in ["tokenmgr_init", "tokenmgr_deinit"]:
            return
        if summary_just_started:
            assert event_status == "started"
            print(f"  - start: \"{timestamp}\"")
            summary_just_started = False
            return
        else: 
            previous_event_timestamp = timestamp
            previous_event_status = event_status
            return
        
# Process log file
with open('log.esp32-tokenmgr.20240831154756.txt', 'r') as file:
    for line in file:
        process_log_line(line.strip())
