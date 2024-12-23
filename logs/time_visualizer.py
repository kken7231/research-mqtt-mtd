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
testcases = []
current_testcase = None
current_iteration = None

def parse_duration(start, end):
    start_time = datetime.strptime(start, "%Y-%m-%d %H:%M:%S.%f")
    end_time = datetime.strptime(end, "%Y-%m-%d %H:%M:%S.%f")
    duration = (end_time - start_time).total_seconds()
    return duration

def add_iteration_data():
    global current_iteration
    if current_iteration and "events" in current_iteration:
        testcases.append(current_iteration)
    current_iteration = None

def process_log_line(line):
    global current_testcase, current_iteration
    # Match for testcase start
    match = testcase_start_pattern.match(line)
    if match:
        testcase_name = match.group(1).strip()
        if testcase_name == "Plain":
            current_testcase = "plain"
        elif testcase_name == "Plain(AEAD)":
            current_testcase = "plain_aead"
        elif testcase_name == "TLS":
            current_testcase = "tls"
        else:
            current_testcase = testcase_name
        return

    # Match for testcase end
    if testcase_end_pattern.match(line):
        add_iteration_data()
        current_testcase = None
        return

    # Match for summary start
    if summary_start_pattern.match(line):
        add_iteration_data()  # Save any previous iteration before starting a new one
        current_iteration = {"testcase": current_testcase, "events": {}}
        return

    # Match for event lines
    match = event_pattern.match(line)
    if match and current_iteration:
        timestamp = match.group(1).strip()
        event_name = match.group(2).strip()
        event_status = match.group(3).strip()

        # Skip tokenmgr_init and tokenmgr_deinit events
        if event_name in ["tokenmgr_init", "tokenmgr_deinit"]:
            return

        if event_status == "started":
            if event_name not in current_iteration["events"]:
                current_iteration["events"][event_name] = {"start": timestamp}
        elif event_status == "ended":
            if event_name in current_iteration["events"] and "start" in current_iteration["events"][event_name]:
                start_time = current_iteration["events"][event_name]["start"]
                duration = parse_duration(start_time, timestamp)
                current_iteration["events"][event_name]["duration"] = duration
        return
    
    match = iteration_summary_pattern.match(line)
    if match and current_iteration:
        iteration_number = match.group(1).strip()
        current_iteration["iteration_number"] = iteration_number
        return


# Process log file
with open('log.esp32-tokenmgr.20240831154756.txt', 'r') as file:
    for line in file:
        process_log_line(line.strip())

# Convert to DataFrame
data = []
for testcase in testcases:
    row = {"testcase": testcase["testcase"], "iteration": int(testcase["iteration_number"])+1}
    for event_name, details in testcase["events"].items():
        row[event_name] = details.get("duration")
    data.append(row)

df = pd.DataFrame(data)
# Output DataFrame as a string
table_str = df.to_string()

# Alternatively, write to a text file
with open('time_table.txt', 'w') as f:
    f.write(table_str)

# Calculate "get_token other than fetch_tokens"
df['get_token_other'] = df['get_token'] - df['fetch_tokens']

# Drop the unnecessary columns
df_filtered = df.drop(columns=['get_token', 'get_token_internal'])

# Get the list of unique test cases
testcases = df_filtered['testcase'].unique()

# Specify the colors for each column by name
color_map = {
    'fetch_tokens': 'blue',  
    'get_token_other': 'red',  
    'b64encode_token': 'green',
    'seal_message': 'orange', 
    'mqtt_publish_qos0': 'purple'
}

# Specify the order of the columns for stacking
stack_order = ['fetch_tokens', 'get_token_other', 'b64encode_token', 'seal_message', 'mqtt_publish_qos0']


# Calculate the number of test cases to determine the grid size
n_testcases = len(testcases)

base_font_size = 12  # Base font size
font_size_multiplier = 1.75
title_font_size = 21
plt.rcParams.update({'font.size': base_font_size * font_size_multiplier})

# Create a figure with a grid of subplots, each sized (10, 4.5)
fig, axes = plt.subplots(nrows=n_testcases, ncols=1, figsize=(10, 4.5 * n_testcases))

# Ensure axes is always iterable (even if there's only one subplot)
if n_testcases == 1:
    axes = [axes]

# Create a stacked bar chart for each testcase and add it to the subplot
for ax, testcase in zip(axes, testcases):
    # Construct the file name based on the provided argument
    config_file = f'plot_confs/{testcase}.yaml'

    # Load configuration from the constructed YAML file
    with open(config_file, 'r') as file:
        config = yaml.safe_load(file)

    # Parse configurations
    plot_type = config['plot_config']['type']

    # Filter the DataFrame for the current testcase
    df_testcase = df_filtered[df_filtered['testcase'] == testcase].dropna(axis=1, how='all')

    # Set the iteration as the index (x-axis)
    df_testcase = df_testcase.set_index('iteration')

    # Filter the stack_order and colors list to include only columns present in df
    stack_order_present = [col for col in stack_order if col in df_testcase.columns]
    colors_present = [color_map[col] for col in stack_order_present]

    # Plot each column as a stacked bar in the subplot ax
    df_testcase[stack_order_present].plot(kind='bar', stacked=True, color=colors_present, ax=ax)
    ax.set_title(f"Publish Duration ({plot_type})", fontsize=title_font_size)
    ax.set_xlabel("Iteration", fontsize=base_font_size * font_size_multiplier)
    ax.set_ylabel("Duration (seconds)", fontsize=base_font_size * font_size_multiplier)
    loc = 'upper right'
    if testcase == "tls":
        loc = 'lower right'
    ax.legend(loc=loc, bbox_to_anchor=(0.5, 0, 0.5, 1))
    ax.set_ylim(0, 2.5)
    ax.set_xlim(-0.5, len(df_testcase) - 0.5)  # Set x-axis limits to fit all bars

# Adjust the layout to make sure everything fits without overlapping
plt.tight_layout()

# Save the concatenated plot as a single PNG file
output_file = f'plots/time_concat.png'
plt.savefig(output_file, format='png')

