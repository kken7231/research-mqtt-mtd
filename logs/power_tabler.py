import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import pytz
import yaml
import argparse

testcases = ["plain", "plain_aead", "tls"]
# Calculate the number of test cases to determine the grid size
n_testcases = len(testcases)

base_font_size = 12  # Base font size
font_size_multiplier = 1.75
title_font_size = 21
plt.rcParams.update({'font.size': base_font_size * font_size_multiplier})

# Create a figure with a grid of subplots, each sized (10, 5)
fig, axes = plt.subplots(nrows=n_testcases, ncols=1, figsize=(10, 5 * n_testcases))

# Ensure axes is always iterable (even if there's only one subplot)
if n_testcases == 1:
    axes = [axes]

data = pd.Series()

# Create a stacked bar chart for each testcase and add it to the subplot
for ax, testcase in zip(axes, testcases):
    # Construct the file name based on the provided argument
    config_file = f'plot_confs/{testcase}.yaml'

    # Load configuration from the constructed YAML file
    with open(config_file, 'r') as file:
        config = yaml.safe_load(file)

    # Parse configurations
    plot_type = config['plot_config']['type']
    arrows = config['plot_config']['arrows']

    db_path = config['database_config']['db_path']
    query = config['database_config']['query']
    iterations = config['iterations']  # Retrieve vertical line times from config

    # Define the system's local timezone
    local_tz = datetime.now().astimezone().tzinfo

    # Parse the strings into timezone-aware datetime objects
    def parse_time(time_str, local_tz):
        return pd.to_datetime(time_str).tz_localize(local_tz)

    start_time = parse_time(iterations[0]["start"], local_tz)
    end_time = parse_time(iterations[-1]["end"], local_tz)

    # Connect to the SQLite database
    conn = sqlite3.connect(db_path)

    # Fetch data from a table
    df = pd.read_sql_query(query, conn)

    # Close the database connection
    conn.close()

    # Convert UNIX timestamp to datetime with the system's local timezone
    df['datetime'] = pd.to_datetime(df['timestamp'], unit='s').dt.tz_localize('UTC').dt.tz_convert(local_tz)

    # Calculate the difference in seconds from start_time
    df['time_diff_seconds'] = (df['datetime'] - start_time).dt.total_seconds()

    start_time_adjusted = start_time - timedelta(seconds=2)
    end_time_adjusted = end_time+ timedelta(seconds=2)

    # Filter data to plot only within the adjusted time range
    df_filtered = df[(df['datetime'] >= start_time_adjusted) & (df['datetime'] <= end_time_adjusted)]

    data[testcase] = df_filtered['power'].mean()

print(data)