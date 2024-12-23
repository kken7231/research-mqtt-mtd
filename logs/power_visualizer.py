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

    # Example Visualization: Line chart of power consumption over time difference in seconds
    df_filtered.plot(x='time_diff_seconds', y='power', kind='line', linestyle='-', color='black', ax=ax)
    ax.set_xlabel('Time (seconds from the start of the first iteration)', fontsize=base_font_size * font_size_multiplier)
    ax.set_ylabel('Power Consumption (mW)', fontsize=base_font_size * font_size_multiplier)
    ax.set_title(f"Power Consumption Over Time ({plot_type})", fontsize=title_font_size)  # Use the specified title font size from the YAML
    ax.set_xlim(-5, (end_time - start_time).total_seconds() + 5)  # Set x-axis limits to cover the desired time range
    ax.set_ylim(0, 320) 

    # Draw vertical lines
    for i, iteration in enumerate(iterations):
        linewidth = 2 if i % 16 == 0 else 1
        line_time = parse_time(iteration["start"], local_tz)
        line_time_diff = (line_time - start_time).total_seconds()
        ax.axvline(x=line_time_diff, color='blue', linestyle='--', linewidth=linewidth)

    # Track previous label positions to avoid overlap
    previous_labels = []

    # Add multiple arrows and labels
    for arrow in arrows:
        arrow_time = parse_time(arrow['time'], local_tz)
        arrow_time_diff = (arrow_time - start_time).total_seconds()
        arrow_y_value = df_filtered[df_filtered['time_diff_seconds'] >= arrow_time_diff]['power'].iloc[0]
        
        # Determine a non-overlapping position for the label
        label_x_pos = arrow_time_diff
        label_y_pos = arrow_y_value * 0.1
        for prev_x, prev_y in previous_labels:
            if abs(prev_x - label_x_pos) < 20 and abs(prev_y - label_y_pos) < 20:
                label_y_pos += 10  # Adjust the y position to avoid overlap
        
        label_text = arrow['label']
        
        previous_labels.append((label_x_pos, label_y_pos))
        
        ax.annotate(
            label_text,
            xy=(arrow_time_diff, arrow_y_value),  # Arrow head position (end of the arrow)
            xytext=(label_x_pos, label_y_pos),  # Adjusted label position
            arrowprops=dict(facecolor='black', shrink=0.05, width=0.5, headwidth=5),
            fontsize=base_font_size * font_size_multiplier,  # Apply font size multiplier
            color='red'
        )

plt.tight_layout()

# Save the plot as a PNG file
output_file = f'plots/power_concat.png'
plt.savefig(output_file, format='png')