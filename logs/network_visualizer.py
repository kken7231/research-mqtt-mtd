import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import yaml
import argparse


# Calculate the number of test cases to determine the grid size
n_testcases = 2

base_font_size = 12  # Base font size
font_size_multiplier = 1.75
title_font_size = 21
plt.rcParams.update({'font.size': base_font_size * font_size_multiplier})

# Create a figure with a grid of subplots, each sized (10, 4.5)
fig, axes = plt.subplots(nrows=n_testcases, ncols=1, figsize=(10, 4.5 * n_testcases))

zipped = [(axes[0], "plain"), (axes[0], "plain_aead"), (axes[1], "tls")]

# Define pcap file and IP filter directly
pcap_path = 'wireshark202408311559.pcapng'

# Capture all packets and filter them based on time range
cap = pyshark.FileCapture(pcap_path, display_filter='ip.addr == 192.168.11.19 && tcp.port in {1883, 8883, 18883}')

# Initialize a dictionary to store packets by TCP stream
packet_times_by_stream = {}
packets_by_stream = {}

# Parse the strings into timezone-aware datetime objects
local_tz = datetime.now().astimezone().tzinfo

# Iterate over packets and group them by TCP stream index
for packet in cap:
    if 'TCP' in packet:
        tcp_stream_index = int(packet.tcp.stream)
        pkt_time = packet.sniff_time.replace(tzinfo=local_tz)

        if tcp_stream_index not in packets_by_stream:
            packets_by_stream[tcp_stream_index] = []
        if tcp_stream_index not in packet_times_by_stream:
            packet_times_by_stream[tcp_stream_index] = []

        packets_by_stream[tcp_stream_index].append(packet)
        packet_times_by_stream[tcp_stream_index].append(pkt_time)


# Create a stacked bar chart for each testcase and add it to the subplot
for ax, testcase in zipped:
    # Construct the file name based on the provided argument
    config_file = f'plot_confs/{testcase}.yaml'

    # Load configuration from the constructed YAML file
    with open(config_file, 'r') as file:
        config = yaml.safe_load(file)

    # Parse configurations
    iterations = config['server_iterations']

    def parse_time(time_str, local_tz):
        return pd.to_datetime(time_str).tz_localize(local_tz)

    # Original start_time and end_time
    start_time = parse_time(iterations[0]["start"], local_tz)
    end_time = parse_time(iterations[-1]["end"], local_tz)

    # Adjust start_time and end_time by +/- 2 seconds
    adjusted_start_time = start_time - timedelta(seconds=2)
    adjusted_end_time = end_time + timedelta(seconds=2)

    # Parse iteration times
    parsed_iterations = []
    for iteration in iterations:
        start_time = parse_time(iteration["start"], local_tz)
        end_time = parse_time(iteration["end"], local_tz)
        parsed_iterations.append((start_time, end_time))

    # Initialize a dictionary to store byte counts per iteration
    byte_counts_per_iteration = {i+1: 0 for i in range(len(iterations))}
    packet_counts_per_iteration = {i+1: 0 for i in range(len(iterations))}

    for stream_index, times in packet_times_by_stream.items():
        first_time = min(times)
        last_time = max(times)

        overlapping_iterations = [
            i for i, t in enumerate(parsed_iterations) if t[0] <= last_time and t[1] >= first_time
        ]
        assert len(overlapping_iterations) <= 1
        if len(overlapping_iterations) == 1:
            overlapped_iteration_fromone = overlapping_iterations[0]+1
            byte_counts_per_iteration[overlapped_iteration_fromone] += sum(int(packet.length) for packet in packets_by_stream[stream_index])
            packet_counts_per_iteration[overlapped_iteration_fromone] += len(packets_by_stream[stream_index])

    # Convert the byte counts into a list corresponding to iterations
    iteration_indices = list(byte_counts_per_iteration.keys())
    byte_counts = list(byte_counts_per_iteration.values())

    # Apply font size multiplier
    base_font_size = 12  # Base font size
    plt.rcParams.update({'font.size': base_font_size * font_size_multiplier})

    # Plot the traffic (bytes per second) over time
    barwidth = 0.5
    barxoffset = 0
    barcolor = 'black'
    barlabel = None
    if testcase == "plain":
        barxoffset = -0.3
        barwidth = 0.3
        barcolor = 'blue'
        barlabel = 'Payload Security off'
    elif testcase == "plain_aead":
        barwidth = 0.3
        barcolor = 'red'
        barlabel = 'Payload Security on'
    ax.bar([x+barxoffset for x in iteration_indices], byte_counts, width=barwidth, linestyle='-', color=barcolor, label=barlabel)
    if testcase == "tls":
        ax.set_title(f"Network Traffic Over Time (Over TLS)", fontsize=title_font_size)
    else:
        ax.set_title(f"Network Traffic Over Time (MQTT-MTD)", fontsize=title_font_size)
        ax.legend(loc='upper right', bbox_to_anchor=(0.5, 0, 0.5, 1))
    ax.set_xlabel('Iteration', fontsize=base_font_size * font_size_multiplier)
    ax.set_ylabel('Bytes Exchanged', fontsize=base_font_size * font_size_multiplier)
    ax.set_ylim(0, 12000)
    ax.set_xlim(0.5, len(iteration_indices)+0.5)
    ax.set_xticks(iteration_indices)
    ax.set_xticklabels(iteration_indices, rotation=90)

plt.tight_layout()


# Save the plot as a PNG file
output_file = f'plots/traffic_concat.png'
plt.savefig(output_file, format='png')

# Close the capture file
cap.close()