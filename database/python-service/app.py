import sqlite3
import paho.mqtt.client as mqtt
import json
from datetime import datetime, timezone, timedelta

# Connect to SQLite
conn = sqlite3.connect('/db/sqlite.db')
cursor = conn.cursor()

# Create table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS cli_watts_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    current REAL,
                    voltage REAL,
                    power REAL,
                    timestamp TEXT
                  )''')
cursor.execute('''CREATE TABLE IF NOT EXISTS cli_timelog_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type REAL,
                    label TEXT,
                    timestamp TEXT
                  )''')
cursor.execute('''CREATE TABLE IF NOT EXISTS cli_network_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rx REAL,
                    tx REAL,
                    timestamp TEXT
                  )''')
cursor.execute('''CREATE TABLE IF NOT EXISTS srv_timelog_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type REAL,
                    label TEXT,
                    timestamp TEXT
                  )''')
cursor.execute('''CREATE TABLE IF NOT EXISTS srv_network_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rx REAL,
                    tx REAL,
                    timestamp TEXT
                  )''')

conn.commit()

def on_connect(client, userdata, flags, rc, properties):
    if rc == 0:
        print("Connected to MQTT broker successfully")
        client.subscribe("#")
    else:
        print(f"Failed to connect, return code {rc}")

def on_message(client, userdata, msg):
    data = msg.payload.decode()
    print(f"on_message Topic: {msg.topic}\n")
    if msg.topic == "cli/watts":
        timestamp, current, voltage, power = parse_watt(data)
        if timestamp != 0:
            timestamp = datetime.fromtimestamp(float(timestamp),tz=timezone(timedelta(hours=9))).isoformat()
            cursor.execute('INSERT INTO cli_watts_data (current, voltage, power, timestamp) VALUES (?, ?, ?, ?)',(current, voltage, power, timestamp))
            conn.commit()
            print(f"cli/watts: Timestamp={timestamp}, Current={current}, Voltage={voltage}, Power={power}")
    elif msg.topic == "cli/timelog":
        timestamp, event_type, label = parse_timelog(data)
        if timestamp != 0:
            timestamp = datetime.fromtimestamp(float(timestamp),tz=timezone(timedelta(hours=9))).isoformat()
            cursor.execute('INSERT INTO cli_timelog_data (event_type, label, timestamp) VALUES (?, ?, ?)',(event_type, label, timestamp))
            conn.commit()
            print(f"cli/timelog: Timestamp={timestamp}, EventType={event_type}, Label={label}")
    elif msg.topic == "cli/network":
        timestamp, tx, rx = parse_network(data)
        if timestamp != 0:
            timestamp = datetime.fromtimestamp(float(timestamp),tz=timezone(timedelta(hours=9))).isoformat()
            cursor.execute('INSERT INTO cli_network_data (tx, rx, timestamp) VALUES (?, ?, ?)',(tx, rx, timestamp))
            conn.commit()
            print(f"cli/network: Timestamp={timestamp}, EventType={event_type}, Label={label}")
    elif msg.topic == "srv/timelog":
        timestamp, event_type, label = parse_timelog(data)
        if timestamp != 0:
            timestamp = datetime.fromtimestamp(float(timestamp),tz=timezone(timedelta(hours=9))).isoformat()
            cursor.execute('INSERT INTO srv_timelog_data (event_type, label, timestamp) VALUES (?, ?, ?)',(event_type, label, timestamp))
            conn.commit()
            print(f"srv/timelog: Timestamp={timestamp}, EventType={event_type}, Label={label}")
    elif msg.topic == "srv/network":
        timestamp, tx, rx = parse_network(data)
        if timestamp != 0:
            timestamp = datetime.fromtimestamp(float(timestamp),tz=timezone(timedelta(hours=9))).isoformat()
            cursor.execute('INSERT INTO srv_network_data (tx, rx, timestamp) VALUES (?, ?, ?)',(tx, rx, timestamp))
            conn.commit()
            print(f"srv/network: Timestamp={timestamp}, EventType={event_type}, Label={label}")

def parse_watt(data):
    try:
        data_dict = json.loads(data)
        timestamp = int(data_dict.get('ts', 0))
        current = float(data_dict.get('cur', 0.0))
        voltage = float(data_dict.get('vol', 0.0))
        power = float(data_dict.get('pow', 0.0))
        return timestamp, current, voltage, power
    except json.JSONDecodeError:
        print("Failed to parse watts data")
        return 0, -1, -1, -1

def parse_timelog(data):
    try:
        data_dict = json.loads(data)
        timestamp = int(data_dict.get('ts', 0))
        event_type = int(data_dict.get('type', 0))
        label = data_dict['label']
        return timestamp, event_type, label
    except json.JSONDecodeError:
        print("Failed to parse timelog data")
        return 0, -1, ""

def parse_network(data):
    try:
        data_dict = json.loads(data)
        timestamp = int(data_dict.get('ts', 0))
        tx = int(data_dict.get('tx', 0))
        rx = int(data_dict.get('rx', 0))
        return timestamp, tx, rx
    except json.JSONDecodeError:
        print("Failed to parse watts data")
        return 0, -1, -1

# Create a client
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message

client.connect("mosquitto", 31883, 60)
client.loop_forever()