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
                    timestamp REAL
                  )''')
conn.commit()

def on_connect(client, userdata, flags, rc, properties):
    if rc == 0:
        print("Connected to MQTT broker successfully")
        client.subscribe("cli/watts")
    else:
        print(f"Failed to connect, return code {rc}")

def on_message(client, userdata, msg):
    data = msg.payload.decode()
    timestamp, current, voltage, power = parse_watt(data)
    if timestamp != 0:
        cursor.execute('INSERT INTO cli_watts_data (current, voltage, power, timestamp) VALUES (?, ?, ?, ?)',(current, voltage, power, timestamp))
        conn.commit()
        print(f"cli/watts: Timestamp={timestamp}, Current={current}, Voltage={voltage}, Power={power}")

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

# Create a client
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message

client.connect("mosquitto", 31883, 60)
client.loop_forever()