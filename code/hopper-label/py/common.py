from ssl import create_default_context, Purpose
from pathlib import Path
from string import punctuation
from base64 import b64encode, b64decode
from datetime import datetime

# Configuration settings
TIMESTAMP_LENGTH = 4
IGNORED_BITS = 10
PORT_BROKER = 11883
RANDOMIZED_TOPIC_NAME_LENGTH = 13
NUM_RANDOMIZED_TOPIC_NAMES = 12
FETCH_LABEL = 'mqtt-mtd-hopping-label:'

BROKER_OUTPUT_DIRECTORY = Path("/mosquitto/topic_names")
PUBLISHER_OUTPUT_DIRECTORY = Path("/mosquitto/topic_names")

# Server addresses
SERVER_ADDRESS_8883 = ('broker', 8883)
SERVER_ADDRESS_1883 = ('broker', 1883)

# SSL/TLS Configuration
CA_FILE = "/mosquitto/config/certs/ca/ca.crt"
CERT_FILE = "/mosquitto/config/certs/broker/broker.crt"
KEY_FILE = "/mosquitto/config/certs/broker/broker.key"
CLIENT_CERT_FILE = "/mosquitto/config/certs/client/client.crt"
CLIENT_KEY_FILE = "/mosquitto/config/certs/client/client.key"

# Packet Types
PACKET_TYPES = [
    'RESRVED', 'CONNECT', 'CONNACK', 'PUBLISH', 'PUBACK_', 'PUBREC_',
    'PUBREL_', 'PUBCOMP', 'SUBSCRB', 'SUBACK_', 'UNSUBSC', 'UNSUBAC',
    'PINGREQ', 'PINGRSP', 'DISCNCT', 'AUTH___'
]

def is_ascii_printable(data: bytes) -> bool:
    try:
        decoded = data.decode('ascii')
        return all(char.isalnum() or char in ' ' + punctuation for char in decoded)
    except UnicodeDecodeError:
        return False

def b64decode_mqttsafe(bs: bytes) -> bytes:
    return b64decode(bs, altchars=b'!@')

def b64encode_mqttsafe(bs: bytes) -> bytes:
    return b64encode(bs, altchars=b'!@')

def print_hex(bs: bytes) -> str:
    return ' '.join(f"{b:02X}" for b in bs)

def print_packet(inout_spec: str, opponent: str, my_port: int, content: bytes) -> None:
    if inout_spec not in ('from', 'to'):
        print('Invalid inout_spec')
        return

    packet_type = 'UDEFND'
    message = f'len={len(content)}'

    if len(content) > 1:
        packet_type = PACKET_TYPES[(content[0] & 0xF0) >> 4]

    if len(content) > 4 and content[3] > 0 and packet_type == 'PUBLISH':
        len_topic_name = content[3]
        if len(content) >= 4 + len_topic_name:
            topic_name = content[4:4 + len_topic_name]
            topic_str = topic_name.decode() if is_ascii_printable(topic_name) else print_hex(topic_name)
            message += f", topic name: \"{topic_str}\""

    print(f"{datetime.now().ctime()} | {opponent}{'=>' if inout_spec == 'from' else '<='}:{my_port} [{packet_type}] {print_hex(content) if len(content) > 0 else ' (zero byte)'} ({message})")
