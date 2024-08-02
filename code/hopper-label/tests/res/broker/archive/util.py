import re
import fcntl
import os
from io import TextIOWrapper 
import json
import base64

MQTT_TOPIC_NAME_REGEX = re.compile(r'^(?!.*[+#])(?=.{1,65535}$)[^\u0000]*$')

N_RANDBYTES = 12
L_RAND_TOPIC_NAME = 8+1+N_RANDBYTES

CA_FILE = "/mosquitto/config/certs/ca/ca.crt"
CERT_FILE_BROKER = "/mosquitto/config/certs/broker/broker.crt"
KEY_FILE_BROKER = "/mosquitto/config/certs/broker/broker.key"
CERT_FILE_CLIENT = "/mosquitto/config/certs/broker/broker.crt"
KEY_FILE_CLIENT = "/mosquitto/config/certs/broker/broker.key"

RESOLVE_TABLE_LOCKFILE = "/mosquitto/resolvTbl.lock"
RESOLVE_TABLE_FILE = "/mosquitto/resolvTbl.json"

RESOLVER_LOCKFILE = "/mosquitto/resolver.lock"
RESOLVER_ADDRESS = ('broker', 8883)

RECEPTION_ADDRESS = ('broker', 1883)

def acquire_resolvTbl_lock():
    lockinfo = acquire_lock(RESOLVE_TABLE_LOCKFILE)
    return None if lockinfo is None else lockinfo[0]

def release_resolvTbl_lock(lockfile):
    release_lock(lockfile, RESOLVE_TABLE_LOCKFILE)

def update_table(topic_name: str, rand_topic_name: bytes):
    data: dict[str] = None
    if os.path.exists(RESOLVE_TABLE_FILE):
        with open(RESOLVE_TABLE_FILE, "r") as f:
            data = json.load(f)        
    if not data:
        return -1
    data[topic_name] = base64.b64encode(rand_topic_name).decode()
    with open(RESOLVE_TABLE_FILE, "w") as f:
        json.dump(data)

def get_table(topic_name: str):
    data: dict[str] = None
    with open(RESOLVE_TABLE_FILE, "r") as f:
        data = json.load(f)
    return data.get(topic_name)

def remove_table(topic_name: str):
    data: dict[str] = None
    if os.path.exists(RESOLVE_TABLE_FILE):
        with open(RESOLVE_TABLE_FILE, "r") as f:
            data = json.load(f)
    data[topic_name] = None
    with open(RESOLVE_TABLE_FILE, "w") as f:
        json.dump(data, f)

def lookup_table(rand_topic_name: bytes):
    rand_topic_name_str = base64.b64encode(rand_topic_name).decode()
    if os.path.exists(RESOLVE_TABLE_FILE):
        with open(RESOLVE_TABLE_FILE, "r") as f:
            data: dict[str] = json.load(f)
        for k, v in data.items():
            if v == rand_topic_name_str:
                return k
    return None

def acquire_lock(lock_filepath: str):
    lockfile: TextIOWrapper = open(lock_filepath, 'w')
    try:
        fcntl.flock(lockfile, fcntl.LOCK_EX)
        lockfile.write(str(os.getpid()))
        lockfile.flush()
        return (lockfile, lock_filepath)
    except IOError:
        print("Failed to acquire lock. Exiting.")
        lockfile.close()
        return None

def release_lock(lockfile: TextIOWrapper, lock_filepath: str):
    if not lockfile.closed:
        fcntl.flock(lockfile, fcntl.LOCK_UN)
        lockfile.close()
        os.remove(lock_filepath)

def toHex(bs: bytes):
    return " ".join(["%02X" % b for b in bs])