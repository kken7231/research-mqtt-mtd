import re

MQTT_TOPIC_NAME_REGEX = re.compile(r'^(?!.*[+#])(?=.{1,65535}$)[^\u0000]*$')

N_RANDBYTES = 12
L_RAND_TOPIC_NAME = 8+1+N_RANDBYTES

def toHex(bs: bytes):
    return " ".join(["%02X" % b for b in bs])