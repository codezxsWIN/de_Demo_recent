"""Fixed loopback lab topology; never an address range or external target."""

ENVIRONMENTS = {
    "127.0.0.2": {
        "id": "office",
        "name": "Office file and remote-access network",
        "tcp": {
            6379: "redis",
            2121: "ftp",
            2122: "ftp",
            2222: "ssh",
            2223: "ssh",
            1445: "microsoft-ds",
            1446: "microsoft-ds",
        },
        "udp": {},
        "comparisons": "Anonymous FTP denied on 2122; password SSH denied on 2223; anonymous SMB denied on 1446.",
        "checks": ["ftp-anonymous", "smb-guest", "smb-signing", "ssh-default-credential"],
    },
    "127.0.0.3": {
        "id": "iot",
        "name": "IoT telemetry and message-broker network",
        "tcp": {1883: "mqtt", 1884: "mqtt", 8883: "mqtts", 6379: "redis"},
        "udp": {1161: "snmp", 1162: "snmp"},
        "comparisons": "Anonymous MQTT denied on 1884; public SNMP community denied on UDP/1162.",
        "checks": ["mqtt-anonymous", "snmp-public", "mqtt-expired-certificate"],
    },
}


def environment(ip):
    return ENVIRONMENTS.get(ip)
