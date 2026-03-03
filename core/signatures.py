# signatures.py

DEVICE_SIGNATURES = {
    "firewall": {
        "pfsense": ["pfSense webConfigurator", "pfsense-"],
        "mikrotik": ["Mikrotik", "Winbox", "RouterOS"],
        "fortinet": ["FortiGate", "Fortinet"]
    },
    "iot": {
        "hikvision": ["Hikvision", "App-layer/1.0"],
        "dahua": ["Dahua", "Server: dvr"]
    },
    "printer": {
        "hp": ["HP JetDirect", "HP FutureSmart"],
        "epson": ["EpsonNet Config", "EPSON HTTP Server"]
    }
}