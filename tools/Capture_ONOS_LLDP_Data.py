from scapy.all import *
import json

print("Sniffing for LLDP packets...")
lldp = bytes(sniff(filter="ether proto 0x88cc", count=1)[0]).hex()

src_mac = lldp[12:24]
portId = lldp[52:54]
deviceID = lldp[114:152]
timestamp = lldp[164:180]
sig = lldp[192:256]

json_data = {
    'SrcMac': src_mac,
    'DeviceId': deviceID,
    'PortId': portId,
    'TimeStamp': timestamp,
    'Sig': sig
}
print(json.dumps(json_data))