from scapy.all import *
import json

print("Sniffing for LLDP packets...")
lldp = bytes(sniff(filter="ether proto 0x88cc", count=1)[0]).hex()

src_mac = lldp[12:24]
controller_id = lldp[92:112]
# deviceID = lldp[114:152]
# timestamp = lldp[164:180]
# sig = lldp[192:256]


# chassis=020704000000000001
# port=0403020004
# ttl=06020078
# dpid=fe0c0026e1000000000000000001
# controller=180806be3f47aac6e5db
# forward=e60101
# timestamp=fe0c0026e1010000000169d3c9d0
# end=0000
json_data = {
    'SrcMac': src_mac,
    'ControllerId': controller_id,

}
print(json.dumps(json_data))