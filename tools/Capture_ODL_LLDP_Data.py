from scapy.all import *
import json

print("Sniffing for LLDP packets...")
lldp = bytes(sniff(filter="ether proto 0x88cc", count=1)[0]).hex()

json_data = {
    'TerminationPoint': lldp[86:122],
    'Sig': lldp[122:-4]
}
print(json.dumps(json_data))