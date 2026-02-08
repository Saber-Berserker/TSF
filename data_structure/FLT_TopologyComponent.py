import json

class Switch:
    def __init__(self, inetAddress, connectedSince, openFlowVersion, switchDPID):
        self.inetAddress = inetAddress
        self.connectedSince = connectedSince    # 时间戳
        self.openFlowVersion = openFlowVersion
        self.switchDPID = switchDPID

    def __repr__(self):
        return f"Switch(switchDPID={self.switchDPID})"


class Link:
    def __init__(self, src_switch, src_port, dst_switch, dst_port, link_type, direction, latency):
        self.src_switch = src_switch
        self.src_port = src_port
        self.dst_switch = dst_switch
        self.dst_port = dst_port
        self.link_type = link_type
        self.direction = direction
        self.latency = latency

    def __repr__(self):
        return f"Link(src_switch={self.src_switch}, dst_switch={self.dst_switch})"


class Host:
    def __init__(self, entityClass, mac, ipv4, ipv6, vlan, attachmentPoint, lastSeen):
        self.entityClass = entityClass
        self.lastSeen = lastSeen    # 时间戳

        # 下面的都可能是列表，都可能有多个值
        self.mac = mac
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.vlan = vlan
        self.attachmentPoint = attachmentPoint  # 有 Switch, Port两个 JSON 属性


    def __repr__(self):
        # 暂不考虑 ipv6
        return f"Host(mac={self.mac}, ipv4={self.ipv4}, attachmentPoint={self.attachmentPoint})"


class Topology:
    """
    Contains lists of switches, links, and hosts.
    """

    def __init__(self):
        self.switches = []
        self.links = []
        self.hosts = []

    def add_switch(self, switch_data):
        switch = Switch(
            inetAddress=switch_data["inetAddress"],
            connectedSince=switch_data["connectedSince"],
            openFlowVersion=switch_data["openFlowVersion"],
            switchDPID=switch_data["switchDPID"]
        )
        self.switches.append(switch)

    def add_link(self, link_data):
        link = Link(
            src_switch=link_data["src-switch"],
            src_port=link_data["src-port"],
            dst_switch=link_data["dst-switch"],
            dst_port=link_data["dst-port"],
            link_type=link_data["type"],
            direction=link_data["direction"],
            latency=link_data["latency"]
        )
        self.links.append(link)

    def add_host(self, host_data):
        host = Host(
            entityClass=host_data["entityClass"],
            mac=host_data["mac"],
            ipv4=host_data["ipv4"],
            ipv6=host_data["ipv6"],
            vlan=host_data["vlan"],
            attachmentPoint=host_data["attachmentPoint"],
            lastSeen=host_data["lastSeen"]
        )
        self.hosts.append(host)

    def load_from_response(self, typeValue: int, response_data: json):
        """
        Load data from JSON response into the appropriate objects.
        type: 1 - switch, 2 - link, 3 - host.
        """
        if typeValue == 1:
            for switch_data in response_data:
                self.add_switch(switch_data)
        elif typeValue == 2:
            for link_data in response_data:
                self.add_link(link_data)
        elif typeValue == 3:
            for host_data in response_data.get("devices", []):
                self.add_host(host_data)

    def __repr__(self):
        """
        Representation of the topology for output.
        """
        return (f"Topology(\n"
                f"\tswitches={self.switches}\n"
                f"\tlinks={self.links}\n"
                f"\thosts={self.hosts}\n)")