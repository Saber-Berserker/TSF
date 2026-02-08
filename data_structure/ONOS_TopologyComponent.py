import json


class Switch:
    def __init__(self, DeviceId, device_type, available, role, mfr, hw, sw, serial, driver, chassisId,
                 lastUpdate, humanReadableLastUpdate, annotations):
        self.id = DeviceId
        self.device_type = device_type
        self.available = available
        self.role = role
        self.mfr = mfr
        self.hw = hw
        self.sw = sw
        self.serial = serial
        self.driver = driver
        self.chassisId = chassisId

        # 这个属性下有个 channelId 不太会影响后续拓扑的大幅不同，并且 fuzz 的时候贼喜欢不一样，因此不比较——但是会影响交换机的稳定性, TODO: Bug?
        self.annotations = annotations

        # 下面这俩一般和时间有关，一般拓扑变换不予考虑此类属性
        self.lastUpdate = lastUpdate
        self.humanReadableLastUpdate = humanReadableLastUpdate

    def __repr__(self):
        return f"Device(id={self.id})"


class Link:
    def __init__(self, src_device, src_port, dst_device, dst_port, link_type, state):
        self.src_device = src_device
        self.src_port = src_port
        self.dst_device = dst_device
        self.dst_port = dst_port
        self.link_type = link_type
        self.state = state

    def __repr__(self):
        return f"Link(src={self.src_device}, dst={self.dst_device})"


class Host:
    def __init__(self, hostId, mac, vlan, innerVlan, outerTpid, configured, suspended, ipAddresses, locations):
        self.id = hostId
        self.mac = mac
        self.vlan = vlan
        self.innerVlan = innerVlan
        self.outerTpid = outerTpid
        self.configured = configured
        self.suspended = suspended
        self.ipAddresses = ipAddresses
        self.locations = locations  # list of dictionaries containing elementId and port

    def __repr__(self):
        return f"Host(id={self.id}, mac={self.mac}, ipAddresses={self.ipAddresses}, locations={self.locations})"


class Topology:
    """
    包含 devices, links, hosts 三个列表数据结构.
    """

    def __init__(self):
        self.devices = []
        self.links = []
        self.hosts = []

    def add_device(self, device_data):
        device = Switch(
            DeviceId=device_data["id"],
            device_type=device_data["type"],
            available=device_data["available"],
            role=device_data["role"],
            mfr=device_data["mfr"],
            hw=device_data["hw"],
            sw=device_data["sw"],
            serial=device_data["serial"],
            driver=device_data["driver"],
            chassisId=device_data["chassisId"],
            lastUpdate=device_data["lastUpdate"],
            humanReadableLastUpdate=device_data["humanReadableLastUpdate"],
            annotations=device_data["annotations"]
        )
        self.devices.append(device)

    def add_link(self, link_data):
        link = Link(
            src_device=link_data["src"]["device"],
            src_port=link_data["src"]["port"],
            dst_device=link_data["dst"]["device"],
            dst_port=link_data["dst"]["port"],
            link_type=link_data["type"],
            state=link_data["state"]
        )
        self.links.append(link)

    def add_host(self, host_data):
        host = Host(
            hostId=host_data["id"],
            mac=host_data["mac"],
            vlan=host_data["vlan"],
            innerVlan=host_data["innerVlan"],
            outerTpid=host_data["outerTpid"],
            configured=host_data["configured"],
            suspended=host_data["suspended"],
            ipAddresses=host_data["ipAddresses"],
            locations=host_data["locations"]
        )
        self.hosts.append(host)

    def load_from_response(self, typeValue: int, response_data: json):
        """
        从json数据中获取数据，写入对应的对象里.
        type: 1 - device, 2 - link, 3 - host.

        :param typeValue:
        :param response_data:
        :return:
        """
        if typeValue == 1:
            for device_data in response_data.get("devices", []):
                self.add_device(device_data)
        elif typeValue == 2:
            for link_data in response_data.get("links", []):
                self.add_link(link_data)
        elif typeValue == 3:
            for host_data in response_data.get("hosts", []):
                self.add_host(host_data)

    def __repr__(self):
        """
        作为输出参数时输出的模式.
        :return:
        """
        return (f"Topology(\n"
                f"\tdevices={self.devices}\n"
                f"\tlinks={self.links}\n"
                f"\thosts={self.hosts}\n)")
