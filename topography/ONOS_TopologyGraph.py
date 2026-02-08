import networkx as nx
import matplotlib.pyplot as plt
from loguru import logger

from data_structure import ONOS_TopologyComponent
import Utils


class ONOSTopologyGraph:
    def __init__(self):
        # 创建一个多重有向图，允许多条边表示不同端口连接
        self.graph = nx.MultiDiGraph()

    def remove_link(self, src, dest, src_port=None, dest_port=None):
        """
        移除指定端口间的链路（可指定端口号）。如果不指定端口，移除所有链路。
        """
        edges = list(self.graph.get_edge_data(src, dest).items())
        for key, edge_data in edges:
            if (src_port is None or edge_data.get("src_port") == src_port) and \
                    (dest_port is None or edge_data.get("dest_port") == dest_port):
                self.graph.remove_edge(src, dest, key)

    def update_node(self, node_id, **attributes):
        """
        更新节点属性。
        """
        if node_id in self.graph:
            self.graph.nodes[node_id].update(attributes)

    def update_link(self, src, dest, src_port, dest_port, **attributes):
        """
        更新指定端口间链路的属性。
        """
        edges = self.graph.get_edge_data(src, dest)
        for key, edge_data in edges.items():
            if edge_data.get("src_port") == src_port and edge_data.get("dest_port") == dest_port:
                edge_data.update(attributes)
                break

    def add_devices(self, devices):
        """从 JSON 设备数据中添加交换机到图中."""
        for device in devices:
            # 提取设备信息
            device_id = device.id
            attributes = {
                "type": device.device_type,
                "available": device.available,
                "role": device.role,
                "mfr": device.mfr,
                "hw": device.hw,
                "sw": device.sw,
                "serial": device.serial,
                "driver": device.driver,
                "chassisId": device.chassisId,
                "annotations": device.annotations,

                # 下面的和时间有关，会影响后续拓扑不同的判断
                # "lastUpdate": device.lastUpdate,
                # "humanReadableLastUpdate": device.humanReadableLastUpdate,
            }
            # 将设备添加到图中，设备 ID 为节点
            self.graph.add_node(device_id, **attributes)

    def add_hosts(self, hosts):
        """从主机 JSON 数据中添加主机和连接到图中."""
        for host in hosts:
            # 提取主机信息
            host_id = host.id
            mac = host.mac
            ip_addresses = host.ipAddresses
            locations = host.locations

            # 将主机作为节点添加到图中
            self.graph.add_node(host_id, mac=mac, ip_addresses=ip_addresses, type="HOST")

            # 主机连接的设备
            for location in locations:
                device_id = location["elementId"]
                port = location["port"]
                # 添加主机和设备的边
                self.graph.add_edge(host_id, device_id, src_port="HOST", dst_port=port)

    def add_links(self, links):
        """从 JSON 链路数据中添加边到图中"""
        for link in links:
            # 提取链路信息
            src_device = link.src_device
            src_port = link.src_port
            dst_device = link.dst_device
            dst_port = link.dst_port
            link_type = link.link_type
            state = link.state

            # 将链路作为有向边添加到图中，带有源和目的端口等属性
            self.graph.add_edge(src_device, dst_device, src_port=src_port, dst_port=dst_port, type=link_type,
                                state=state)

    @staticmethod  # 类中的静态方法
    def node_is_same(oldElement, newElement):
        if oldElement != {} and newElement != {} and oldElement['type'] == newElement['type']:
            if oldElement['type'] == 'SWITCH':
                if oldElement['chassisId'] == newElement['chassisId']:  # 已经经过同构的测试了，直接考虑同 ChassisId 的情况, TODO: 是否会有漏？
                    # 表示控制器和交换机的连接的通道 ID, 很喜欢在测试中变换，但是对拓扑又没有什么大影响 TODO: Bug?
                    oldElement['annotations']['channelId'] = newElement['annotations']['channelId']
                    if oldElement != newElement:
                        logger.info(f"Difference.\n oldDevice: {oldElement}\n newDevice: {newElement}")
                        return False
                    else:
                        return True
                else:
                    return True
            elif oldElement['type'] == 'HOST':
                # LLDP 包基本不会影响主机的属性，因此只需要毕竟同构就行，添加的话反而会在后续的已存在的突变拓扑比较中引起误判（保存的是之前的 mininet 主机 mac）
                return True
                # # mac和ip不匹配，说明是不同的主机（或者新主机）
                # if (oldElement['mac'] == newElement['mac'] and oldElement['ip_addresses'] != newElement['ip_addresses']
                #     ) or (
                #         oldElement['mac'] != newElement['mac'] and oldElement['ip_addresses'] == newElement['ip_addresses']):
                #     logger.info(f"Difference.\n oldHost: {oldElement}\n newHost: {newElement}")
                #     return False
                # else:
                #     return True
        else:
            return True

    @staticmethod
    def edge_is_same(oldElement, newElement):
        for key in oldElement:
        # 很多同构的链路，容易引起误判（端口不同）
        #     if oldElement[key] != newElement[key]:
        #         logger.info(f"oldEdge: {oldElement}\n newEdge: {newElement}")
        #         return False
        #     else:
        #         return True
            if (oldElement[key]['src_port'] == 'HOST' or oldElement[key]['dst_port'] == 'HOST') or \
                    (newElement[key]['src_port'] == 'HOST' or newElement[key]['dst_port'] == 'HOST'):
                # 主机和交换机的边需要不区分端口和方向, 同时没有type，state属性，只需要比较同构，这里直接返回就行
                return True
            if oldElement[key]['type'] != newElement[key]['type'] or oldElement[key]['state'] != newElement[key]['state']:
                logger.info(f"Difference.\n oldEdge: {oldElement}\n newEdge: {newElement}")
                return False
        return True

    def compare_topologies(self, other_topology):
        """
        比较当前拓扑与另一个拓扑，返回是否相同。
        """
        # 多重有向图认为相同还是得看属性匹配，但从同构很难认为相同，但有点不一样又不一定是不同的拓扑
        return nx.is_isomorphic(
            self.graph,
            other_topology.graph,
            node_match=self.node_is_same,
            edge_match=self.edge_is_same
        )

    def display_topology(self):
        """
        输出拓扑节点和链路的详细信息。
        """

        # Define positions for nodes
        pos = nx.spring_layout(self.graph, k=0.17)

        # Create a larger figure with higher resolution
        plt.figure(figsize=(20, 15), dpi=100)

        # Draw the graph with advanced features
        nx.draw_networkx(self.graph, pos, with_labels=True, node_color='skyblue', node_size=1700, font_size=27,
                         font_color='black', edge_color='gray', linewidths=10, width=9, arrowsize=30)

        # Draw edge labels
        edge_labels = nx.get_edge_attributes(self.graph, 'weight')
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=edge_labels)

        # Display the plot
        plt.show()


def build_topology_graph(topology_graph: ONOSTopologyGraph):
    """
    访问 RestAPI，获取拓扑数据，从而构建拓扑图。
    :param topology_graph: 被构建的拓扑图.
    :return:
    """
    # 从 REST API 获取拓扑数据
    topology_data = ONOS_TopologyComponent.Topology()
    try:
        Utils.get_topology("ONOS", topology_data)
    except ConnectionError as e:
        logger.warning(f"Interesting! Get topology data find Error, ONOS may RuntimeError: {e}")

    # 将设备、链路和主机添加到拓扑图中
    topology_graph.add_devices(topology_data.devices)
    topology_graph.add_links(topology_data.links)
    topology_graph.add_hosts(topology_data.hosts)

    # 显示构建的拓扑信息
    # topology_graph.display_topology()
