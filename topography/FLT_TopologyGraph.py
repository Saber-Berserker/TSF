import networkx as nx
import matplotlib.pyplot as plt
from loguru import logger

from data_structure import FLT_TopologyComponent
import Utils


class FLTTopologyGraph:
    def __init__(self):
        # Create a multi-directed graph to allow multiple edges representing different port connections
        self.graph = nx.MultiDiGraph()

    def remove_link(self, src, dest, src_port=None, dest_port=None):
        """
        Remove the link between specified ports (can specify port number). If no port is specified, remove all links.
        """
        edges = list(self.graph.get_edge_data(src, dest).items())
        for key, edge_data in edges:
            if (src_port is None or edge_data.get("src_port") == src_port) and \
                    (dest_port is None or edge_data.get("dest_port") == dest_port):
                self.graph.remove_edge(src, dest, key)

    def update_node(self, node_id, **attributes):
        """
        Update node attributes.
        """
        if node_id in self.graph:
            self.graph.nodes[node_id].update(attributes)

    def update_link(self, src, dest, src_port, dest_port, **attributes):
        """
        Update the attributes of the link between specified ports.
        """
        edges = self.graph.get_edge_data(src, dest)
        for key, edge_data in edges.items():
            if edge_data.get("src_port") == src_port and edge_data.get("dest_port") == dest_port:
                edge_data.update(attributes)
                break

    def add_switches(self, switches):
        """Add switches to the graph from JSON switch data."""
        for switch in switches:
            switch_id = switch.switchDPID
            attributes = {
                "type": "SWITCH",
                "inetAddress": switch.inetAddress,
                "connectedSince": switch.connectedSince,
                "openFlowVersion": switch.openFlowVersion,
                "switchDPID": switch.switchDPID
            }
            self.graph.add_node(switch_id, **attributes)

    def add_hosts(self, hosts):
        """Add hosts and their connections to the graph from JSON host data."""
        for host in hosts:
            host_id = host.mac[0]
            ip_addresses = host.ipv4 + host.ipv6    # 两列表相加结果为新的一个列表
            attachment_points = host.attachmentPoint
            # lastSeen = host.lastSeen
            if len(ip_addresses) < 2:   # 没有ipv4的主机直接不管，floodlight的bug会出现很多主机
                continue

            self.graph.add_node(host_id, mac=host.mac, ip_addresses=ip_addresses, type="HOST")

            for attachment in attachment_points:
                switch_id = attachment["switch"]
                port = attachment["port"]
                self.graph.add_edge(host_id, switch_id, src_port="HOST", dst_port=port)

    def add_links(self, links):
        """Add edges to the graph from JSON link data."""
        for link in links:
            src_switch = link.src_switch
            src_port = link.src_port
            dst_switch = link.dst_switch
            dst_port = link.dst_port
            link_type = link.link_type
            direction = link.direction
            latency = link.latency

            self.graph.add_edge(src_switch, dst_switch, src_port=src_port, dst_port=dst_port, type=link_type,
                                direction=direction, latency=latency)

    @staticmethod
    def node_is_same(oldElement, newElement):
        try:
            # if oldElement['type'] == newElement['type']:
            #     if oldElement['type'] == 'SWITCH':
            #         if oldElement["switchDPID"] == newElement["switchDPID"]:
            #             if (oldElement["openFlowVersion"] != newElement["openFlowVersion"]
            #                     or oldElement["inetAddress"] != newElement["inetAddress"]):
            #                 logger.info(f"Difference.\n oldSwitch: {oldElement}\n newSwitch: {newElement}")
            #                 return False
            #             else:
            #                 return True
            #         else:
            #             return True
            #
            #     elif oldElement['type'] == 'HOST':
            #         if oldElement["mac"] == newElement["mac"]:
            #             # oldElement['lastSeen'] = newElement['lastSeen']
            #             if oldElement != newElement:
            #                 logger.info(f"Difference.\n oldHost: {oldElement}\n newHost: {newElement}")
            #                 return False
            #             else:
            #                 return True
            #         return True
            # else:
            #     return True
            return True     # Floodlight 的交换机属性少，还基本和连接时间有关（重启 Mininet 就不同了，影响性能），暂时不考虑交换机属性的变化，只考虑是否同构
        except KeyError as e:
            logger.error(f"KeyError: {e}")
            return True

    @staticmethod
    def edge_is_same(oldElement, newElement):
        # try:
        #     # 现在只对只连接一对交换机和非主机的链路进行比较
        #     if oldElement[0]['src_port'] == 'HOST' or newElement[0]['dst_port'] == 'HOST':
        #         return True
        #     if ((oldElement[0]['direction'] == 'unidirectional' or newElement[0]['direction'] == 'unidirectional')
        #             and (oldElement[0]['src_port'] != newElement[0]['src_port'] or oldElement[0]['dst_port'] != newElement[0]['dst_port'])):  # 链路伪造攻击，太常见影响性能，不考虑方向
        #         return True
        #     if oldElement[0]['type'] != newElement[0]['type'] or oldElement[0]['direction'] != newElement[0]['direction']:
        #         logger.info(f"Difference.\n oldEdge: {oldElement}\n newEdge: {newElement}")
        #         return False
        #
        #     return True
        # except KeyError as e:
        #     logger.error(f"KeyError: {e}")
        #     return True
        return True     # 只算同构得了，其他属性都有人发现 Bug，floodlight 属性基本就是链路伪造

    def compare_topologies(self, other_topology):
        """
        Compare the current topology with another topology and return whether they are the same.
        """
        return nx.is_isomorphic(
            self.graph,
            other_topology.graph,
            node_match=self.node_is_same,
            edge_match=self.edge_is_same
        )

    def display_topology(self):
        """
        Display detailed information about the topology nodes and links.
        """
        fixed_positions = {
            '00:00:00:00:00:00:00:01': (-10000, 0),
            '00:00:00:00:00:00:00:08': (10000, 0),

            '00:00:00:00:00:00:00:02': (-20000, -10000),
            '00:00:00:00:00:00:00:03': (-20000, 10000),


            '00:00:00:00:00:00:00:04': (-30000, -15000),
            '00:00:00:00:00:00:00:05': (-30000, -5000),

            '00:00:00:00:00:00:00:06': (-30000, 15000),
            '00:00:00:00:00:00:00:07': (-30000, 5000),

            '00:00:00:00:00:00:00:09': (20000, 10000),
            '00:00:00:00:00:00:00:10': (20000, -10000),

            '00:00:00:00:00:00:00:11': (30000, 15000)
        }

        fixed_nodes = fixed_positions.keys()
        pos = nx.spring_layout(self.graph, pos=fixed_positions, fixed=fixed_nodes, seed=42)
        plt.figure(figsize=(20, 15), dpi=100)
        nx.draw_networkx(self.graph, pos, with_labels=True, node_color='skyblue', node_size=1700, font_size=27,
                         font_color='black', edge_color='gray', linewidths=10, width=9, arrowsize=30)
        edge_labels = nx.get_edge_attributes(self.graph, 'weight')
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=edge_labels)
        plt.tight_layout()
        plt.show()


def build_topology_graph(topology_graph: FLTTopologyGraph):
    """
    Access the RestAPI to get topology data and build the topology graph.
    :param topology_graph: The topology graph to be built.
    :return:
    """
    topology_data = FLT_TopologyComponent.Topology()
    try:
        Utils.get_topology('Floodlight', topology_data)
    except ConnectionError as e:
        logger.warning(f"Interesting! Get topology data find Error, FLT may RuntimeError: {e}")

    topology_graph.add_switches(topology_data.switches)
    topology_graph.add_links(topology_data.links)
    topology_graph.add_hosts(topology_data.hosts)