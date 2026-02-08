import networkx as nx
import matplotlib.pyplot as plt
from loguru import logger

import Utils


class ODLTopologyGraph:
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

    def add_nodes_and_edges_from_json(self, json_data):
        topology = json_data["network-topology:network-topology"]["topology"][0]

        # Add nodes
        for node in topology["node"]:
            node_id = node["node-id"]
            self.graph.add_node(node_id, **node)

        # Add edges
        for link in topology["link"]:
            src_node = link["source"]["source-node"]
            # src_tp = link["source"]["source-tp"]
            dest_node = link["destination"]["dest-node"]
            # dest_tp = link["destination"]["dest-tp"]
            self.graph.add_edge(src_node, dest_node, **link)

    @staticmethod
    def node_is_same(oldElement, newElement):
        if oldElement == {} or newElement == {}:
            return True  # 不知道为什么会出现这种情况，拓扑图也没有问题，直接返回 True
        try:
            if oldElement["node-id"] == newElement["node-id"]:
                if oldElement != newElement:
                    return False
                else:
                    return True
            else:
                return True
        except KeyError as e:
            logger.error(f"KeyError: {e}")
            return True

    @staticmethod
    def edge_is_same(oldElement, newElement):
        try:
            key = list(oldElement.keys())
            if isinstance(key[0], int):  # networkx 的多重边数据结构
                for i in key:
                    if oldElement[i]["link-id"] == newElement[i]["link-id"]:
                        if (oldElement[i]["source"]["source-node"] == newElement[i]["source"]["source-node"] and  # 前者情况已经记录（源地址才能被修改，目的地址不好恶意修改），并且十分常见
                                oldElement != newElement):
                            return False
            else:  # 一般情况多重边结构不会出现此情况，因此下面的代码基本不会被执行，随意写的一些
                if oldElement["link-id"] == newElement["link-id"]:
                    if oldElement != newElement:
                        return False
            return True
        except KeyError as e:
            logger.error(f"KeyError: {e}")
            return True

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
        pos = nx.spring_layout(self.graph, seed=42)
        plt.figure(figsize=(20, 15), dpi=100)
        nx.draw_networkx(self.graph, pos, with_labels=True, node_color='skyblue', node_size=1700, font_size=27,
                         font_color='black', edge_color='gray', linewidths=10, width=9, arrowsize=30)
        edge_labels = nx.get_edge_attributes(self.graph, 'weight')
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=edge_labels)
        plt.tight_layout()
        plt.show()


def build_topology_graph(topology_graph: ODLTopologyGraph):
    """
    Access the RestAPI to get topology data and build the topology graph.
    :param topology_graph: The topology graph to be built.
    :return:
    """

    try:
        topology_data = Utils.get_topology('ODL').json()
    except ConnectionError as e:
        logger.warning(f"Interesting! Get topology data find Error, ODL may RuntimeError: {e}")
        raise e

    topology_graph.add_nodes_and_edges_from_json(topology_data)