import os
import numpy as np
import math
import networkx as nx
import matplotlib.pyplot as plt
from networkx.readwrite import json_graph
import json
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
import matplotlib.image as mpimg
## this script defines network topology for best effort policy enforcement


class nw_topology(object):

    def __init__(self):
        
        self.define_assets()
        self.define_security_functions()
        self.configure_topology()
        self.save_topology()

    
    def define_assets(self):

        # define cost
        pc_cost_mat = {"cost": 0, "latency": 0}
        server_cost_mat = {"cost": 0, "latency": 0}

        self.src_asset = [['PC', 'source', pc_cost_mat]]
        self.dst_asset = [['DB Server', 'destination', server_cost_mat]]


    
    def define_security_functions(self):
    
        # define cost matrix
        biometric_auth_cost_mat = {"cost": 2, "latency": 1}
        edr_cost_mat = {"cost": 1, "latency": 1}
        l3_fw_cost_mat = {"cost": 0.5, "latency": 0.5}
        l4_fw_cost_mat = {"cost": 0.8, "latency": 0.7}
        #ids_cost_mat = {"cost": 0.8, "latency": 0.7}
        self.security_functions = [
                                    ['biometric-authenticator', 'auth', biometric_auth_cost_mat], 
                                    ['EDR', 'm_encrypt', edr_cost_mat], 
                                    ['L3-firewall', 'firewall', l3_fw_cost_mat], 
                                    ['L4-firewall', 'firewall', l4_fw_cost_mat],
                                    #["IDS", "detection-mech", ids_cost_mat]
                                    ]
    

    def configure_topology(self):

        self.nw_graph = nx.DiGraph()
        # add source and destination nodes
        for _node in self.src_asset:
            self.nw_graph.add_node(_node[0], type=_node[1], cost = _node[2])
        for _node in self.dst_asset:
            self.nw_graph.add_node(_node[0], type=_node[1], cost = _node[2])

        # add security functions

        for _node in self.security_functions:
            self.nw_graph.add_node(_node[0], type=_node[1], cost = _node[2])


        ## make path 
        # path 1 --> PC -> Biometric Auth -> L3 Firewall -> DB Server
        # path 2 --> PC -> L4 Firewall -> Cert Auth Server -> DB Server

        # path 1
        # define edge cost
        edge_cost_mat_path1 = [{"cost": 0, "latency": 0.5}, {"cost": 0, "latency": 0.4}, {"cost": 0, "latency": 0.2}]
        self.nw_graph.add_edge('PC', 'biometric-authenticator', cost = edge_cost_mat_path1[0])
        self.nw_graph.add_edge('biometric-authenticator', 'L3-firewall', cost = edge_cost_mat_path1[1])
        self.nw_graph.add_edge('L3-firewall', 'DB Server', cost = edge_cost_mat_path1[2])
        
        # path 2
        edge_cost_mat_path2 = [{"cost": 0, "latency": 0.3}, {"cost": 0, "latency": 0.3}, {"cost": 0, "latency": 0.2}]
        self.nw_graph.add_edge('PC', 'L4-firewall', cost = edge_cost_mat_path2[0])
        self.nw_graph.add_edge('L4-firewall', 'EDR', cost = edge_cost_mat_path2[1])
        self.nw_graph.add_edge('EDR', 'DB Server', cost = edge_cost_mat_path2[2])

        # path 3
        edge_cost_mat_path3 = [{"cost": 0, "latency": 0.3}]
        #self.nw_graph.add_edge('L3-firewall', 'IDS', cost = edge_cost_mat_path3[0])
        #self.nw_graph.add_edge('IDS', 'EDR', cost = edge_cost_mat_path3[0])
        self.nw_graph.add_edge('L3-firewall', 'EDR', cost = edge_cost_mat_path3[0])

        
        # Draw the graph
        node_colors = []
        for node in self.nw_graph.nodes():
            if self.nw_graph.nodes[node].get('type') == 'source':
                node_colors.append('lightblue')  # Source: orange
            elif self.nw_graph.nodes[node].get('type') == 'destination':
                node_colors.append('lightblue')     # Destination: red
            else:
                node_colors.append('lightpink')  # Intermediate nodes: lightblue
        pos = nx.spring_layout(self.nw_graph)
        nx.draw(self.nw_graph, pos, with_labels=True, node_color= node_colors, node_size=2000, font_size=10)
        edge_labels = {e: '' for e in self.nw_graph.edges()}
        nx.draw_networkx_edge_labels(self.nw_graph, pos, edge_labels=edge_labels)
        plt.title('Network Topology')
        plt.show()


    def save_topology(self):
        # Convert the graph to node-link data format
        data = json_graph.node_link_data(self.nw_graph)
        filename = 'network_graph.json'
        path = os.getcwd()
        file = os.path.join(path, filename)
        with open(file, 'w') as fw:
            json.dump(data, fw, indent=2)
        fw.close()
        # G_loaded = json_graph.node_link_graph(data)



def main():

    nw = nw_topology()
main()
