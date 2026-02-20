## this is the script for best effort translation and policy enforcement

import os
import numpy as np
import math
import networkx as nx
import matplotlib.pyplot as plt
import json
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
import matplotlib.image as mpimg
import statistics
import time

class bepte(object):
    
    def __init__(self):

        self.define_abac_policies()
        self.import_network()
        self.get_all_sf_in_path()

        # constraints
        self.import_constraints()


        ## policy combination
        #self.policy_finegrain(self, p1, p2)

        # policy translation
        self.define_security_measures()
        self.policy_sm_relation()
        self.attr_tr_relation()
        self.define_transformers()
        self.define_capabilities()
        
        # security functions
        self.security_functions()
        self.assoc()
        self.sf_conditions()
        self.assoc_conditions()

        #self.define_conditions()
        #self.best_effort_translation()



    def define_abac_policies(self):

        self.pol_statement = "Only Nurses with biometric authentication are allowed to view patient data"

        # policy format --> p = (t, d) where t is target and d is decision
        # target t = dictionary {t.s, t.r, t.o} and decision d is a dictionary d = {decision: }
        # target t: each dictionary key holds a list of tuples (attribute, value)
        self.abac_policy = ({"t.s": {"(attr, val)": {("role", "nurse"), ("authentication", "biometric")}, "cond-op": ["AND"]}, "t.r": {"(attr, val)":{("data", "patient-file"), ('encryption', "1")}, "cond-op": ["AND"]}, "t.o": {"(attr, val)":{("op", "r")}, "cond-op": []}}, {"decision": "allow"})


    # policy combinations

    def policy_extension(self, p1, p2):

        # lets define two policies
        self.abac_policy = ({"t.s": {"(attr, val)": [("role", "nurse"), ("authentication", "biometric")], "cond-op": ["AND"]}, "t.r": {"(attr, val)":[("data", "patient-file"), ('encryption', "1")], "cond-op": ["AND"]}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
        self.p2 = ({"t.s": {"(attr, val)": [("emg", 1)], "cond-op": [""]}, "t.r": {"(attr, val)":[("data", "patient-file")], "cond-op": ["AND"]}, "t.o": {"(attr, val)":[("op", "w")], "cond-op": []}}, {"decision": "allow"})

        # define extended policy as follows:
        # p_ext = p1 (override) {(p1.t.s AND p2.t.s), (p1.t.r or p2.t.r), (p1.t.o or p2.t.o), (d1 or d2)}

        self.p_ext = [
                    ({"t.s": [("role", "nurse"), ("authentication", "biometric")], "t.r": [("data", "patient-file"), ('encryption', "1")], "t.o": [("op", "r")]}, {"decision": "allow"}),
                    ({"t.s": [("role", "nurse"), ("authentication", "biometric"), ("emg", 1)], "t.r": [("data", "patient-file"), ('encryption', "1")], "t.o": [("op", "r"), ("op", "w")]}, {"decision": "allow"})
                    ]

    # policy fine-graining
    def policy_finegrain(self, p1, p2):

        # lets define two policies
        #self.p1 = ({"t.s": {"(attr, val)": [("role", "nurse"), ("authentication", "biometric")], "cond-op": ["AND"]}, "t.r": {"(attr, val)":[("data", "patient-file"), ('encryption', "1")], "cond-op": ["AND"]}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
        #self.p2 = ({"t.s": {"(attr, val)": [("emg", 1)], "cond-op": [""]}, "t.r": {"(attr, val)":[("data", "patient-file")], "cond-op": ["AND"]}, "t.o": {"(attr, val)":[("op", "r"), ("op", "w")], "cond-op": ["OR"]}}, {"decision": "allow"})

        # define extended policy as follows:
        # p_ext = p1 (override) {(p1.t.s AND p2.t.s), (p1.t.r AND p2.t.r), (p1.t.o AND p2.t.o), (d1 AND d2)}

        #self.p_fine = [
        #                ({"t.s": {"(attr, val)": [("role", "nurse"), ("authentication", "biometric"), ("emg", 1)], "cond-op": ["AND", "AND"]}, "t.r": {"(attr, val)":[("data", "patient-file"), ('encryption', "1")], "cond-op": ["AND"]}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
        #            ]

        #self.p_fine = []
        p_fine = [None, None]
        p_fine[0] = dict()
        for key in p1[0]:
            p1_cons = p1[0][key]["(attr, val)"]
            p1_op = p1[0][key]["cond-op"]
            p2_cons = p2[0][key]["(attr, val)"]
            p2_op = p2[0][key]["cond-op"]

            # check for same attribute
            p_fine_cons = set()
            p_fine_op = list()
            #print(p1_cons)
            #print(key)
            for i, (attr, val) in enumerate(p1_cons):
                p2_cons_attr_set = [x[0] for x in p2_cons]
                if attr not in p2_cons_attr_set:
                    if p_fine_cons=={}:
                        p_fine_cons.add((attr, val))
                    else:
                        #print(i)
                        #print((attr, val))
                        p_fine_cons.add((attr, val))
                        p_fine_op.append(p1_op[i-1])
                elif attr in p2_cons_attr_set:
                    val2 = [y for (x,y) in p2_cons if x == attr]
                    if val==val2:
                        if p_fine_cons=={}:
                            p_fine_cons.add((attr, val))
                        else:
                            p_fine_cons.add((attr, val))
                            #p_fine_op.append(p1_op[i-1])
            
            # add the remaining conditions
            for i, (attr, val) in enumerate(p2_cons):
                p_fine_attr_set = [x[0] for x in p_fine_cons]
                if attr not in p_fine_attr_set:
                    if p_fine_cons =={}:
                        p_fine_cons.add((attr, val))
                    else:
                        p_fine_cons.add((attr, val))
                        #p_fine_op.append(p2_op[i-1])
            p_fine[0][key] = {"(attr, val)": p_fine_cons, "cond-op": p_fine_op}
            #print(p_fine[0][key])
        
        p_fine[1] = {"decision": "allow"}
        return p_fine


    def import_network(self):

        nw_file = 'network_graph.json'
        path = os.getcwd()
        file = os.path.join(path, nw_file)
        with open(nw_file, 'r') as fr:
            self.nw_topo = json.load(fr)
        fr.close()

        self.nw_graph = nx.DiGraph()
        for node in self.nw_topo["nodes"]:
            self.nw_graph.add_node(node["id"], **node)
        
        for link in self.nw_topo["links"]:
            self.nw_graph.add_edge(link['source'], link['target'], **link) 
        #print(self.nw_topo)


    def get_all_sf_in_path(self):

        source_node = [n['id'] for n in self.nw_topo["nodes"] if n['type']=='source'][0]
        destination_node = [n['id'] for n in self.nw_topo["nodes"] if n['type']=='destination'][0]
        self.paths = list(nx.all_simple_paths(self.nw_graph, source = source_node, target = destination_node))
        
        #for _path in self.paths:
        #    print(_path)
        node_set = set(_node for _path in self.paths for _node in _path)
        #print(node_set)
        self.all_path_sf = node_set - {source_node, destination_node}
        #print(self.path_sf)
    
    def get_sf_in_path(self, path):

        source_node = [n['id'] for n in self.nw_topo["nodes"] if n['type']=='source'][0]
        destination_node = [n['id'] for n in self.nw_topo["nodes"] if n['type']=='destination'][0]

        path_nodes = set(_node for _node in path)
        path_sf = path_nodes - {source_node, destination_node}
        return path_sf


    def import_constraints(self):

        pass

    def define_security_measures(self):

        self.security_measures = ["authentication", "authorization", "encryption", "isolation", "logging", "detection", "emergency"]


    def policy_sm_relation(self):

        # relation is applied between a security measure and the attribute on which the security measure is applicable
        self.rel_p_sm = {"authentication": ["authentication"], "authorization": ["device", "role", "data", "op"], "encryption": ["encryption"], "isolation": ["device", "data"], "logging": ["log-data"], "detection": ["apply-detection"], "emergency": ["emg"]}


    def attr_tr_relation(self):
        self.rel_attr_tr = {
                            "m_biom": "authentication", 
                            "m_cert": "authentication", 
                            "m_2fa": "authentication",
                            "m_pswd": "authentication", 
                            "m_token": "authentication", 
                            "m_role": "role",
                            "m_device": "device", 
                            "m_IP": "ip-address", 
                            "m_port": "port", 
                            "m_loc": "location", 
                            "m_time": "time",
                            "m_encrypt": "encryption",
                            "m_malware": "apply-detection",
                            "m_logger": "logging"
                            }

    def find_sm(self, p):
        # this function finds related security measure for the policy
        sm = list()
        for key in p[0]:
            condition = p[0][key]["(attr, val)"]
            for (attr, val) in condition:
                for _k in self.rel_p_sm:
                    if attr in self.rel_p_sm[_k] and val!=0:            # check for False case
                        if _k not in sm:
                            sm.append(_k)
                    else:
                        continue
        return sm


    def get_attributes(self, p):
        attr_list = []
        for key in p[0]:
            condition = p[0][key]["(attr, val)"]
            for (attr, val) in condition:
                attr_list.append(attr)
        return attr_list


    def define_transformers(self):

        self.transformers = [
                            "m_biom", 
                            "m_cert", 
                            "m_2fa", 
                            "m_pswd", 
                            "m_token", 
                            "m_role",
                            "m_device", 
                            "m_IP", 
                            "m_port", 
                            "m_loc", 
                            "m_time",
                            "m_encrypt",
                            "m_malware",
                            "m_logger"
                            ]


    def define_capabilities(self):

        # capabilities are defined between transformers and security measures with a value "degree" 
        # between 0 and 1, 1 being highest capability

        self.capability_vals = dict()
        self.capability_vals["m_biom"] = [0.9, 0, 0, 0, 0, 0, 0]
        self.capability_vals["m_cert"] = [0.7, 0, 0, 0, 0, 0, 0]
        self.capability_vals["m_2fa"] = [1, 0, 0, 0, 0, 0, 0]
        self.capability_vals["m_pswd"] = [0.5, 0, 0, 0, 0, 0, 0]
        self.capability_vals["m_token"] = [0.6, 0, 0, 0, 0, 0, 0]
        self.capability_vals["m_role"] = [0, 1, 0, 0, 0, 0, 0]
        self.capability_vals["m_device"] = [0.5, 1, 0.2, 0.6, 0.35, 0, 0]
        self.capability_vals["m_IP"] = [0.3, 0.5, 0, 0.5, 0.5, 0.3, 0]
        self.capability_vals["m_port"] = [0, 0.5, 0, 0.5, 0.5, 0.3, 0]
        self.capability_vals["m_loc"] = [0, 0.5, 0, 0, 0, 0, 0]
        self.capability_vals["m_time"] = [0, 0.3, 0, 0, 0, 0, 0]
        self.capability_vals["m_encrypt"] = [0, 0, 1, 0, 0, 0, 0]
        self.capability_vals["m_malware"] = [0, 0, 0, 0, 0, 1, 0]
        self.capability_vals["m_logger"] = [0, 0, 0, 0, 1, 0, 0]

        self.capabilities = dict()

        for _tr in self.transformers:
            self.capabilities[_tr] = dict()
            for i, _sm in enumerate(self.security_measures):
                self.capabilities[_tr][_sm] = self.capability_vals[_tr][i]

        #print(self.capabilities)



    def security_functions(self):

        self.security_functions = [
                                    "biometric-authenticator", 
                                    "certificate-authenticator", 
                                    "password-authenticator", 
                                    "2fa-authenticator", 
                                    "token-authenticator", 
                                    "L3-firewall", 
                                    "IDS", "IPS", 
                                    "L4-firewall", 
                                    "application-firewall" 
                                    "logger", 
                                    "EDR"
                                    ]


    def assoc(self):

        self.assoc_sf_tr = dict()

        for key in self.security_functions:
            self.assoc_sf_tr[key] = []

        self.assoc_sf_tr["biometric-authenticator"] = ["m_biom", "m_role", "m_loc", "m_time", "m_device"]
        self.assoc_sf_tr["certificate-authenticator"] = ["m_cert", "m_role", "m_loc", "m_time", "m_device"]
        self.assoc_sf_tr["password-authenticator"] = ["m_pswd", "m_role"]
        self.assoc_sf_tr["2fa-authenticator"] = ["m_2fa", "m_role", "m_time", "m_device"]
        self.assoc_sf_tr["token-authenticator"] = ["m_token", "m_role", "m_time"]
        self.assoc_sf_tr["L3-firewall"] = ["m_IP", "m_device"]
        self.assoc_sf_tr["L4-firewall"] = ["m_IP", "m_port", "m_device"]
        self.assoc_sf_tr["EDR"] = ["m_encrypt"]
        self.assoc_sf_tr["IDS"] = ["m_IP", "m_port", "m_malware"]
        self.assoc_sf_tr["logger"] = ["m_logger"]


    def sf_conditions(self):

        self.condition_metric = ["available", "cost", "latency"]

        self.sf_condition_metric = dict()
        
        for _sf in self.security_functions:
            self.sf_condition_metric[_sf] = {_con: 0 for _con in self.condition_metric}
        
        #self.sf_condition_metric["biometric-authenticator"] = {"available": 1, "cost": 0.4, "latency": 0.6}
        #self.sf_condition_metric["certificate-authenticator"] = {"available": 1, "cost": 0.3, "latency": 0.5}
        #self.sf_condition_metric["password-authenticator"] = {"available": 1, "cost": 0.2, "latency": 0.7}
        #self.sf_condition_metric["2fa-authenticator"] = {"available": 1, "cost": 0.8, "latency": 0.7}
        #self.sf_condition_metric["token-authenticator"] = {"available": 1, "cost": 0.8, "latency": 0.7}
        #self.sf_condition_metric["L3-firewall"] = {"available": 1, "cost": 0.2, "latency": 0.5}
        #self.sf_condition_metric["L4-firewall"] = {"available": 1, "cost": 0.3, "latency": 0.6}
        #self.sf_condition_metric["EDR"] = {"available": 1, "cost": 0.3, "latency": 0.6}

        for _sf in self.security_functions:
            if _sf in self.all_path_sf:
                self.sf_condition_metric[_sf]["available"] = 1
                self.sf_condition_metric[_sf]["cost"] = [_node["cost"]["cost"] for _node in self.nw_topo["nodes"] if _node["id"] == _sf][0]
                self.sf_condition_metric[_sf]["latency"] = [_node["cost"]["latency"] for _node in self.nw_topo["nodes"] if _node["id"] == _sf][0]
            else:
                self.sf_condition_metric[_sf]["available"] = 0
        #print(self.sf_condition_metric)


    def affecting_conditions(self):

        self.affecting_conditions = ["access-needs", "security-needs", "trust"]
    

    def calculate_constraints(self, affec_cons, cost_constraint, latency_constraint):

        cost_constraint = cost_constraint*( 1 - 0.4 * ( (1) / (1 + (math.exp((100-10*affec_cons['trust'])))) ) )
        cost_constraint = cost_constraint*( 1 + 0.8 * ( (1) / (1 + (math.exp((100-10*affec_cons['security-needs'])))) ) )
        cost_constraint = cost_constraint*( 1 - 0.5 * ( (1) / (1 + (math.exp((100-10*affec_cons['access-needs'])))) ) )

        latency_constraint = latency_constraint*( 1  - 0.5 * ( (1) / (1 + (math.exp((100-10*affec_cons['trust'])))) ) )
        latency_constraint = latency_constraint*( 1  + 1.0 * ( (1) / (1 + (math.exp((100-10*affec_cons['security-needs'])))) ) )
        latency_constraint = latency_constraint*( 1  - 0.6 * ( (1) / (1 + (math.exp((100-10*affec_cons['access-needs'])))) ) )


        print((cost_constraint, latency_constraint))
        return (cost_constraint, latency_constraint)


    def assoc_conditions(self):

        self.assoc_conditions_tr = dict()
        for _tr in self.transformers:
            self.assoc_conditions_tr[_tr] = {_con: 0 for _con in self.condition_metric}
        
        flag = {_tr: 0 for _tr in self.transformers}
        for _tr in self.transformers:
            for _sf in self.security_functions:
                if _tr in self.assoc_sf_tr[_sf]:
                    if flag[_tr] == 0:
                        self.assoc_conditions_tr[_tr]["cost"] = self.sf_condition_metric[_sf]["cost"]
                        self.assoc_conditions_tr[_tr]["latency"] = self.sf_condition_metric[_sf]["latency"]
                        self.assoc_conditions_tr[_tr]["available"] = self.sf_condition_metric[_sf]["available"]
                        flag[_tr] = 1
                    elif flag[_tr] == 1:
                        #self.assoc_conditions_tr[_tr] = {_con: min(self.assoc_conditions_tr[_tr][_con], self.sf_condition_metric[_sf][_con]) for _con in self.condition_metric}
                        self.assoc_conditions_tr[_tr]["cost"] = statistics.mean([self.assoc_conditions_tr[_tr]["cost"], self.sf_condition_metric[_sf]["cost"]])
                        self.assoc_conditions_tr[_tr]["latency"] = statistics.mean([self.assoc_conditions_tr[_tr]["latency"], self.sf_condition_metric[_sf]["latency"]])
                        self.assoc_conditions_tr[_tr]["available"] = max(self.assoc_conditions_tr[_tr]["available"], self.sf_condition_metric[_sf]["available"])
        
        #print(self.assoc_conditions_tr)

    
    def check_and_replace(self, t_map, _tr, _sm):
        if t_map == [] and self.capabilities[_tr][_sm]>0:
            t_map.append(_tr)
        for tr in t_map:
            if self.capabilities[_tr][_sm] > self.capabilities[tr][_sm]:
                t_map.remove(tr)
                t_map.append(_tr)
                return t_map
            else:
                continue
        return t_map


    def check_and_replace_opt(self, attr, t_map, _tr, _sm, current_cost, current_latency, cost_constraint, latency_constraint):
        if self.assoc_conditions_tr[_tr]["available"]==1:
            if t_map == [] and self.capabilities[_tr][_sm]>0:
                if current_cost + self.assoc_conditions_tr[_tr]["cost"] < cost_constraint and current_latency + self.assoc_conditions_tr[_tr]["latency"] < latency_constraint:
                    t_map.append(_tr)
                    current_cost = current_cost + self.assoc_conditions_tr[_tr]["cost"]
                    current_latency = current_latency + self.assoc_conditions_tr[_tr]["latency"]
                #print(current_cost)
                #print(current_latency)
            elif t_map!= []:
                for tr in t_map:
                    if self.capabilities[_tr][_sm] > self.capabilities[tr][_sm]:
                        if current_cost + self.assoc_conditions_tr[_tr]["cost"] - self.assoc_conditions_tr[tr]["cost"] <= cost_constraint and current_latency + self.assoc_conditions_tr[_tr]["latency"] - self.assoc_conditions_tr[tr]["latency"]<= latency_constraint:
                            t_map.remove(tr)
                            t_map.append(_tr)
                            #print(current_cost)
                            #print(current_latency)
                            current_cost = current_cost + self.assoc_conditions_tr[_tr]["cost"]
                            current_latency = current_latency + self.assoc_conditions_tr[_tr]["latency"]
                            return (t_map,current_cost, current_latency)
                        else:
                            continue
                    elif self.capabilities[_tr][_sm] == self.capabilities[tr][_sm]:
                        if self.rel_attr_tr[_tr] in attr and self.capabilities[tr] not in attr:
                            t_map.remove(tr)
                            t_map.append(_tr)
                        else:
                            continue
                    else:
                        continue
        else:
            pass
        return (t_map, current_cost, current_latency)



    def best_effort_translation(self, p, affec_cons, constraints):

        cost_constraint = constraints[0]
        latency_constraint = constraints[1]
        #print((cost_constraint, latency_constraint))
        current_cost = 0
        current_latency = 0
        sm = self.find_sm(p)
        #print(f"sm: {sm}")
        attr = self.get_attributes(p)
        print(attr)
        best_effort_translation_map = dict()
        for _sm in sm:
            best_effort_translation_map[_sm] = list()
            sorted_tr_list = sorted(self.transformers, key=lambda x: self.capabilities[x][_sm], reverse = True)
            #print(sorted_tr_list)
            for _tr in sorted_tr_list:
                (best_effort_translation_map[_sm], current_cost, current_latency) = self.check_and_replace_opt(attr, best_effort_translation_map[_sm], _tr, _sm, current_cost, current_latency, cost_constraint, latency_constraint)
        return (best_effort_translation_map, current_cost, current_latency)


    def get_security_functions(self, p, affec_cons, constraints):

        (be_tmap_opt, cost, latency) = self.best_effort_translation(p, affec_cons, constraints)
        print((be_tmap_opt, cost, latency))

        sf_set = set()
        for _sm in be_tmap_opt:
            tr_list = be_tmap_opt[_sm]
            for _tr in tr_list:
                sf_list = [_sf for _sf in self.security_functions if _tr in self.assoc_sf_tr[_sf]]
                for _sf in sf_list:
                    sf_set.add(_sf)        
        return sf_set


    def calculate_capability(self, sf_set, tmap, cost, latency):
        total_cap = 0
        total_cost = 0
        total_latency = 0
        #print(cost)
        #print(latency)
        cap = dict()
        cap_sf = dict()
        satisfaction = {_sm: False for _sm in tmap}
        for _sf in sf_set:
            cap_sf[_sf] = 0
            tr_list = self.assoc_sf_tr[_sf]
            for _tr in tr_list:
                cap[_tr] = 0
                count_sm = 0
                for _sm in tmap:
                    if _tr in tmap[_sm]:
                        if total_cost + self.sf_condition_metric[_sf]["cost"] <= cost and total_latency + self.sf_condition_metric[_sf]["latency"] <= latency:
                            #print(_tr)
                            count_sm+=1
                            cap[_tr]+=self.capabilities[_tr][_sm]
                            total_cost+=self.sf_condition_metric[_sf]["cost"]
                            total_latency+=self.sf_condition_metric[_sf]["cost"]
                            #print(_sf)
                            satisfaction[_sm] = True
                        else:
                            continue
                    else:
                        continue
                cap[_tr] = cap[_tr] / (max(count_sm, 1))
            cap_sf[_sf] = max(cap[_tr] for _tr in tr_list)
            if False in satisfaction.values():
                continue
            else:
                break
        print(cap_sf)
        total_cap = sum(cap_sf[_sf] for _sf in cap_sf if cap_sf[_sf]!=0) / len(cap_sf)
        return total_cap


    def calculate_capability(self, sf_set, tmap, cost, latency):
        total_cap = 0
        total_cost = 0
        total_latency = 0
        satisfaction_score = {_sm: 0 for _sm in tmap}
        satisfaction_dict = {_sm: False for _sm in tmap}

        for _sf in sf_set:
            tr_list = self.assoc_sf_tr[_sf]
            for _tr in tr_list:
                for _sm in tmap:
                    if _tr in tmap[_sm] and total_cost + self.sf_condition_metric[_sf]["cost"] <= cost and total_latency + self.sf_condition_metric[_sf]["latency"] <= latency:
                        satisfaction_dict[_sm] = True
                        satisfaction_score[_sm] = max(satisfaction_score[_sm], self.capabilities[_tr][_sm])
                    else:
                        continue
        total_cap = sum(satisfaction_score.values()) / len(satisfaction_score.keys())
        print(satisfaction_score)
        print(total_cap)
        return total_cap




    def calculate_link_cost(self, path):
        total_cost = 0
        total_latency = 0
        edge_lookup = {(link['source'], link['target']): link["cost"] for link in self.nw_topo["links"]}
        for i in range(len(path)-1):
            edge = (path[i], path[i+1])
            if edge in edge_lookup:
                total_cost += edge_lookup[edge]['cost']
                total_latency += edge_lookup[edge]['latency']
            else:
                print(f'No link from {edge[0]} to {edge[1]}')
                return None
        return total_cost, total_latency


    def get_enforce_location_on_path(self, path, selected_tr, constraints):
        enforcement_location = {_node: False for _node in path}
        tr_enforced_flag = {_tr: False for _tr in selected_tr}
        path_sf = self.get_sf_in_path(path)
        current_cost = 0
        current_latency = 0
        for _node in path:
            if _node not in path_sf:
                enforcement_location[_node] = "na"
                continue
            for _tr in selected_tr:
                if _tr in self.assoc_sf_tr[_node]:
                    if tr_enforced_flag[_tr]==False:
                        enforcement_location[_node] = True
                        tr_enforced_flag[_tr] = True
                        current_cost = current_cost + self.sf_condition_metric[_node]["cost"]
                        current_latency = current_latency + self.sf_condition_metric[_node]["latency"]
                    elif tr_enforced_flag[_tr]==True:
                        if current_cost + self.sf_condition_metric[_node]["cost"] < constraints[0] and current_latency + self.sf_condition_metric[_node]["latency"] < constraints[1]:
                            enforcement_location[_node] = True
                            current_cost = current_cost + self.sf_condition_metric[_node]["cost"]
                            current_latency = current_latency + self.sf_condition_metric[_node]["latency"]
                        else:
                            enforcement_location[_node] = False
                else:
                    continue
            
        return enforcement_location


    def select_security_path(self, p, affec_cons):

        link_cost_constraint = 100
        link_latency_constraint = 100
        sf_cost_constraint = 100
        sf_latency_constraint = 100
        (new_sf_cost_constraint, new_sf_latency_constraint) = self.calculate_constraints(affec_cons, sf_cost_constraint, sf_latency_constraint)
        
        (be_tmap_opt, m_cost, m_latency) = self.best_effort_translation(p, affec_cons, constraints = (new_sf_cost_constraint, new_sf_latency_constraint))
        sf_set = self.get_security_functions(p, affec_cons, constraints = (new_sf_cost_constraint, new_sf_latency_constraint))
        #print(sf_set)
        max_capability = 0
        selected_path = set()
        for _path in self.paths:
            #print(_path)
            path_sf = self.get_sf_in_path(_path)
            #print(path_sf)
            if not sf_set.isdisjoint(path_sf):
                used_sf = path_sf & sf_set
                #print(used_sf)
                capability = self.calculate_capability(used_sf, be_tmap_opt, new_sf_cost_constraint, new_sf_latency_constraint)
                link_cost, link_latency = self.calculate_link_cost(_path)
                #path_cost, path_latency = self.calculate_path_cost(cost)
                #print(capability)
                #print((link_cost, link_latency))
                if capability >= max_capability and link_cost < link_cost_constraint and link_latency < link_latency_constraint:
                    max_capability = capability
                    selected_path = _path
                else:
                    continue
        
        #total_cost_constraint = link_cost_constraint + link_latency_constraint
        #total_latency_constraint = link_latency_constraint + sf_latency_constraint
        enforce_location = dict()
        selected_tr = list(be_tmap_opt[_k][0] for _k in be_tmap_opt if be_tmap_opt[_k]!=[])
        #print(selected_tr)

        enforce_location = self.get_enforce_location_on_path(selected_path, selected_tr, [new_sf_cost_constraint, new_sf_latency_constraint])
        return (selected_path, enforce_location, max_capability)


    def display_enforcement_path(self, enforcement_path, enforce_location):

        activation_dict = enforce_location

        # Prepare node attributes
        node_colors = []
        for node in self.nw_graph.nodes():
            act_value = activation_dict.get(node, False)
            # Set base color (change as needed)
            base_color = 'lightpink'
            highlight_color = '#FF8DA1'  # dark color
            if self.nw_graph.nodes[node].get('type') == 'source':
                base_color = 'lightblue'
                highlight_color = '#0a3264'  # darker blue
            elif self.nw_graph.nodes[node].get('type') == 'destination':
                base_color = 'lightblue'
                highlight_color = '#0a3264'  # darker blue

            if act_value is True:
                node_colors.append(highlight_color)
            else:
                node_colors.append(base_color)

        #pos = nx.spring_layout(self.nw_graph)
        pos = {
                'PC': (0, 0),
                'biometric-authenticator': (1, 1),
                'L3-firewall': (2, 0.5),
                #'IDS': (3, 0),
                'EDR': (3, -0.5),
                'L4-firewall': (1, -0.5),
                'DB Server': (4, 0)
            }
        # Draw nodes and edges
        nx.draw_networkx_nodes(self.nw_graph, pos, node_color=node_colors, node_size=2000)
        edges_all = list(self.nw_graph.edges())
        input_path = enforcement_path
        highlight_edges = list(zip(input_path[:-1], input_path[1:]))
        nx.draw_networkx_edges(self.nw_graph, pos, edgelist=edges_all, width=1, edge_color='gray')
        nx.draw_networkx_edges(self.nw_graph, pos, edgelist=highlight_edges, width=1, edge_color='red',
                            arrows=True, arrowstyle='->', arrowsize=24)

        # Draw node labels individually, setting font_weight per node
        for node in self.nw_graph.nodes():
            act_value = activation_dict.get(node, False)
            font_weight = 'bold' if act_value is True else 'normal'
            nx.draw_networkx_labels(self.nw_graph, pos,
                                labels={node: node},
                                font_size=10,
                                font_color='black',
                                font_weight=font_weight)

        # Edge labels (optional)
        edge_labels = {e: '' for e in self.nw_graph.edges()}
        nx.draw_networkx_edge_labels(self.nw_graph, pos, edge_labels=edge_labels)

        plt.title('MED-NW')
        plt.axis('off')
        plt.show()

def main():

    best_effort_pte = bepte()
    #p = ({"t.s": {"(attr, val)": [("role", "nurse"), ("authentication", "biometric"), ("apply-detection", "IDS")], "cond-op": ["AND"]}, "t.r": {"(attr, val)":[("data", "patient-file"), ('encryption', "1")], "cond-op": ["AND"]}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
    #p1 = ({"t.s": {"(attr, val)": [("device", "officePC")], "cond-op": []}, "t.r": {"(attr, val)":[("data", "patient-file")], "cond-op": []}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
    #p2 = ({"t.s": {"(attr, val)": [("role", "nurse")], "cond-op": []}, "t.r": {"(attr, val)":[("data", "patient-file")], "cond-op": ["AND"]}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
    #p3 = ({"t.s": {"(attr, val)": [("role", "nurse"), ("authentication", "biometric")], "cond-op": ["AND"]}, "t.r": {"(attr, val)":[("data", "patient-file")], "cond-op": []}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
    #p4 = ({"t.s": {"(attr, val)": [("role", "nurse"), ("authentication", "biometric")], "cond-op": ["AND"]}, "t.r": {"(attr, val)":[("data", "patient-file"), ('encryption', "1")], "cond-op": []}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})

    p1 = ({"t.s": {"(attr, val)": [("role", "nurse")], "cond-op": [""]}, "t.r": {"(attr, val)":[("data", "patient-file")], "cond-op": []}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
    p2 = ({"t.s": {"(attr, val)": [("role", "nurse"), ("authentication", "biometric")], "cond-op": ["AND"]}, "t.r": {"(attr, val)":[("data", "patient-file")], "cond-op": []}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
    p3 = ({"t.s": {"(attr, val)": [("role", "nurse"), ("authentication", "biometric")], "cond-op": ["AND"]}, "t.r": {"(attr, val)":[("data", "patient-file"), ('encryption', "1")], "cond-op": []}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
    p4 = ({"t.s": {"(attr, val)": [("role", "nurse"), ("authentication", "biometric")], "cond-op": ["AND"]}, "t.r": {"(attr, val)":[("data", "patient-file"), ('encryption', "1"), ('log-data', "1")], "cond-op": ["AND", "AND"]}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
    p5 = ({"t.s": {"(attr, val)": [("role", "nurse"), ("authentication", "biometric"), ("apply-detection", "IDS")], "cond-op": ["AND"]}, "t.r": {"(attr, val)":[("data", "patient-file"), ('encryption', "1"), ('log-data', "1")], "cond-op": ["AND", "AND"]}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
    

    affec_cons = {"access-needs": 0, "security-needs": 10, "trust": 0}
    
    start_time = time.time()
    (enforcement_path, enforcement_locations, max_capability) = best_effort_pte.select_security_path(p5, affec_cons)
    end_time = time.time()
    print(enforcement_path)
    print(enforcement_locations)
    print(max_capability)
    run_time = end_time - start_time
    print(run_time)

    #best_effort_pte.display_enforcement_path(enforcement_path, enforcement_locations)

    #print(best_effort_pte.capabilities["m_biom"])
main()
