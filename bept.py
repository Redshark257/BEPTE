## this is the script for best effort translation and policy enforcement

import os
import numpy as np
import math
import networkx as nx
import statistics
#import matplotlib.pyplot as plt

class bept(object):
    
    def __init__(self):

        self.define_abac_policies()

        ## policy combination
        #self.policy_finegrain(self, p1, p2)

        # policy translation
        self.define_security_measures()
        self.policy_sm_relation()
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
            print(key)
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
            print(p_fine[0][key])
        
        p_fine[1] = {"decision": "allow"}
        return p_fine


    def define_security_measures(self):

        self.security_measures = ["authentication", "authorization", "encryption", "isolation", "logging", "detection"]

    def policy_sm_relation(self):

        # relation is applied between a security measure and the attribute on which the security measure is applicable
        self.rel_p_sm = {"authentication": ["authentication"], "authorization": ["role", "data", "op"], "encryption": ["encryption"], "isolation": ["data"], "logging": ["log-data"], "detection": ["apply-detection"], "emergency": ["emg"]}


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


    def define_transformers(self):

        self.transformers = [
                            "m_biom", 
                            "m_cert", 
                            "m_2fa", 
                            "m_pswd", 
                            "m_token", 
                            "m_role", 
                            "m_IP", 
                            "m_port", 
                            "m_loc", 
                            "m_time",
                            "m_encrypt"
                            ]


    def define_capabilities(self):

        # capabilities are defined between transformers and security measures with a value "degree" 
        # between 0 and 1, 1 being highest capability

        self.capability_vals = dict()
        self.capability_vals["m_biom"] = [0.9, 0, 0, 0, 0, 0, 0]
        self.capability_vals["m_cert"] = [0.7, 0, 0, 0, 0, 0, 0]
        self.capability_vals["m_2fa"] = [1, 0, 0, 0, 0, 0, 0]
        self.capability_vals["m_pswd"] = [0.5, 0, 0, 0, 0, 0, 0]
        self.capability_vals["m_token"] = [0.5, 0, 0, 0, 0, 0, 0]
        self.capability_vals["m_role"] = [0, 1, 0, 0, 0, 0, 0]
        self.capability_vals["m_IP"] = [0.3, 0.5, 0, 0.5, 0.5, 0.5, 0]
        self.capability_vals["m_port"] = [0, 0.5, 0, 0.5, 0.5, 0.5, 0]
        self.capability_vals["m_loc"] = [0, 0.5, 0, 0, 0, 0, 0]
        self.capability_vals["m_time"] = [0, 0.3, 0, 0, 0, 0, 0]
        self.capability_vals["m_encrypt"] = [0, 0, 1, 0, 0, 0, 0]

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

        self.assoc_sf_tr["biometric-authenticator"] = ["m_biom", "m_role", "m_loc", "m_time"]
        self.assoc_sf_tr["certificate-authenticator"] = ["m_cert", "m_role", "m_loc", "m_time"]
        self.assoc_sf_tr["password-authenticator"] = ["m_pswd", "m_role"]
        self.assoc_sf_tr["2fa-authenticator"] = ["m_2fa", "m_role", "m_time"]
        self.assoc_sf_tr["token-authenticator"] = ["m_token", "m_role", "m_time"]
        self.assoc_sf_tr["L3-firewall"] = ["m_IP"]
        self.assoc_sf_tr["L4-firewall"] = ["m_IP", "m_port"]
        self.assoc_sf_tr["EDR"] = ["m_encrypt"]


    def sf_conditions(self):

        self.condition_metric = ["available", "cost", "latency"]

        self.sf_condition_metric = dict()
        
        for _sf in self.security_functions:
            self.sf_condition_metric[_sf] = {_con: 0 for _con in self.condition_metric}
        
        self.sf_condition_metric["biometric-authenticator"] = {"available": 1, "cost": 0.4, "latency": 0.6}
        self.sf_condition_metric["certificate-authenticator"] = {"available": 1, "cost": 0.3, "latency": 0.5}
        self.sf_condition_metric["password-authenticator"] = {"available": 1, "cost": 0.2, "latency": 0.7}
        self.sf_condition_metric["2fa-authenticator"] = {"available": 1, "cost": 0.8, "latency": 0.7}
        self.sf_condition_metric["token-authenticator"] = {"available": 1, "cost": 0.8, "latency": 0.7}
        self.sf_condition_metric["L3-firewall"] = {"available": 1, "cost": 0.2, "latency": 0.5}
        self.sf_condition_metric["L4-firewall"] = {"available": 1, "cost": 0.3, "latency": 0.6}
        self.sf_condition_metric["EDR"] = {"available": 1, "cost": 0.3, "latency": 0.6}



    def affecting_conditions(self):

        self.affecting_conditions = ["access-needs", "security-needs", "trust"]
    

    def calculate_constraints(self, affec_cons, latency_constraint, cost_constraint):

        #latency_constraint = latency_constraint*( 1  - 0.5 * ( (1) / (1 + (math.exp(-affec_cons['trust']))) ) )
        latency_constraint = latency_constraint*( 1  + 1.0 * ( (1) / (1 + (math.exp(-affec_cons['security-needs']))) ) )
        #latency_constraint = latency_constraint*( 1  - 0.6 * ( (1) / (1 + (math.exp(-affec_cons['access-needs']))) ) )

        #cost_constraint = cost_constraint*( 1 - 0.4 * ( (1) / (1 + (math.exp(-affec_cons['trust']))) ) )
        cost_constraint = cost_constraint*( 1 + 0.8 * ( (1) / (1 + (math.exp(-affec_cons['security-needs']))) ) )
        #cost_constraint = cost_constraint*( 1 - 0.5 * ( (1) / (1 + (math.exp(-affec_cons['access-needs']))) ) )

        return (latency_constraint, cost_constraint)


    def assoc_conditions(self):

        self.assoc_conditions_tr = dict()
        for _tr in self.transformers:
            #self.assoc_conditions_tr[_tr] = {_con: 100 for _con in self.condition_metric}
            self.assoc_conditions_tr[_tr] = {_con: 0 for _con in self.condition_metric}
        
        #print(self.assoc_conditions_tr)
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

        print(self.assoc_conditions_tr)



    def policy_translation(self, p):

        sm = self.find_sm(p)
        #print(sm)
        translation_map = dict()
        for _sm in sm:
            translation_map[_sm] = set()
            for _tr in self.transformers:
                if self.capabilities[_tr][_sm] > 0:
                    translation_map[_sm].add(_tr)
                else:
                    continue
        return translation_map

    
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


    def check_and_replace_opt(self, t_map, _tr, _sm, current_cost, current_latency, cost_constraint, latency_constraint):
        if self.assoc_conditions_tr[_tr]["available"]==1:
            if t_map == [] and self.capabilities[_tr][_sm]>0:
                t_map.append(_tr)
                current_cost = current_cost + self.assoc_conditions_tr[_tr]["cost"]
                current_latency = current_latency + self.assoc_conditions_tr[_tr]["latency"]
            for tr in t_map:
                if self.capabilities[_tr][_sm] > self.capabilities[tr][_sm]:
                    if current_cost + self.assoc_conditions_tr[_tr]["cost"] <= cost_constraint and current_latency + self.assoc_conditions_tr[_tr]["latency"] <= latency_constraint:
                        t_map.remove(tr)
                        t_map.append(_tr)
                        current_cost = current_cost + self.assoc_conditions_tr[_tr]["cost"]
                        current_latency = current_latency + self.assoc_conditions_tr[_tr]["latency"]
                        return (t_map,current_cost, current_latency)
                    else:
                        continue
                else:
                    continue
        else:
            pass
        return (t_map,current_cost, current_latency)



    def best_effort_translation(self, p, affec_cons):

        cost_constraint = 1
        latency_constraint = 1
        (latency_constraint, cost_constraint) = self.calculate_constraints(affec_cons,  latency_constraint, cost_constraint)
        print((latency_constraint, cost_constraint))
        current_cost = 0
        current_latency = 0
        sm = self.find_sm(p)
        print(sm)
        best_effort_translation_map = dict()
        for _sm in sm:
            best_effort_translation_map[_sm] = list()
            for _tr in self.transformers:
                #best_effort_translation_map[_sm] = self.check_and_replace(best_effort_translation_map[_sm], _tr, _sm)
                (best_effort_translation_map[_sm], current_cost, current_latency) = self.check_and_replace_opt(best_effort_translation_map[_sm], _tr, _sm, current_cost, current_latency, cost_constraint, latency_constraint)
        return (best_effort_translation_map, current_cost, current_latency)


    def get_security_functions(self, p, affec_cons):

        (be_tmap_opt, cost, latency) = self.best_effort_translation(p, affec_cons)
        print((be_tmap_opt, cost, latency))

        sf_set = set()
        for _sm in be_tmap_opt:
            tr_list = be_tmap_opt[_sm]
            for _tr in tr_list:
                sf_list = [_sf for _sf in self.security_functions if _tr in self.assoc_sf_tr[_sf]]
                for _sf in sf_list:
                    sf_set.add(_sf)        
        return sf_set



def main():

    best_effort_pt = bept()
    # p = ({"t.s": [("role", "nurse"), ("authentication", "biometric")], "t.r": [("data", "patient-file")], "t.o": [("op", "r")]}, {"decision": "allow"})
    p = ({"t.s": {"(attr, val)": [("role", "nurse"), ("authentication", "biometric")], "cond-op": ["AND"]}, "t.r": {"(attr, val)":[("data", "patient-file"), ('encryption', "1")], "cond-op": ["AND"]}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
    sm = best_effort_pt.find_sm(p)
    #print(sm)

    #T_map = best_effort_pt.policy_translation(p)
    #print(T_map)
    #be_t_map = best_effort_pt.best_effort_translation(p)
    #print(be_t_map)
    affec_cons = {"access-needs": 100, "security-needs": 50, "trust": 100}
    #be_t_map_opt = best_effort_pt.best_effort_translation(p, affec_cons)
    #print(be_t_map_opt)
    sf_set = best_effort_pt.get_security_functions(p, affec_cons)
    print(sf_set)

    ## policy combination

    #p1 = ({"t.s": {"(attr, val)": [("role", "nurse"), ("authentication", "biometric")], "cond-op": ["AND"]}, "t.r": {"(attr, val)":[("data", "patient-file"), ('encryption', "1")], "cond-op": ["AND"]}, "t.o": {"(attr, val)":[("op", "r")], "cond-op": []}}, {"decision": "allow"})
    #p2 = ({"t.s": {"(attr, val)": [("emg", 1)], "cond-op": [""]}, "t.r": {"(attr, val)":[("data", "patient-file")], "cond-op": ["AND"]}, "t.o": {"(attr, val)":[("op", "r"), ("op", "w")], "cond-op": ["OR"]}}, {"decision": "allow"})
    #p_fine = best_effort_pt.policy_finegrain(p1, p2)
    #print(p_fine)

main()
