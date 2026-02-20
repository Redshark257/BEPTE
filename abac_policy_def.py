import os
import numpy as np
import math
from itertools import product
import json

class abac_policy(object):

    def __init__(self):

        self.define_attributes()
        self.define_attribute_values()
        self.define_targets()
        self.define_policies()
        self.save_policies()
    

    def define_attributes(self):

        self.attributes = {
                            "subject": 
                                [
                                "role", 
                                "authentication", 
                                "emg",
                                "location",
                                "login-time"
                                ],
                            "resource": 
                                [
                                "data",
                                "encryption",
                                ],
                            "operation": 
                            [
                                "op"
                            ]
                        }


    def define_attribute_values(self):

        self.attr_vals = {"role": ["nurse", "doctor", "patient", "any"], 
        "authentication": ["biometric", "certificate", "token", "2fa", "password", "none", "any"],
        "emg": ["yes", "no", "any"],
        "location": ["hospital", "remote", "any"],
        "login-time": ["day", "evening", "night", "any"],
        "data": ["patient-file", "system"],
        "encryption": ["1", "0", "any"],
        "op": ["r", "w", "x", "any"]
        }
    
    def define_targets(self):

        self.targets = dict()
        for _key in self.attributes:
            self.targets[_key] = []
            for attr in self.attributes[_key]:
                attr_target = []
                for val in self.attr_vals[attr]:
                    attr_target.append((attr, val))
                self.targets[_key].append(attr_target)
        print(self.targets)


    def define_policies(self):
        self.abac_policy = ({"t.s": {"(attr, val)": {("role", "nurse"), ("authentication", "biometric")}, "cond-op": ["AND"]}, "t.r": {"(attr, val)":{("data", "patient-file"), ('encryption', "1")}, "cond-op": ["AND"]}, "t.o": {"(attr, val)":{("op", "r")}, "cond-op": []}}, {"decision": "allow"})

        self.policy_list = []

        target_combination = dict()
        for key in self.targets:
            target_combination[key] = set(product(*self.targets[key]))
        target_combination_list = [target_combination[key] for key in target_combination]
        self.policy_comb = list(product(*target_combination_list))
        for i in range(len(self.policy_comb)):
            policy = (
                    {"t.s": {"(attr, val)": list(self.policy_comb[i][0]), "cond-op": ["AND"]}, 
                    "t.r": {"(attr, val)":list(self.policy_comb[i][1]), "cond-op": ["AND"]}, 
                    "t.o": {"(attr, val)":list(self.policy_comb[i][1]), "cond-op": []}}, 
                    {"decision": "any"}
                    )
            self.policy_list.append(policy)
        
        #for item in self.policy_list:
        #    print(item)

    def save_policies(self):

        file = "abac_policies.json"
        path = os.getcwd()
        filepath = os.path.join(path, file)
        with open(file, "w") as fw:
            fw.write('[')
            for item in self.policy_list:
                json_str = json.dumps(item, ensure_ascii=False)
                fw.write(json_str + ',\n')
            fw.write(']')
        fw.close()


def main():
    abac = abac_policy()
main()
