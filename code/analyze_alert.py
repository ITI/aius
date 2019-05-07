import datetime
import numpy as np
import time
import math
from pymongo import MongoClient
from pprint import pprint
from correlate_alert import AlertCorrelator
from generate_template import TemplateGenerator

BEL_TH = 0
TIME_TH = 60*60*24*10
CANDIDATE_LIMIT = 3 


class AlertAnalyzer():
    def __init__(self):
        self.client = MongoClient()
        self.client.drop_database("meta_alert_database")
        self.alert_db = self.client.meta_alert_database 
        self.alert_correlator = AlertCorrelator()
        self.template_generator = TemplateGenerator(self.alert_correlator, self.alert_db)
        self.template_generator.generate()
        self.candidate_dict = self.template_generator.getTemplates()
        

    def analyze(self, meta_alert):
        #print("")
        #pprint(meta_alert)
        #print("")
        update_time = meta_alert["ts"][1]
        meta_alerts = self.alert_db.meta_alert
        replace_rst = meta_alerts.replace_one({"_id": meta_alert["_id"]}, meta_alert, upsert=True)
        if replace_rst.matched_count > 0:
            for candidates in self.candidate_dict.itervalues():
                for candidate in candidates:
                    candidate.updateAlert(meta_alert)
        else:
            for attack_name, candidates in self.candidate_dict.iteritems():
                new_candidates = []
                for candidate in candidates:
                    if candidate.isTemplate() or update_time - candidate.getLastUpdateTime() < TIME_TH:
                        new_candidates += candidate.matchAlert(meta_alert)
                if len(new_candidates) > CANDIDATE_LIMIT:
                    new_candidates.sort(key=lambda x: x.getRankScore())
                    index = 0
                    while index < len(new_candidates) and len(new_candidates) > CANDIDATE_LIMIT:
                        if new_candidates[index].isTemplate():
                            index += 1
                        else:
                            new_candidates.remove(new_candidates[index])
                self.candidate_dict[attack_name] = new_candidates


    def print_alerts(self):
        meta_alerts = self.alert_db.meta_alert
        print("Meta-Alert Number: " + str(meta_alerts.count()))
 
        #for meta_alert in meta_alerts.find():
        #    print("")
        #    pprint(meta_alert)


    def print_candidates(self, top_k=100):
        print_list = []
        for candidates in self.candidate_dict.itervalues():
            candidates.sort(key=lambda x: x.getRankScore(), reverse=True)
            if not candidates[0].isTemplate() and candidates[0].getMaxLeafBEL() > BEL_TH:
                print_list.append(candidates[0])

        print_list.sort(key=lambda x: x.getRankScore(), reverse=True)
        top_k = min(top_k, len(print_list))
        for i in range(top_k):
            print(print_list[i])
