import copy
import timeit
import numpy
from pprint import pprint
from attack_step import AttackStep

class AttackTemplate:

    def __init__(self,
                 attack_info=None,
                 correlator=None,
                 db=None,
                 ):
        self.attack_info = attack_info
        self.node_list = []
        # key: anomaly_desp value: dict(node_id, match_rule)
        self.alert_match_dict = dict()
        # key: alert_id value: node_id
        self.matched_alerts = dict()
        self.correlator = correlator
        self.db = db

        self.cor_time = [] 
        self.update_time = [] 
    
    def addNode(self,
                node_id=None,
                node_name=None,
                node_type="OR",
                parents=None,
                q_list=None,
                children=None,
                alerts=None,
                pi=None,
                ):
        parents_pi = None 
        if parents is not None:
            parents_pi = []
            for parent in parents:
                parents_pi.append(self.node_list[parent].getPiChild(node_id))

        for alert_unit in alerts:
            for desp in alert_unit[1]:
                if desp not in self.alert_match_dict:
                    self.alert_match_dict[desp] = {node_id: alert_unit[1][desp]}
                else:
                    self.alert_match_dict[desp][node_id] = alert_unit[1][desp]

        attack_step = AttackStep(node_id,
                                 node_name,
                                 node_type,
                                 parents,
                                 q_list,
                                 children,
                                 alerts,
                                 pi,
                                 parents_pi)
        self.node_list.append(attack_step)


    def findCorrelation(self, alert, node_id):
        start = timeit.default_timer() 
        rst = 0
        meta_alerts = self.db.meta_alert  
        node = self.node_list[node_id]

        # Correlate own alerts
        node_alerts = node.getMatchedAlerts()
        for node_alert_id in node_alerts:
            dest_alert = meta_alerts.find_one({"_id": node_alert_id})
            cor_rst = self.correlator.correlate(dest_alert, alert)
            rst = max(rst, cor_rst)

        # Correlate alerts of parents
        if node.hasParents():
            parents = node.getParents()
            for parent in parents:
                parent_node = self.node_list[parent]
                parent_node_alerts = parent_node.getMatchedAlerts()
                for parent_node_alert_id in parent_node_alerts:
                    dest_alert = meta_alerts.find_one({"_id": parent_node_alert_id})
                    cor_rst = self.correlator.correlate(dest_alert, alert)
                    if self.correlator.timeOrder(alert, dest_alert) < 0:
                        return -1
                    rst = max(rst, cor_rst)

        # Correlate alerts of children 
        if node.hasChildren():
            children = node.getChildren()
            for child in children:
                child_node = self.node_list[child]
                child_node_alerts = child_node.getMatchedAlerts()
                for child_node_alert_id in child_node_alerts:
                    dest_alert = meta_alerts.find_one({"_id": child_node_alert_id})
                    cor_rst = self.correlator.correlate(dest_alert, alert)
                    if self.correlator.timeOrder(alert, dest_alert) > 0:
                        return -1
                    rst = max(rst, cor_rst)

        self.cor_time.append(timeit.default_timer() - start)

        return rst

    
    def updateTreeFromChild(self, node_id, src_child_id, child_la):
        node = self.node_list[node_id]
        node.setLaChild(src_child_id, child_la)
        node.calLa()
        node.calBEL()
        for child_id in node.getChildren():
            if child_id != src_child_id:
                self.updateTreeFromParent(child_id, node_id, node.getPiChild(child_id))
        if node.hasParents():
            for parent_id in node.getParents():
                self.updateTreeFromChild(parent_id, node_id, node.getLaParent(parent_id))
   

    def updateTreeFromParent(self, node_id, src_parent_id, parent_pi):
        node = self.node_list[node_id]
        node.setPiParent(src_parent_id, parent_pi)
        node.calPi()
        node.calBEL()
        if node.hasChildren():
            for child_id in node.getChildren():
                self.updateTreeFromParent(child_id, node_id, node.getPiChild(child_id))
        for parent_id in node.getParents():
            if parent_id != src_parent_id:
                self.updateTreeFromChild(parent_id, node_id, node.getLaParent(parent_id))


    def updateTreeFromNode(self, alert, node_id):
        start = timeit.default_timer()
        self.matched_alerts[alert["_id"]] = node_id 
        node = self.node_list[node_id]
        node.updateAlert(alert)
        node.calLa()
        node.calBEL()
        if node.hasChildren():
            for child_id in node.getChildren():
                self.updateTreeFromParent(child_id, node_id, node.getPiChild(child_id))
        if node.hasParents():
            for parent_id in node.getParents():
                self.updateTreeFromChild(parent_id, node_id, node.getLaParent(parent_id))
        self.update_time.append(timeit.default_timer() - start)


    def matchAlert(self, alert): 
        candidates = [self]
        correlated_node = None 
        max_cor = 0
        potential_nodes = []
        if alert["desp"] in self.alert_match_dict:
            for node_id in self.alert_match_dict[alert["desp"]]:
                if self.checkMatchRule(alert, self.alert_match_dict[alert["desp"]][node_id]):
                    cor_rst = self.findCorrelation(alert, node_id)
                    if cor_rst > 0:
                        if cor_rst > max_cor:
                            correlated_node = node_id
                    elif cor_rst == 0:
                        potential_nodes.append(node_id)
        #print("correlated_node: " + str(correlated_node))
        #print("potential_nodes: " + str(potential_nodes))
        if correlated_node is not None:
            self.updateTreeFromNode(alert, correlated_node)
        else:
            for node_id in potential_nodes:
                candidate = self.copy()
                candidate.updateTreeFromNode(alert, node_id)
                candidates.append(candidate)
        return candidates 


    def checkMatchRule(self, alert, match_rule):
        if len(match_rule) == 0:
            return True

        for conjunction in match_rule:
            conjunction_val = True
            for literal in conjunction:
                index_str = literal[0]
                value = literal[1]
                index_list = index_str.split(".")
                cur = alert
                find_value = True
                for i in range(len(index_list)):
                    index = index_list[i]
                    if index not in cur:
                        find_val = False
                        break
                    else:
                        cur = cur[index]
                if find_value == False or cur != value:
                    conjunction_val = False
                    break
            if conjunction_val == True:
                return True
        return False 
         

    def updateAlert(self, alert):
        if alert["_id"] in self.matched_alerts:
            node_id = self.matched_alerts[alert["_id"]]
            if alert["confi"] != self.node_list[node_id].getAlertConfiInNode(alert):
                self.updateTreeFromNode(alert, node_id)


    def getAvgBEL(self):
        total_bel = 0
        for node in self.node_list:
            total_bel += node.getBEL()

        return total_bel / len(self.node_list)


    def getMaxLeafBEL(self):
        max_bel = 0
        for node in self.node_list:
            if not node.hasChildren():
                max_bel = max(node.getBEL(), max_bel)

        return max_bel 


    def getRankScore(self):
        return self.getMaxLeafBEL() + 0.0000001 * len(self.matched_alerts) 
        

    def getLastUpdateTime(self):
        meta_alerts = self.db.meta_alert  
        rst = None
        for alert_id in self.matched_alerts:
            alert = meta_alerts.find_one({"_id": alert_id})
            if rst is None:
                rst = alert["ts"][1]
            else:
                rst = max(rst, alert["ts"][1])
        return rst
        

    def isTemplate(self):
        return not self.matched_alerts
 

    def getNode(self, node_id):
        return self.node_list[node_id]


    def copy(self):
        rst = AttackTemplate(
            self.attack_info,
            self.correlator,
            self.db,
        ) 
        rst.node_list = copy.deepcopy(self.node_list)
        rst.alert_match_dict = copy.deepcopy(self.alert_match_dict)
        rst.matched_alerts = copy.deepcopy(self.matched_alerts)

        rst.cor_time = copy.deepcopy(self.cor_time)
        rst.update_time = copy.deepcopy(self.update_time)
 
        return rst


    def __str__(self):
        rst = "\nattack info: {\n"
        for key in self.attack_info:
            rst += "    {}: {}\n".format(key, self.attack_info[key])
        rst += "}}\nMax_Leaf_BEL: {}\nnode list: [\n".format(self.getMaxLeafBEL())
        for node in self.node_list:
            rst += str(node)
        rst += "]\n"
        if len(self.cor_time) > 0:
            cor_array = numpy.array([self.cor_time])
            rst += "cor_avg_time: {}\n".format(numpy.mean(cor_array, axis=1))
            rst += "cor_std: {}\n".format(numpy.std(cor_array, axis=1))
            rst += "cor_num: {}\n".format(len(self.cor_time))
        if len(self.update_time) > 0:
            update_array = numpy.array([self.update_time])
            rst += "update_avg_time: {}\n".format(numpy.mean(update_array, axis=1))
            rst += "update_std: {}\n".format(numpy.std(update_array, axis=1))
            rst += "update_num: {}\n".format(len(self.update_time)) 
        return rst
