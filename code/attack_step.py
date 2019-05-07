import numpy as np
import math

P_MISSING_ALERT = 0.1

class AttackStep:

    def __init__(self,
                node_id=None,
                node_name=None,
                node_type="OR",
                parents=None,
                q_list=None,
                children=None,
                alerts=None,
                pi=None,
                parents_pi=None,
                ):
        self.node_id = node_id
        self.node_name = node_name
        self.bel = np.array([0.5, 0.5])
        self.pi = None
        self.la = None
        self.q_list = None
        self.c_list = None
        self.alerts = [] 

        self.node_index = node_id
        self.node_type = node_type
        self.parents = parents
        self.children = children

        if len(alerts) > 0:
            w_total = 0
            for alert_unit in alerts:
                w_total += float(alert_unit[0])
                unit_dict = dict()
                for desp in alert_unit[1]:
                    unit_dict[desp] = dict()
                self.alerts.append([float(alert_unit[0]), unit_dict])
            assert(abs(w_total-1.0) < 0.0001)

        self.children_la = [] 
        if children is not None:
            for child in children:
                self.children_la.append(np.array([1, 1]))

        if parents is None:
            self.pi = np.array([1.0-float(pi), float(pi)])
        else:
            self.parents_pi = parents_pi 
            self.q_list = q_list 
            self.c_list = [1.0 - q for q in q_list]
            self.calPi()

        self.calLa()
        self.calBEL()


    def calBEL(self):
        bel = np.multiply(self.pi, self.la)
        self.bel = bel / bel.sum(0)


    def calLa(self):
        la = np.array([0.5, 0.5])
        for child_la in self.children_la:
            la = np.multiply(la, child_la)

        if len(self.alerts) > 0:
            total_confi = 0
            for alert_unit in self.alerts:
                max_confi = P_MISSING_ALERT 
                for desp in alert_unit[1]:
                    id_dict = alert_unit[1][desp]
                    if bool(id_dict):
                        cur = np.array([0.5, 0.5])
                        for confi in id_dict.itervalues():
                            cur = np.multiply(cur, np.array([1-confi, confi]))
                            cur = cur / cur.sum(0)
                        max_confi = max(max_confi, cur[1])
                total_confi += alert_unit[0] * max_confi
            la = np.multiply(la, np.array([1.0-total_confi, total_confi]))

        self.la = la / la.sum(0)


    def calPi(self):
        if self.parents is not None:
            pi_total = 1
            if self.node_type == "OR":
                for i in range(len(self.parents)):
                    pi_total *= (1.0 - self.c_list[i]*self.parents_pi[i])
                self.pi = np.array([pi_total, 1.0- pi_total])
            else:
                for i in range(len(self.parents)):
                    pi_total *= (1.0 - self.c_list[i]*(1.0-self.parents_pi[i]))
                self.pi = np.array([1.0 - pi_total, pi_total])


    def hasParents(self):
        return self.parents is not None


    def getParents(self):
        return self.parents


    def hasChildren(self):
        return self.children is not None


    def getChildren(self):
        return self.children


    def getBEL(self):
        return self.bel[1]


    def setLaChild(self, node_id, child_la):
        assert(node_id in self.children)
        i = self.children.index(node_id)
        self.children_la[i] = child_la 


    def setPiParent(self, node_id, parent_pi):
        assert(node_id in self.parents)
        i = self.parents.index(node_id)
        self.parents_pi[i] = parent_pi


    def getPiChild(self, node_id):
        assert(node_id in self.children)
        i = self.children.index(node_id)
        pi_child = np.divide(self.bel, self.children_la[i])
        pi_child = pi_child / pi_child.sum(0)
        return pi_child[1]


    def getLaParent(self, node_id):
        assert(node_id in self.parents)
        i = self.parents.index(node_id)
        if self.node_type == "OR":
            pi_i = self.pi[0] / (1.0-self.c_list[i]*self.parents_pi[i])
            la_parent_1 = self.la[0]*self.q_list[i]*pi_i + self.la[1]*(1.0-self.q_list[i]*pi_i)
            la_parent_0 = self.la[0]*pi_i + self.la[1]*(1.0-pi_i)
        else:
            pi_i = self.pi[1] / (1.0-self.c_list[i]*(1-self.parents_pi[i]))
            la_parent_1 = self.la[0]*(1.0-pi_i) + self.la[1]*pi_i
            la_parent_0 = self.la[0]*(1.0-self.q_list[i]*pi_i) + self.la[1]*self.q_list[i]*pi_i
        return np.array([la_parent_0, la_parent_1])


    def getAlertConfiInNode(self, alert):
        for alert_unit in self.alerts:
            if alert["desp"] in alert_unit[1]:
                if alert["_id"] in alert_unit[1][alert["desp"]]:
                    return alert_unit[1][alert["desp"]][alert["_id"]]
        return None


    def getMatchedAlerts(self):
        rst = []
        for alert_unit in self.alerts:
            for id_dict in alert_unit[1].itervalues():
                for alert_id in id_dict:
                    rst.append(alert_id)
        return rst 
        

    def updateAlert(self, alert):
        for alert_unit in self.alerts:
            if alert["desp"] in alert_unit[1]:
                alert_unit[1][alert["desp"]][alert["_id"]] = alert["confi"]


    def __str__(self):
        if len(self.alerts) == 0: 
            return  "    node: {}  name: {}  BEL: {}\n".format(self.node_id, self.node_name, self.bel[1])
        else:
            title = "    node: {}  name: {}  BEL: {}  alerts:".format(self.node_id, self.node_name, self.bel[1])
            matched_alerts = ""
            for alert_unit in self.alerts:
                for anomaly_desp in alert_unit[1]:
                    dest_id = None
                    max_confi = 0
                    count = 0
                    for alert_id, confi in alert_unit[1][anomaly_desp].iteritems():
                        count += 1
                        if confi > max_confi:
                            dest_id = alert_id
                            max_confi = confi
                    if dest_id is not None:
                        matched_alerts += '''
            desp: {}  alert_num: {}  example_alert_id: {}  confi: {}'''.format(anomaly_desp,
                                                                               count,
                                                                               alert_id,
                                                                               alert_unit[1][anomaly_desp][alert_id]
                                                                              )        
            if matched_alerts == "":
                return title + " no matched alerts\n"
            else:
                return title + matched_alerts + "\n" 
