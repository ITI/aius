import numpy as np
import math


class AlertCorrelator():
    
    cor_th = 0.5

    # CPT for Time Difference 
    cor_CPT1 = np.array([[0.3, 0.3, 0.3, 0.1], [0.1, 0.2, 0.2, 0.5]])
    # CPT for IP Similarity 
    cor_CPT2 = np.array([[0.7, 0.15, 0.1, 0.05], [0.1, 0.3, 0.3, 0.3]])
    # CPT for Same Protocol 
    cor_CPT3 = np.array([[0.8, 0.2], [0.4, 0.6]])

    # Dictionary for Anomaly Description Index
    anomaly_index = {
        'PACKET_IAT': 0,
        'PACKET_BYTES': 1,
        'NEW_ORIG': 2,
        'NEW_RESP': 3,
        'NEW_PROTOCOL': 4,
        'NEW_SERVICE': 5,
        'PACKET_AB_TOO_MANY': 6,
        'PACKET_AB_TOO_FEW': 7,
        'PACKET_BA_TOO_MANY': 8,
        'PACKET_BA_TOO_FEW': 9,
        'MEAN_BYTES_AB_TOO_LARGE': 10,
        'MEAN_BYTES_AB_TOO_SMALL': 11,
        'MEAN_BYTES_BA_TOO_LARGE': 12,
        'MEAN_BYTES_BA_TOO_SMALL': 13,
        'OPERATION_TOO_LATE': 14,
        'OPERATION_TOO_EARLY': 15,
        'OPERATION_MISSING': 16,
        'INVALID_FUNCTION_CODE': 17,
        'RESPONSE_FROM_ORIG': 18,
        'REQUEST_FROM_RESP': 19,
        'NEW_OPERATION': 20,
        'BINARY_FAULT': 21,
        'ANALOG_TOO_LARGE': 22,
        'ANALOG_TOO_SMALL': 23,
    }

    def __init__(self,
                time_accuracy=10,
                ):
        self.time_accuracy = time_accuracy
        self.cor_pi = [] 
        anomaly_num = len(self.anomaly_index)
        for i in range(anomaly_num):
            row = []
            for j in range(anomaly_num):
                row.append(np.array([0.2, 0.8]))
            self.cor_pi.append(row) 

    
    def timeDifference(self, alert1, alert2):
        if (alert1['ts'][0] - alert2['ts'][1]) * (alert1['ts'][1] - alert2['ts'][0]) <= 0:
            return np.array([1, 0, 0, 0])
        else:
            timediff = min(abs(alert1['ts'][0] - alert2['ts'][1]), abs(alert1['ts'][1] - alert2['ts'][0]))
            if timediff <= 60:
                return np.array([1, 0, 0, 0])
            elif timediff <= 60*60:
                return np.array([0, 1, 0, 0])
            elif timediff <= 60*60*24:
                return np.array([0, 0, 1, 0])
            else:
                return np.array([0, 0, 0, 1])


    def timeOrder(self, alert1, alert2):
        diff = alert1['ts'][0] - alert2['ts'][0]
        if abs(diff) <= self.time_accuracy:
            return 0
        elif diff > 0:
            return 1
        else:
            return -1 


    def ipSimilarity(self, ip1, ip2):
        ip1 = ip1.split('.')
        ip2 = ip2.split('.')
        assert(len(ip1) == 4)
        assert(len(ip2) == 4)
        similarity = 0
        for i in range(4):
            if ip1[i] != ip2[i]:
                break
            similarity += 1
        return similarity


    def ipPairSimilarity(self, alert1, alert2): 
        if alert1['anomaly_type'] == 'measurement':
            ip_pair1 = [alert1['index'].split(';')[0]]
        else:
            ip_pair1 = alert1['index'].split(';')[0:2]

        if alert2['anomaly_type'] == 'measurement':
            ip_pair2 = [alert2['index'].split(';')[0]]
        else:
            ip_pair2 = alert2['index'].split(';')[0:2]

        max_similarity = 0
        for ip1 in ip_pair1:
            if ip1 == "-":
                continue
            for ip2 in ip_pair2:
                if ip2 == "-":
                    continue
                max_similarity = max(max_similarity, self.ipSimilarity(ip1, ip2))

        if max_similarity == 4:
            return np.array([1, 0, 0, 0])
        elif max_similarity == 3:
            return np.array([0, 1, 0, 0])
        elif max_similarity == 2:
            return np.array([0, 0, 1, 0])
        else:
            return np.array([0, 0, 0, 1])


    def sameProtocol(self, alert1, alert2): 
        if alert1['anomaly_type'] == 'packet':
            tmp = alert1['index'].split(';')[3].strip('[]').split(',')
            protocol1 = [proto.strip('\' ') for proto in tmp] 
        elif alert1['anomaly_type'] == 'flow':
            protocol1 = [alert1['index'].split(';')[3]]
        elif alert1['anomaly_type'] == 'operation':
            protocol1 = [alert1['index'].split(';')[2]]
        else:
            protocol1 = [alert1['index'].split(';')[1]]

        if alert2['anomaly_type'] == 'packet':
            tmp = alert2['index'].split(';')[3].strip('[]').split(',')
            protocol2 = [proto.strip('\' ') for proto in tmp] 
        elif alert2['anomaly_type'] == 'flow':
            protocol2 = [alert2['index'].split(';')[3]]
        elif alert2['anomaly_type'] == 'operation':
            protocol2 = [alert2['index'].split(';')[2]]
        else:
            protocol2 = [alert2['index'].split(';')[1]]

        for p1 in protocol1:
            for p2 in protocol2:
                if p1 != '' and p1 == p2:
                    return np.array([1, 0])

        return np.array([0, 1])


    def correlate(self, alert1, alert2):
        # Get Prior Probability
        index1 = self.anomaly_index[alert1['desp']]
        index2 = self.anomaly_index[alert2['desp']]
        prior = self.cor_pi[index1][index2] 

        # Time Difference 
        lambda1 = np.dot(self.cor_CPT1, self.timeDifference(alert1, alert2))
        lambda_total = lambda1
        #print(self.timeDifference(alert1, alert2))
        # IP Similarity 
        lambda2 = np.dot(self.cor_CPT2, self.ipPairSimilarity(alert1, alert2))
        lambda_total = np.multiply(lambda_total, lambda2)
        #print(self.ipPairSimilarity(alert1, alert2))
        # Same Protocol 
        lambda3 = np.dot(self.cor_CPT3, self.sameProtocol(alert1, alert2))
        lambda_total = np.multiply(lambda_total, lambda3)
        #print(self.sameProtocol(alert1, alert2))


        believe = np.multiply(prior, lambda_total)
        believe = believe / believe.sum(0)

        #pprint(meta_alert)
        #print(believe[1])
        #print("")

        if believe[0] >= self.cor_th:
            return believe[0] 
        else:
            return -1
