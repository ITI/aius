from packet import Packet 
from flow import Flow
from anomaly import PacketAnomaly
from den_stream import DenStream1D 
from inc_mean_std import IncMeanSTD, ExpMeanSTD
import datetime
import numpy as np 
import math

TIME_NORM = 60.0 * 10 
COUNT_NORM = 100.0
COUNT_EACH_NORM = 100.0
CONFI_TH = 0.9
PERIOD = 60*10 

def sigmoid(x):
    return 2 * (1 / (1 + math.exp(-x)) - 0.5)


def generate_flow(start, end, orig, resp, protocol, service, service_stats, flow_queue):
    tcp_flag_most = -1
    tcp_flag_max = 0
    for tcp_flag in service_stats.tcp_flag_count:
        if service_stats.tcp_flag_count[tcp_flag] > tcp_flag_max:
            tcp_flag_most = tcp_flag
            tcp_flag_max = service_stats.tcp_flag_count[tcp_flag]

    flow = Flow(
                start,
                end,
                orig,
                resp,
                protocol,
                service,
                tcp_flag_most,
                service_stats.bytes_flow_ab.getTotal(),
                service_stats.bytes_flow_ba.getTotal(), 
                service_stats.bytes_flow_ab.getMean(),
                service_stats.bytes_flow_ab.getSTD(),
                service_stats.bytes_flow_ba.getMean(),
                service_stats.bytes_flow_ba.getSTD(),
                service_stats.iat_flow_ab.getMean(),
                service_stats.iat_flow_ab.getSTD(),
                service_stats.iat_flow_ba.getMean(),
                service_stats.iat_flow_ba.getSTD()
                )
    flow_queue.put_nowait(flow)


def generate_anomaly(ts,
                     desp,
                     confi,
                     index,
                     anomaly_queue,
                     packet=None,
                     current=None,
                     normal_mean=None,
                     normal_std=None):
    if confi >= CONFI_TH:
        anomaly = PacketAnomaly(ts,
                                desp,
                                confi,
                                index,
                                packet,
                                current,
                                normal_mean,
                                normal_std)
        anomaly_queue.put_nowait(anomaly)


class IPPairStats():
    def __init__(self):
        self.protocol_dict = dict()
        self.total = 0


class ProtocolStats(): 
    def __init__(self):
        self.service_dict = dict()
        self.total = 0


class ServiceStats():
    def __init__(self, index, anomaly_queue):
        self.index = index
        self.anomaly_queue = anomaly_queue

        self.total_ab = 0
        self.total_ba = 0

        self.tcp_flag_count = dict()

        self.last_seen_ab = None
        self.iat_ab = DenStream1D(0.5) 
        #self.iat_ab = ExpMeanSTD(COUNT_EACH_NORM, 0.02) 
        self.iat_flow_ab = IncMeanSTD(COUNT_EACH_NORM) 

        self.last_seen_ba = None
        self.iat_ba = DenStream1D(0.5)
        #self.iat_ba = ExpMeanSTD(COUNT_EACH_NORM, 0.02) 
        self.iat_flow_ba = IncMeanSTD(COUNT_EACH_NORM) 

        self.bytes_ab = DenStream1D(1)
        #self.bytes_ab = ExpMeanSTD(COUNT_EACH_NORM, 0.02) 
        self.bytes_flow_ab = IncMeanSTD(COUNT_EACH_NORM) 

        self.bytes_ba = DenStream1D(1) 
        #self.bytes_ba = ExpMeanSTD(COUNT_EACH_NORM, 0.02) 
        self.bytes_flow_ba = IncMeanSTD(COUNT_EACH_NORM) 


    def clearFlow(self):
        self.tcp_flag_count = dict()
        self.iat_flow_ab = IncMeanSTD(COUNT_EACH_NORM) 
        self.iat_flow_ba = IncMeanSTD(COUNT_EACH_NORM) 
        self.bytes_flow_ab = IncMeanSTD(COUNT_EACH_NORM) 
        self.bytes_flow_ba = IncMeanSTD(COUNT_EACH_NORM) 


    def update(self, packet, ip_pair):
        if packet.tcp_flag not in self.tcp_flag_count:
            self.tcp_flag_count[packet.tcp_flag] = 1
        else:
            self.tcp_flag_count[packet.tcp_flag] += 1
            
        if packet.sender == ip_pair.split(";")[0]:
            if self.last_seen_ab != None:
                iat = packet.ts - self.last_seen_ab
                rst, ano_score, p_c_list, p_r_list = self.iat_ab.merge(iat, packet.ts)
                #rst, ano_score, p_c_list, p_r_list = self.iat_ab.update(iat)
                self.iat_flow_ab.update(iat)
                #print("iat_ab: " + str(iat))
                #print(self.iat_ab)
                if not rst:
                    desp = "PACKET_IAT"
                    confi = sigmoid(self.total_ab/COUNT_EACH_NORM) * ano_score
                    generate_anomaly(packet.ts,
                                     desp,
                                     confi,
                                     self.index,
                                     self.anomaly_queue,
                                     packet,
                                     iat,
                                     p_c_list,
                                     p_r_list)
            self.last_seen_ab = packet.ts

            packet_len = packet.packet_len 
            rst, ano_score, p_c_list, p_r_list = self.bytes_ab.merge(packet_len, packet.ts)
            #rst, ano_score, p_c_list, p_r_list = self.bytes_ab.update(packet_len)
            self.bytes_flow_ab.update(packet_len)
            #print("bytes_ab: " + str(packet_len))
            #print(self.bytes_ab)
            if not rst:
                desp = "PACKET_BYTES"
                confi = sigmoid(self.total_ab/COUNT_EACH_NORM) * ano_score 
                generate_anomaly(packet.ts,
                                 desp,
                                 confi,
                                 self.index,
                                 self.anomaly_queue,
                                 packet,
                                 packet_len,
                                 p_c_list,
                                 p_r_list)
            self.total_ab += 1
        else:
            if self.last_seen_ba != None:
                iat = packet.ts - self.last_seen_ba
                rst, ano_score, p_c_list, p_r_list = self.iat_ba.merge(iat, packet.ts)
                #rst, ano_score, p_c_list, p_r_list = self.iat_ba.update(iat)
                self.iat_flow_ba.update(iat)
                #print("iat_ba: " + str(iat))
                #print(self.iat_ba)
                if not rst:
                    desp = "PACKET_IAT"
                    confi = sigmoid(self.total_ba/COUNT_EACH_NORM) * ano_score
                    generate_anomaly(packet.ts,
                                     desp,
                                     confi,
                                     self.index,
                                     self.anomaly_queue,
                                     packet,
                                     iat,
                                     p_c_list,
                                     p_r_list)
            self.last_seen_ba = packet.ts

            packet_len = packet.packet_len 
            rst, ano_score, p_c_list, p_r_list = self.bytes_ba.merge(packet_len, packet.ts)
            #rst, ano_score, p_c_list, p_r_list = self.bytes_ba.update(packet_len)
            self.bytes_flow_ba.update(packet_len)
            #print("bytes_ba: " + str(packet_len))
            #print(self.bytes_ba)
            if not rst:
                desp = "PACKET_BYTES"
                confi = sigmoid(self.total_ba/COUNT_EACH_NORM) * ano_score 
                generate_anomaly(packet.ts,
                                 desp,
                                 confi,
                                 self.index,
                                 self.anomaly_queue,
                                 packet,
                                 packet_len,
                                 p_c_list,
                                 p_r_list)
            self.total_ba += 1
 

class PacketAnalyzer():
    def __init__(self, anomaly_queue, flow_queue):
        self.orig_dict = dict()
        self.resp_dict = dict()
        self.protocol_dict = dict()
        self.service_dict = dict()
        self.ip_pair_dict = dict()
        self.total = 0
        self.start_time = None 
        self.anomaly_queue = anomaly_queue
        self.flow_queue = flow_queue
        self.last_aggregate = -1


    def analyze(self, packet):
        if self.last_aggregate == -1:
            self.last_aggregate = packet.ts
            self.start_time = packet.ts

        while packet.ts > self.last_aggregate + PERIOD:
            self.aggregate()
            self.last_aggregate += PERIOD 

        orig = packet.conn[0]
        resp = packet.conn[2]
        protocol = packet.protocol_type
        service_list = packet.service
        ip_pair = orig + ";" + resp
        inverse_ip_pair = resp + ";" + orig
        cur_ip_pair = ip_pair
        index = ip_pair + ";" + protocol + ";" + str(service_list)

        confi = sigmoid(self.total/COUNT_NORM) * sigmoid(abs(packet.ts-self.start_time)/TIME_NORM)
        if orig not in self.orig_dict:
            self.orig_dict[orig] = 0 
        if self.orig_dict[orig] < COUNT_NORM:
            generate_anomaly(packet.ts,
                             "NEW_ORIG",
                             confi,
                             index,
                             self.anomaly_queue,
                             packet)

        if resp not in self.resp_dict:
            self.resp_dict[resp] = 0 
        if self.resp_dict[resp] < COUNT_NORM:
            generate_anomaly(packet.ts,
                             "NEW_RESP",
                             confi,
                             index,
                             self.anomaly_queue,
                             packet)
        if protocol not in self.protocol_dict:
            self.protocol_dict[protocol] = 0 
        if self.protocol_dict[protocol] < COUNT_NORM:
            generate_anomaly(packet.ts,
                             "NEW_PROTOCOL",
                             confi,
                             index,
                             self.anomaly_queue,
                             packet)

        for service in service_list:
            if service not in self.service_dict:
                self.service_dict[service] = 0 
            if self.service_dict[service] < COUNT_NORM:
                generate_anomaly(packet.ts,
                                 "NEW_SERVICE",
                                 confi,
                                 index,
                                 self.anomaly_queue,
                                 packet)
            self.service_dict[service] += 1

        self.orig_dict[orig] += 1
        self.resp_dict[resp] += 1
        self.protocol_dict[protocol] += 1 
        self.total += 1

        if ip_pair not in self.ip_pair_dict and inverse_ip_pair not in self.ip_pair_dict:
            self.ip_pair_dict[ip_pair] = IPPairStats() 
        if ip_pair not in self.ip_pair_dict:
            ip_pair_stats = self.ip_pair_dict[inverse_ip_pair] 
            index = inverse_ip_pair + ";" + protocol + ";" + str(service_list)
            cur_ip_pair = inverse_ip_pair
        else:
            ip_pair_stats = self.ip_pair_dict[ip_pair] 
       
 
        confi = sigmoid(ip_pair_stats.total/COUNT_NORM)
        if protocol not in ip_pair_stats.protocol_dict:
            ip_pair_stats.protocol_dict[protocol] = ProtocolStats()
        protocol_stats = ip_pair_stats.protocol_dict[protocol]
        if protocol_stats.total < COUNT_NORM: 
            generate_anomaly(packet.ts,
                             "NEW_PROTOCOL",
                             confi,
                             index,
                             self.anomaly_queue,
                             packet)
        ip_pair_stats.total += 1
        
        confi = sigmoid(protocol_stats.total/COUNT_NORM)
        for service in service_list:
            if service not in protocol_stats.service_dict:
                protocol_stats.service_dict[service] = ServiceStats(index, self.anomaly_queue)
            service_stats = protocol_stats.service_dict[service]
            if service_stats.total_ab + service_stats.total_ba < COUNT_NORM:
                generate_anomaly(packet.ts,
                                 "NEW_SERVICE",
                                 confi,
                                 index,
                                 self.anomaly_queue,
                                 packet)
            service_stats.update(packet, cur_ip_pair)
        protocol_stats.total += 1


    def aggregate(self):
        for ip_pair in self.ip_pair_dict:
            ip_pair_stats = self.ip_pair_dict[ip_pair]
            ip_pair_list = ip_pair.split(";")
            orig = ip_pair_list[0]
            resp = ip_pair_list[1]
            for protocol in ip_pair_stats.protocol_dict:
                protocol_stats = ip_pair_stats.protocol_dict[protocol] 
                for service in protocol_stats.service_dict:
                    service_stats = protocol_stats.service_dict[service]
                    generate_flow(self.last_aggregate,
                                  self.last_aggregate+PERIOD,
                                  orig,
                                  resp,
                                  protocol,
                                  service,
                                  service_stats,
                                  self.flow_queue)
                    service_stats.clearFlow()
