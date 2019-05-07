import numpy as np
import random
import math
import csv
from packet import Packet
from flow import Flow
from operation import Operation
from data_value import DataValue
from Queue import PriorityQueue as PQueue

CC_NUM = 1 
STATION_NUM = 10 

class PacketGenerator():
    def __init__(self,
                 sender,
                 receiver,
                 protocol_type,
                 service,
                 packet_len,
                 conn,
                 tcp_flag=0,
        ):
        self.sender = sender
        self.receiver = receiver
        self.protocol_type = protocol_type
        self.service = service
        self.packet_len = packet_len
        self.conn = conn
        self.tcp_flag = tcp_flag


    def generate_one(self, ts):
        packet = Packet(ts,
                        self.sender,
                        self.receiver,
                        self.protocol_type,
                        self.tcp_flag,
                        self.service,
                        self.packet_len,
                        self.conn)
        return packet


class OperationGenerator():
    def __init__(self,
                 orig_ip,
                 resp_ip,
                 service,
                 uid,
                 fc,
                 fn,
                 is_orig
        ):
        self.orig_ip = orig_ip 
        self.resp_ip = resp_ip 
        self.service = service
        self.uid = uid
        self.fc = fc
        self.fn = fn
        self.is_orig = is_orig


    def generate_one(self, ts):
        operation = Operation(ts,
                              self.orig_ip,
                              self.resp_ip,
                              self.service,
                              self.uid,
                              self.fc,
                              self.fn,
                              self.is_orig)
        return operation 


class MeasurementGenerator():
    def __init__(self,
                 holder_ip,
                 protocol,
                 uid,
                 data_type,
                 index,
                 interval=None,
                 mean=None,
                 analog_type=None,
                 diff=None,
                 amp=None,
                 period=None):
        self.holder_ip = holder_ip 
        self.protocol = protocol 
        self.uid = uid
        self.data_type = data_type
        self.index = index 
        self.interval = interval
        self.mean = mean
        self.analog_type = analog_type
        self.diff = diff
        self.amp = amp
        self.period = period


    def generate_one(self, idx, ts):
        if self.data_type == "Binary":
            value = self.mean
        elif self.data_type == "Analog":
            if self.analog_type == "Frequency" or self.analog_type == "Voltage":
                value = np.random.normal(self.mean, self.diff)
            elif self.analog_type == "Current/Power":
                value = (self.mean +
                         self.amp * math.sin(idx*self.interval%self.period/self.interval*2*math.pi) +
                         np.random.normal(0, self.diff))
            else:
                value = random.uniform(self.mean-self.diff, self.mean+self.diff)
        else:
            value = 0
        measurement = DataValue(ts,
                                self.holder_ip,
                                self.protocol,
                                self.uid,
                                self.data_type,
                                self.index,
                                value,
                                False)
        return measurement 


class MeasurementReader():
    def __init__(self,
                 holder_ip,
                 protocol,
                 uid,
                 data_type,
                 index,
                 csv_rows,
                 col_name):
        self.holder_ip = holder_ip 
        self.protocol = protocol 
        self.uid = uid
        self.data_type = data_type
        self.index = index 
        self.col_name = col_name 
        self.csv_rows = csv_rows 

    def generate_one(self, idx, row_idx, ts):
        row = self.csv_rows[row_idx]
        value = float(row[self.col_name])

        measurement = DataValue(ts,
                                self.holder_ip,
                                self.protocol,
                                self.uid,
                                self.data_type,
                                self.index,
                                value,
                                False)
        return measurement 


class CommunicationPair():
    def __init__(self,
                 priority_queue,
                 cc_ip,
                 ss_ip,
                 uid,
                 csv_steady,
                 anomalies=[],
                 csv_over_voltage=None,
                 csv_under_voltage=None,
                 csv_over_current=None,
        ):
        self.pq = priority_queue 
        self.g_dict = {}
        self.ts = None
        self.anomalies = sorted(
            anomalies,
            key=lambda a: self.getIndex(a["start_day"], a["start_index"]),
        ) 

        ss_port = "20000tcp"
        cc_port = str(random.randint(44000, 47000)) + "tcp"
        conn = (cc_ip, cc_port, ss_ip, ss_port) 

        self.g_dict["p_read"] = PacketGenerator(
            cc_ip,
            ss_ip,
            "TCP",
            ["DNP3_TCP"],
            79,
            conn,
        )

        self.g_dict["o_read"] = OperationGenerator(
            cc_ip,
            ss_ip,
            "DNP3_TCP",
            uid,
            1,
            "READ",
            True,
        )

        self.g_dict["p_resp"] = PacketGenerator(
            ss_ip,
            cc_ip,
            "TCP",
            ["DNP3_TCP"],
            98,
            conn,
        )

        self.g_dict["o_resp"] = OperationGenerator(
            cc_ip,
            ss_ip,
            "DNP3_TCP",
            uid,
            129,
            "RESPONSE",
            False,
        )
        
        self.g_dict["p_conf"] = PacketGenerator(
            cc_ip,
            ss_ip,
            "TCP",
            ["DNP3_TCP"],
            67,
            conn,
        )

        self.g_dict["o_conf"] = OperationGenerator(
            cc_ip,
            ss_ip,
            "DNP3_TCP",
            uid,
            0,
            "CONFIRM",
            True,
        )

        self.g_dict["p_ack"] = PacketGenerator(
            ss_ip,
            cc_ip,
            "TCP",
            ["DNP3_TCP"],
            52,
            conn,
        )

        self.g_dict["m_f"] = MeasurementReader(
            ss_ip,
            "DNP3_TCP",
            uid,
            "Analog",
            1,
            csv_steady,
            "MVf1",
        )

        self.g_dict["m_v"] = MeasurementReader(
            ss_ip,
            "DNP3_TCP",
            uid,
            "Analog",
            2,
            csv_steady,
            "MVVa2",
        )

        self.g_dict["m_i"] = MeasurementReader(
            ss_ip,
            "DNP3_TCP",
            uid,
            "Analog",
            3,
            csv_steady,
            "MVIa1",
        )

        self.g_dict["m_p"] = MeasurementReader(
            ss_ip,
            "DNP3_TCP",
            uid,
            "Analog",
            4,
            csv_steady,
            "MVPa1",
        )

        self.g_dict["m_b"] = MeasurementGenerator(
            ss_ip,
            "DNP3_TCP",
            uid,
            "Binary",
            5,
            20,
            1,
        )
        
        if csv_over_voltage is not None:
            self.g_dict["m_v_o"] = MeasurementReader(
                ss_ip,
                "DNP3_TCP",
                uid,
                "Analog",
                2,
                csv_over_voltage,
                "MVVa2",
            )

        if csv_under_voltage is not None:
            self.g_dict["m_v_u"] = MeasurementReader(
                ss_ip,
                "DNP3_TCP",
                uid,
                "Analog",
                2,
                csv_under_voltage,
                "MVVa2",
            )

        if csv_over_current is not None:
            self.g_dict["m_i_o"] = MeasurementReader(
                ss_ip,
                "DNP3_TCP",
                uid,
                "Analog",
                3,
                csv_over_current,
                "MVIa1",
            )


    def getIndex(self, day, i):
        return day*3*60*24 + i


    def addAnomalies(self, anomalies):
        self.anomalies += anomalies
        self.anomalies = sorted(
            self.anomalies,
            key=lambda a: self.getIndex(a["start_day"], a["start_index"]),
        ) 


    def getAnomaly(self, anomaly_name, day, i):
        k = 0
        while k < len(self.anomalies):
            anomaly = self.anomalies[k]
            if self.getIndex(anomaly["end_day"], anomaly["end_index"]) < self.getIndex(day, i):
                self.anomalies.remove(anomaly)
            elif self.getIndex(anomaly["start_day"], anomaly["start_index"]) > self.getIndex(day, i):
                return None
            elif anomaly["name"] == anomaly_name:
                return anomaly
            else:
                k += 1
        return None


    def generate_read(self, day, i):
        self.ts = self.getIndex(day, i)*20 + 0.2 + np.random.normal(0, 0.02)
        # Delay Command 
        anomaly = self.getAnomaly("Delay Command", day, i)
        if anomaly is not None:
            self.ts += anomaly["value"] 
        p_read = self.g_dict["p_read"].generate_one(self.ts)
        # Change Command Size
        anomaly = self.getAnomaly("Change Command Size", day, i)
        if anomaly is not None:
            p_read.packet_len = anomaly["value"] 
        self.pq.put((self.ts, 'p', p_read))

        o_read = self.g_dict["o_read"].generate_one(self.ts)
        # Tamper Command 
        anomaly = self.getAnomaly("Tamper Command", day, i)
        if anomaly is not None:
            o_read.fc = anomaly["fc"] 
            o_read.fn = anomaly["fn"] 
        self.pq.put((self.ts, 'o', o_read))


    def generate_ack1(self):
        self.ts = self.ts + 0.002 + np.random.normal(0, 0.0005)
        p_ack1 = self.g_dict["p_ack"].generate_one(self.ts)
        self.pq.put((self.ts, 'p', p_ack1))
 
       
    def generate_resp(self, day, i):
        row_idx = i*24000/(3*60*24)
        self.ts = self.ts + 0.01 + np.random.normal(0, 0.003)
        # Delay Response 
        anomaly = self.getAnomaly("Delay Response", day, i)
        if anomaly is not None:
            self.ts += anomaly["value"] 
        p_resp = self.g_dict["p_resp"].generate_one(self.ts)
        self.pq.put((self.ts, 'p', p_resp))
        o_resp = self.g_dict["o_resp"].generate_one(self.ts)
        self.pq.put((self.ts, 'o', o_resp))
                
        m_f = self.g_dict["m_f"].generate_one(day*3*60*24+i, row_idx, self.ts)
        # Tamper Frequncy
        anomaly = self.getAnomaly("Tamper Frequency", day, i)
        if anomaly is not None:
            m_f.value = anomaly["value"] 
        self.pq.put((self.ts, 'd', m_f))

        m_v = self.g_dict["m_v"].generate_one(day*3*60*24+i, row_idx, self.ts)
        # Over Voltage
        anomaly = self.getAnomaly("Over Voltage", day, i)
        if anomaly is not None:
            m_v = self.g_dict["m_v_o"].generate_one(day*3*60*24+i, row_idx, self.ts)
        # Under Voltage
        anomaly = self.getAnomaly("Under Voltage", day, i)
        if anomaly is not None:
            m_v = self.g_dict["m_v_u"].generate_one(day*3*60*24+i, row_idx, self.ts)
        self.pq.put((self.ts, 'd', m_v))

        # Tamper Frequncy
        anomaly = self.getAnomaly("Tamper Voltage", day, i)
        if anomaly is not None:
            m_v.value = anomaly["value"] 
        self.pq.put((self.ts, 'd', m_v))

        m_i = self.g_dict["m_i"].generate_one(day*3*60*24+i, row_idx, self.ts)
        # Over Current
        anomaly = self.getAnomaly("Over Current", day, i)
        if anomaly is not None:
            m_i = self.g_dict["m_i_o"].generate_one(day*3*60*24+i, row_idx, self.ts)
        self.pq.put((self.ts, 'd', m_i))

        m_p = self.g_dict["m_p"].generate_one(day*3*60*24+i, row_idx, self.ts)
        # Tamper Power
        anomaly = self.getAnomaly("Tamper Power", day, i)
        if anomaly is not None:
            m_p.value = anomaly["value"]
        self.pq.put((self.ts, 'd', m_p))

        m_b = self.g_dict["m_b"].generate_one(day*3*60*24+i, self.ts)
        # Tamper Binary
        anomaly = self.getAnomaly("Tamper Binary", day, i)
        if anomaly is not None:
            m_b.value = anomaly["value"] 
        self.pq.put((self.ts, 'd', m_b))


    def generate_conf(self):
        self.ts = self.ts + 0.2*2 + np.random.normal(0, 0.05)
        p_conf = self.g_dict["p_conf"].generate_one(self.ts)
        self.pq.put((self.ts, 'p', p_conf))
        o_conf = self.g_dict["o_conf"].generate_one(self.ts)
        self.pq.put((self.ts, 'o', o_conf))


    def generate_ack2(self):
        self.ts = self.ts + 0.002 + np.random.normal(0, 0.0005)
        p_ack2 = self.g_dict["p_ack"].generate_one(self.ts)
        self.pq.put((self.ts, 'p', p_ack2))



class TrafficGenerator():
    def __init__(self, packet_queue, operation_queue, data_value_queue):
        self.packet_queue = packet_queue
        self.operation_queue = operation_queue
        self.data_value_queue = data_value_queue
        self.num_day = 14 
        self.pq = PQueue()
        self.anomalies = []

        # Read Analog Measurement Files
        self.csv_steady = None
        with open("../csv/S1_Steady_State.csv") as csvfile:
            reader = csv.DictReader(csvfile)
            self.csv_steady = [row for row in reader]

        self.csv_over_voltage = None
        with open("../csv/S4_Overvoltage_Tripping.csv") as csvfile:
            reader = csv.DictReader(csvfile)
            self.csv_over_voltage = [row for row in reader]

        self.csv_under_voltage = None
        with open("../csv/S7_Undervoltage_Tripping.csv") as csvfile:
            reader = csv.DictReader(csvfile)
            self.csv_under_voltage = [row for row in reader]

        self.csv_over_current = None
        with open("../csv/S3_Overcurrent_Instant_Fault6.csv") as csvfile:
            reader = csv.DictReader(csvfile)
            self.csv_over_current = [row for row in reader]
 
        # Calculate Substation per Control Center
        self.ss_num = []
        count = 0
        ss_per_cc = int(math.ceil(float(STATION_NUM)/CC_NUM))
        for i in range(CC_NUM):
            if i == CC_NUM-1:
                self.ss_num.append(STATION_NUM - count)
            else:
                self.ss_num.append(ss_per_cc)
                count += ss_per_cc

        # Create Generators
        self.cc_list = []
        uid = "85:80"
        for i in range(CC_NUM):
            cc_ip = "100.0." + str(i) + ".1"
            ss_list = [] 
            for j in range(self.ss_num[i]):
                ss_ip = "100.0." + str(i) + "." + str(j+2)
                anomalies = []
                comm_pair = CommunicationPair(
                    self.pq,
                    cc_ip,
                    ss_ip,
                    uid,
                    self.csv_steady,
                    anomalies,
                    self.csv_over_voltage,
                    self.csv_under_voltage,
                    self.csv_over_current,
                )
                ss_list.append(comm_pair)
            self.cc_list.append(ss_list)

        # Inject Anomalies
        self.injectTCPSYNFlooding()
        self.injectDataIntegrityAttack()
        self.injectCommandInjection()


    def injectTCPSYNFlooding(self):
        day = 9 
        address_scan = {
            "name": "Address Scan",
            "start_day": day,
            "start_index": 500,
            "end_day": day,
            "end_index": 500,
            "attacker_ip": "200.0.0.1",
            "subnet": "100.0.0.",
        }
        tcp_syn_flooding = {
            "name": "TCP SYN Flooding",
            "start_day": day,
            "start_index": 1000,
            "end_day": day,
            "end_index": 1600,
            "interval": 0.2,
            "target_ip": "100.0.0.1",
        }
        delay_command = {
            "name": "Delay Command",
            "start_day": day,
            "start_index": 1000,
            "end_day": day,
            "end_index": 1600,
            "value": 5,
        }
        self.anomalies += [address_scan, tcp_syn_flooding]
        for j in range(self.ss_num[0]):
            self.cc_list[0][j].addAnomalies([delay_command])


    def injectDataIntegrityAttack(self):
        day = 11 
        delay_response = {
            "name": "Delay Response",
            "start_day": day,
            "start_index": 1000,
            "end_day": day,
            "end_index": 1100,
            "value": 1,
        }
        tamper_frequency = {
            "name": "Tamper Frequency",
            "start_day": day,
            "start_index": 1000,
            "end_day": day,
            "end_index": 1100,
            "value": 61,
        }
        over_voltage = {
            "name": "Over Voltage",
            "start_day": day,
            "start_index": 0,
            "end_day": day,
            "end_index": 3*60*24-1,
        }
        under_voltage = {
            "name": "Under Voltage",
            "start_day": day,
            "start_index": 0,
            "end_day": day,
            "end_index": 3*60*24-1,
        }
        tamper_voltage = {
            "name": "Tamper Voltage",
            "start_day": day,
            "start_index": 1000,
            "end_day": day,
            "end_index": 1100,
            "value": 10, 
        }
        over_current = {
            "name": "Over Current",
            "start_day": day,
            "start_index": 0,
            "end_day": day,
            "end_index": 3*60*24-1,
        }
        tamper_power = {
            "name": "Tamper Power",
            "start_day": day,
            "start_index": 1000,
            "end_day": day,
            "end_index": 1100,
            "value": 10,
        }
        tamper_binary = {
            "name": "Tamper Binary",
            "start_day": day,
            "start_index": 1000,
            "end_day": day,
            "end_index": 1100,
            "value": -1.0,
        }

        self.cc_list[0][1].addAnomalies([delay_response, tamper_voltage])
        #self.cc_list[0][1].addAnomalies([delay_response, tamper_frequency, tamper_binary])
        #self.cc_list[0][1].addAnomalies([tamper_frequency, tamper_binary])


    def injectCommandInjection(self):
        day = 13 
        address_scan = {
            "name": "Address Scan",
            "start_day": day,
            "start_index": 500,
            "end_day": day,
            "end_index": 500,
            "attacker_ip": "150.0.0.1",
            "subnet": "100.0.0.",
        }
        service_scan = {
            "name": "Service Scan",
            "start_day": day,
            "start_index": 700,
            "end_day": day,
            "end_index": 700,
            "attacker_ip": "150.0.0.1",
            "subnet": "100.0.0.",
        }
        tamper_command = {
            "name": "Tamper Command",
            "start_day": day,
            "start_index": 1000,
            "end_day": day,
            "end_index": 1000,
            "fc": 13,
            "fn": "COLD_RESTART",
        }
        delay_command = {
            "name": "Delay Command",
            "start_day": day,
            "start_index": 1000,
            "end_day": day,
            "end_index": 1000,
            "value": 1,
        }
        change_command_size = {
            "name": "Change Command Size",
            "start_day": day,
            "start_index": 1000,
            "end_day": day,
            "end_index": 1000,
            "value": 70,
        }
 
        #self.cc_list[0][2].addAnomalies([delay_command, change_command_size, tamper_command]) 
        self.cc_list[0][2].addAnomalies([change_command_size, tamper_command]) 
        self.anomalies += [address_scan, service_scan]


    def getIndex(self, day, i):
        return day*3*60*24 + i


    def getAnomaly(self, anomaly_name):
        rst = []
        for anomaly in self.anomalies:
            if anomaly["name"] == anomaly_name:
                rst.append(anomaly) 
        return rst 


    def prepare(self):
        for day in range(self.num_day):
            for i in range(3*60*24):
                for ss_list in self.cc_list: 
                    for comm_pair in ss_list:
                        comm_pair.generate_read(day, i)

                for ss_list in self.cc_list: 
                    for comm_pair in ss_list:
                        comm_pair.generate_ack1()

                for ss_list in self.cc_list: 
                    for comm_pair in ss_list:
                        comm_pair.generate_resp(day, i)

                for ss_list in self.cc_list: 
                    for comm_pair in ss_list:
                        comm_pair.generate_conf()

                for ss_list in self.cc_list: 
                    for comm_pair in ss_list:
                        comm_pair.generate_ack2()

        # Address Scan
        address_scans = self.getAnomaly("Address Scan")
        for anomaly in address_scans:
            ts = self.getIndex(anomaly["start_day"], anomaly["start_index"])*20
            dst_port = "20000tcp"
            src_port = str(random.randint(44000, 47000)) + "tcp"
            subnet = anomaly["subnet"]
            cc_index = int(subnet.split(".")[2]) 
            for j in range(1, 256):
                src_ip = anomaly["attacker_ip"]
                dst_ip = subnet + str(j)
                conn = (src_ip, src_port, dst_ip, dst_port) 
                scan_gen = PacketGenerator(
                    src_ip,
                    dst_ip,
                    "TCP",
                    [],
                    48,
                    conn,
                )
                p_scan = scan_gen.generate_one(ts)
                self.pq.put((ts, 'p', p_scan))
                if j < self.ss_num[cc_index] + 1:
                    ts = ts + 0.2 + np.random.normal(0, 0.02)
                    ack_gen = PacketGenerator(
                        dst_ip,
                        src_ip,
                        "TCP",
                        [],
                        52,
                        conn,
                    )
                    p_ack = ack_gen.generate_one(ts)
                    self.pq.put((ts, 'p', p_ack))

        # TCP SYN Flooding
        tcp_syn_floods = self.getAnomaly("TCP SYN Flooding")
        for anomaly in tcp_syn_floods:
            start_time = self.getIndex(anomaly["start_day"], anomaly["start_index"])*20
            end_time = self.getIndex(anomaly["end_day"], anomaly["end_index"])*20
            dst_port = "20000tcp"
            src_port = str(random.randint(44000, 47000)) + "tcp"
            dst_ip = anomaly["target_ip"]
            target_ip_list = dst_ip.split(".")
            cc_index = int(target_ip_list[2])
            for j in range(self.ss_num[cc_index]+1):
                src_ip = "100.0.0." + str(j+1)
                if src_ip != dst_ip:
                    conn = (src_ip, src_port, dst_ip, dst_port) 
                    syn_gen = PacketGenerator(
                        src_ip,
                        dst_ip,
                        "TCP",
                        ["DNP3_TCP"],
                        48,
                        conn,
                        2,
                    )
                    ts = start_time
                    while ts <= end_time:
                        p_syn = syn_gen.generate_one(ts)
                        self.pq.put((ts, 'p', p_syn))
                        ts += anomaly["interval"] 

        # Service Scan
        service_scans = self.getAnomaly("Service Scan")
        for anomaly in service_scans:
            ts = self.getIndex(anomaly["start_day"], anomaly["start_index"])*20
            src_port = str(random.randint(44000, 47000)) + "tcp"
            subnet = anomaly["subnet"]
            cc_index = int(subnet.split(".")[2]) 
            for j in range(self.ss_num[cc_index]+1):
                src_ip = anomaly["attacker_ip"]
                dst_ip = subnet + str(j)

                dst_port = "502tcp"
                conn = (src_ip, src_port, dst_ip, dst_port) 
                scan_gen = PacketGenerator(
                    src_ip,
                    dst_ip,
                    "TCP",
                    ["MODEBUS"],
                    48,
                    conn,
                )
                p_scan = scan_gen.generate_one(ts)
                self.pq.put((ts, 'p', p_scan))

                dst_port = "102tcp"
                conn = (src_ip, src_port, dst_ip, dst_port) 
                scan_gen = PacketGenerator(
                    src_ip,
                    dst_ip,
                    "TCP",
                    ["IEC61850"],
                    48,
                    conn,
                )
                p_scan = scan_gen.generate_one(ts)
                self.pq.put((ts, 'p', p_scan))

                dst_port = "20000tcp"
                conn = (src_ip, src_port, dst_ip, dst_port) 
                scan_modbus_gen = PacketGenerator(
                    src_ip,
                    dst_ip,
                    "TCP",
                    ["DNP3_TCP"],
                    48,
                    conn,
                )
                p_scan = scan_gen.generate_one(ts)
                self.pq.put((ts, 'p', p_scan))

                ts = ts + 0.2 + np.random.normal(0, 0.02)
                ack_gen = PacketGenerator(
                    dst_ip,
                    src_ip,
                    "TCP",
                    ["DNP3_TCP"],
                    52,
                    conn,
                )
                p_ack = ack_gen.generate_one(ts)
                self.pq.put((ts, 'p', p_ack))


    def generate(self):
        self.prepare()
        while not self.pq.empty():
            cur = self.pq.get()
            if cur[1] == 'p':
                self.packet_queue.put_nowait(cur[2])
            elif cur[1] == 'o':
                self.operation_queue.put_nowait(cur[2])
            else:
                self.data_value_queue.put_nowait(cur[2])
