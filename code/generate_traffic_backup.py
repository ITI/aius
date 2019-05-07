import numpy as np
import random
import math
import csv
from packet import Packet
from flow import Flow
from operation import Operation
from data_value import DataValue

CC_NUM = 1
STATION_NUM = 3

class PacketGenerator():
    def __init__(self,
                 sender,
                 receiver,
                 protocol_type,
                 service,
                 interval,
                 interval_std,
                 packet_len_list,
                 conn):
        self.sender = sender
        self.receiver = receiver
        self.protocol_type = protocol_type
        self.service = service
        self.interval = interval
        self.interval_std = interval_std
        self.packet_len_list = packet_len_list
        self.packet_len_list_size = len(packet_len_list)
        self.conn = conn


    def generate_one(self, time):
        len_index = random.randint(0, self.packet_len_list_size-1)
        packet_len = self.packet_len_list[len_index]
        ts = time + abs(np.random.normal(0, self.interval_std))
        packet = Packet(ts,
                        self.sender,
                        self.receiver,
                        self.protocol_type,
                        0,
                        self.service,
                        packet_len,
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
                 is_orig,
                 interval,
                 interval_std):
        self.orig_ip = orig_ip 
        self.resp_ip = resp_ip 
        self.service = service
        self.uid = uid
        self.fc = fc
        self.fn = fn
        self.is_orig = is_orig
        self.interval = interval
        self.interval_std = interval_std


    def generate_one(self, time):
        ts = time + abs(np.random.normal(0, self.interval_std))
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
                 interval,
                 interval_std,
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
        self.interval_std = interval_std
        self.mean = mean
        self.analog_type = analog_type
        self.diff = diff
        self.amp = amp
        self.period = period


    def generate_one(self, idx):
        ts = max(0, idx*self.interval)
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
                 interval,
                 interval_std,
                 csv_rows,
                 col_name):
        self.holder_ip = holder_ip 
        self.protocol = protocol 
        self.uid = uid
        self.data_type = data_type
        self.index = index 
        self.interval = interval
        self.interval_std = interval_std
        self.col_name = col_name 
        self.csv_rows = csv_rows 

    def generate_one(self, idx, row_idx):
        ts = max(0, idx*self.interval)
        #ts = max(0, np.random.normal(idx*self.interval, self.interval_std))
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


class TrafficGenerator():
    def __init__(self, packet_queue, flow_queue, operation_queue, data_value_queue):
        self.packet_queue = packet_queue
        self.flow_queue = flow_queue
        self.operation_queue = operation_queue
        self.data_value_queue = data_value_queue

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
        for i in range(CC_NUM):
            cc_ip = "100.0." + str(i) + ".1"
            ss_list = [] 
            for j in range(self.ss_num[i]):
                ss_dict = {}
                ss_ip = "100.0." + str(i) + "." + str(j+2)
                ss_port = "20000tcp"
                cc_port = str(random.randint(44000, 47000)) + "tcp"
                conn = (cc_ip, cc_port, ss_ip, ss_port) 

                ss_dict["p_read"] = PacketGenerator(
                    cc_ip,
                    ss_ip,
                    "TCP",
                    ["DNP3_TCP"],
                    20,
                    0.1,
                    [79],
                    conn,
                )

                ss_dict["o_read"] = OperationGenerator(
                    cc_ip,
                    ss_ip,
                    "DNP3_TCP",
                    "85:80",
                    1,
                    "READ",
                    True,
                    20,
                    0.1,
                )

                ss_dict["p_resp"] = PacketGenerator(
                    ss_ip,
                    cc_ip,
                    "TCP",
                    ["DNP3_TCP"],
                    20,
                    0.2,
                    [98],
                    conn,
                )

                ss_dict["o_resp"] = OperationGenerator(
                    cc_ip,
                    ss_ip,
                    "DNP3_TCP",
                    "85:80",
                    129,
                    "RESPONSE",
                    False,
                    20,
                    0.2,
                )
                
                ss_dict["p_conf"] = PacketGenerator(
                    cc_ip,
                    ss_ip,
                    "TCP",
                    ["DNP3_TCP"],
                    20,
                    0.05,
                    [67],
                    conn,
                )

                ss_dict["o_conf"] = OperationGenerator(
                    cc_ip,
                    ss_ip,
                    "DNP3_TCP",
                    "85:80",
                    0,
                    "CONFIRM",
                    True,
                    20,
                    0.05,
                )

                ss_dict["p_ack"] = PacketGenerator(
                    ss_ip,
                    cc_ip,
                    "TCP",
                    ["DNP3_TCP"],
                    20,
                    0.05,
                    [52],
                    conn,
                )

                ss_dict["mr_f"] = MeasurementReader(
                    ss_ip,
                    "DNP3_TCP",
                    "85:80",
                    "Analog",
                    1,
                    20,
                    0.5,
                    self.csv_steady,
                    "MVf1",
                )

                ss_dict["mr_v"] = MeasurementReader(
                    ss_ip,
                    "DNP3_TCP",
                    "85:80",
                    "Analog",
                    2,
                    20,
                    0.5,
                    self.csv_steady,
                    "MVVa2",
                )
                
                ss_dict["mr_v_o"] = MeasurementReader(
                    ss_ip,
                    "DNP3_TCP",
                    "85:80",
                    "Analog",
                    2,
                    20,
                    0.5,
                    self.csv_over_voltage,
                    "MVVa2",
                )

                ss_dict["mr_v_u"] = MeasurementReader(
                    ss_ip,
                    "DNP3_TCP",
                    "85:80",
                    "Analog",
                    2,
                    20,
                    0.5,
                    self.csv_under_voltage,
                    "MVVa2",
                )


                ss_dict["mr_i"] = MeasurementReader(
                    ss_ip,
                    "DNP3_TCP",
                    "85:80",
                    "Analog",
                    3,
                    20,
                    0.5,
                    self.csv_steady,
                    "MVIa1",
                )

                ss_dict["mr_i_o"] = MeasurementReader(
                    ss_ip,
                    "DNP3_TCP",
                    "85:80",
                    "Analog",
                    3,
                    20,
                    0.5,
                    self.csv_over_current,
                    "MVIa1",
                )

                ss_dict["mr_p"] = MeasurementReader(
                    ss_ip,
                    "DNP3_TCP",
                    "85:80",
                    "Analog",
                    4,
                    20,
                    0.5,
                    self.csv_steady,
                    "MVPa1",
                )

                ss_dict["mg_u"] = MeasurementGenerator(
                    ss_ip,
                    "DNP3_TCP",
                    "85:80",
                    "Analog",
                    5,
                    20,
                    0.5,
                    10,
                    "Unknown",
                    5,
                )

                ss_dict["mg_b"] = MeasurementGenerator(
                    ss_ip,
                    "DNP3_TCP",
                    "85:80",
                    "Binary",
                    1,
                    20,
                    0.5,
                    1,
                )

                ss_list.append(ss_dict)
            self.cc_list.append(ss_list)


    def generate(self):
        for day in range(10):
            for i in range(3*60*24):
                row_idx = i*24000/(3*60*24)

                cur = self.cc_list[0][0]

## Frequncy Tampering
#                m_f = cur["mr_f"].generate_one(day*3*60*24+i, row_idx)
#                if day == 8 and i >= 200 and i < 205:
#                    m_f.value = 61
#                if day == 9 and i >= 200 and i < 205:
#                    m_f.value = 59 
#                self.data_value_queue.put_nowait(m_f)
#
## Over Voltage
#                if day != 9:
#                    m_v = cur["mr_v"].generate_one(day*3*60*24+i, row_idx)
#                else:
#                    m_v = cur["mr_v_o"].generate_one(day*3*60*24+i, row_idx)
#                self.data_value_queue.put_nowait(m_v)
#
## Under Voltage
#                if day != 9:
#                    m_v = cur["mr_v"].generate_one(day*3*60*24+i, row_idx)
#                else:
#                    m_v = cur["mr_v_u"].generate_one(day*3*60*24+i, row_idx)
#                self.data_value_queue.put_nowait(m_v)
#
## Over Current
#                if day != 9:
#                    m_i = cur["mr_i"].generate_one(day*3*60*24+i, row_idx)
#                else:
#                    m_i = cur["mr_i_o"].generate_one(day*3*60*24+i, row_idx)
#                self.data_value_queue.put_nowait(m_i)
#
## Power Tampering
                m_p = cur["mr_p"].generate_one(day*3*60*24+i, row_idx)
#                if day == 8 and i >= 200 and i < 205:
#                    m_p.value = 10 
                if day == 9 and i >= 1200 and i < 1205:
                    m_p.value = 2 
                self.data_value_queue.put_nowait(m_p)

## Unknown Tampering 
#                m_u = cur["mg_u"].generate_one(day*3*60*24+i)
#                if day == 8 and i >= 200 and i <= 205:
#                    m_u.value = 20 
#                if day == 9 and i >= 1200 and i <= 1205:
#                    m_u.value = 0 
#                self.data_value_queue.put_nowait(m_u)
#
## Binary Tampering
#                m_b = cur["mg_b"].generate_one(day*3*60*24+i)
#                if day == 9 and i >= 1200 and i < 1205:
#                    m_b.value = -1.0 
#                self.data_value_queue.put_nowait(m_b)
#
## More Reads 
                time = (day*3*60*24+i)*20

                p_read = cur["p_read"].generate_one(time)
                self.packet_queue.put_nowait(p_read)
                if day == 9 and i >= 1000 and i < 1050:
                    for j in range(5):
                        p_read_extra = cur["p_read"].generate_one(time)
                        self.packet_queue.put_nowait(p_read_extra)
                p_ack1 = cur["p_ack"].generate_one(p_read.ts)
                self.packet_queue.put_nowait(p_ack1)
                p_resp = cur["p_resp"].generate_one(p_ack1.ts)
                self.packet_queue.put_nowait(p_resp)
                p_conf = cur["p_conf"].generate_one(p_resp.ts)
                self.packet_queue.put_nowait(p_conf)
                p_ack2 = cur["p_ack"].generate_one(p_conf.ts)
                self.packet_queue.put_nowait(p_ack2)
#
## Delay of Response
#                time = (day*3*60*24+i)*20
#                p_read = cur["p_read"].generate_one(time)
#                self.packet_queue.put_nowait(p_read)
#                p_ack1 = cur["p_ack"].generate_one(p_read.ts)
#                self.packet_queue.put_nowait(p_ack1)
#                p_resp = cur["p_resp"].generate_one(p_ack1.ts)
#                if day == 9 and i == 1000:
#                    p_resp.ts += 5
#                self.packet_queue.put_nowait(p_resp)
#                p_conf = cur["p_conf"].generate_one(p_resp.ts)
#                self.packet_queue.put_nowait(p_conf)
#                p_ack2 = cur["p_ack"].generate_one(p_conf.ts)
#                self.packet_queue.put_nowait(p_ack2)
#
## Packet Size Change 
#                time = (day*3*60*24+i)*20
#                p_read = cur["p_read"].generate_one(time)
#                self.packet_queue.put_nowait(p_read)
#                p_ack1 = cur["p_ack"].generate_one(p_read.ts)
#                self.packet_queue.put_nowait(p_ack1)
#                p_resp = cur["p_resp"].generate_one(p_ack1.ts)
#                if day == 9 and i == 1000:
#                    p_resp.packet_len += 12 
#                self.packet_queue.put_nowait(p_resp)
#                p_conf = cur["p_conf"].generate_one(p_resp.ts)
#                self.packet_queue.put_nowait(p_conf)
#                p_ack2 = cur["p_ack"].generate_one(p_conf.ts)
#                self.packet_queue.put_nowait(p_ack2)
#
## New Sender
                time = (day*3*60*24+i)*20
                if day == 9 and i == 1000:
                    p_read = cur["p_read"].generate_one(time)
                    p_read.sender = "100.0.0.4"
                    p_read.conn = ("100.0.0.4", "40001tcp", "100.0.0.2", "20000tcp")
                    self.packet_queue.put_nowait(p_read)
                p_read = cur["p_read"].generate_one(time)
                self.packet_queue.put_nowait(p_read)
                p_ack1 = cur["p_ack"].generate_one(p_read.ts)
                self.packet_queue.put_nowait(p_ack1)
                p_resp = cur["p_resp"].generate_one(p_ack1.ts)
                self.packet_queue.put_nowait(p_resp)
                p_conf = cur["p_conf"].generate_one(p_resp.ts)
                self.packet_queue.put_nowait(p_conf)
                p_ack2 = cur["p_ack"].generate_one(p_conf.ts)
                self.packet_queue.put_nowait(p_ack2)
#
## Invalid Function & Wrong Direction
#                time = (day*3*60*24+i)*20
#                if day == 9 and i == 1000:
#                    o_invalid = cur["o_read"].generate_one(time)
#                    o_invalid.fc = 300 
#                    self.operation_queue.put_nowait(o_invalid)
#                if day == 9 and i == 2000:
#                    o_invalid = cur["o_read"].generate_one(time)
#                    tmp = o_invalid.orig_ip
#                    o_invalid.orig_ip = o_invalid.resp_ip 
#                    o_invalid.resp_ip = tmp 
#                    o_invalid.is_orig = False
#                    self.operation_queue.put_nowait(o_invalid)
#                o_read = cur["o_read"].generate_one(time)
#                self.operation_queue.put_nowait(o_read)
#                o_resp = cur["o_resp"].generate_one(o_read.ts)
#                self.operation_queue.put_nowait(o_resp)
#                o_conf = cur["o_conf"].generate_one(o_resp.ts)
#                self.operation_queue.put_nowait(o_conf)
#
## Delay of Read 
#                time = (day*3*60*24+i)*20
#                o_read = cur["o_read"].generate_one(time)
#                if day == 9 and i == 1000:
#                    o_read.ts += 5
#                self.operation_queue.put_nowait(o_read)
#                o_resp = cur["o_resp"].generate_one(o_read.ts)
#                self.operation_queue.put_nowait(o_resp)
#                o_conf = cur["o_conf"].generate_one(o_resp.ts)
#                self.operation_queue.put_nowait(o_conf)
#

### 3-step Attack 
## Step 1: Port Scan
#                time = (day*3*60*24+i)*20
#                if day == 9 and i >= 1000 and i < 1020:
#                    ip = i+1-1000
#                    sender = "100.0.0.100"
#                    receiver = "100.0.0.{}".format(ip)
#                    # Modbus Scan
#                    p1_scan_modbus = pg1_ack.generate_one(time)
#                    p1_scan_modbus.sender = sender 
#                    p1_scan_modbus.receiver = receiver 
#                    p1_scan_modbus.service = ["MODBUS"] 
#                    p1_scan_modbus.conn = (sender, "55555tcp", receiver, "502tcp")
#                    self.packet_queue.put_nowait(p1_scan_modbus)
#                    # IEC61850 Scan
#                    p1_scan_61850 = pg1_ack.generate_one(time)
#                    p1_scan_61850.sender = sender 
#                    p1_scan_61850.receiver = receiver 
#                    p1_scan_61850.service = ["IEC61850"] 
#                    p1_scan_61850.conn = (sender, "55555tcp", receiver, "102tcp")
#                    self.packet_queue.put_nowait(p1_scan_61850)
#                    # DNP3 Scan
#                    p1_scan_dnp3 = pg1_ack.generate_one(time)
#                    p1_scan_dnp3.sender = sender 
#                    p1_scan_dnp3.receiver = receiver 
#                    p1_scan_dnp3.conn = (sender, "55555tcp", receiver, "20000tcp")
#                    self.packet_queue.put_nowait(p1_scan_dnp3)
#                # Normal Traffic 
#                p1_read = pg1_read.generate_one(time)
#                self.packet_queue.put_nowait(p1_read)
#                p1_ack1 = pg1_ack.generate_one(p1_read.ts)
#                self.packet_queue.put_nowait(p1_ack1)
#                p1_resp = pg1_resp.generate_one(p1_ack1.ts)
#                self.packet_queue.put_nowait(p1_resp)
#                p1_conf = pg1_conf.generate_one(p1_resp.ts)
#                self.packet_queue.put_nowait(p1_conf)
#                p1_ack2 = pg1_ack.generate_one(p1_conf.ts)
#                self.packet_queue.put_nowait(p1_ack2)
## Step 2: Invalid Function to Compromise
#                if day == 9 and i == 1020:
#                    o1_write = og1_read.generate_one(time)
#                    o1_write.fc = 2
#                    o1_write.fn = "WRITE" 
#                    self.operation_queue.put_nowait(o1_write)
#                # Normal Traffic
#                o1_read = og1_read.generate_one(time)
#                self.operation_queue.put_nowait(o1_read)
#                o1_resp = og1_resp.generate_one(o1_read.ts)
#                self.operation_queue.put_nowait(o1_resp)
#                o1_conf = og1_conf.generate_one(o1_resp.ts)
#                self.operation_queue.put_nowait(o1_conf)
## Step 3: Tempered Data
#                m1_b = mg1_b.generate_one(day*3*60*24+i)
#                if day == 9 and i >= 1030 and i < 1040:
#                    m1_b.value = -1.0 
#                self.data_value_queue.put_nowait(m1_b)


#                time = (day*3*60*24+i)*20
#                if day == 9 and i >= 1000 and i < 1020:
#                    o2_invalid = og2_read.generate_one(time)
#                    o2_invalid.fc = 13 
#                    self.operation_queue.put_nowait(o2_invalid)
#                o2_read = og2_read.generate_one(time)
#                self.operation_queue.put_nowait(o2_read)
#                o2_resp = og2_resp.generate_one(o2_read.ts)
#                self.operation_queue.put_nowait(o2_resp)
#                o2_conf = og2_conf.generate_one(o2_resp.ts)
#                self.operation_queue.put_nowait(o2_conf)
