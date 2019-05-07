#!/usr/bin/env python

from __future__ import unicode_literals

import sys
sys.path.append('/usr/local/bro/lib/broctl')
import broker
import gevent
import pickle
import socket
import timeit
import numpy
from gevent import select
from gevent.queue import Queue, Empty
from pprint import pprint
from parse_packet import parse_packet
from parse_operation import parse_operation
from parse_data_value import parse_data_value
from packet import Packet
from flow import Flow
from operation import Operation
from data_value import DataValue 
from analyze_packet import PacketAnalyzer 
from analyze_flow import FlowAnalyzer 
from analyze_operation import OperationAnalyzer
from analyze_data import DataAnalyzer 
from manage_anomaly import AnomalyManager
from generate_traffic import TrafficGenerator
            
raw_packet_queue = Queue()
raw_operation_queue = Queue()
raw_data_value_queue = Queue()
packet_queue = Queue()
operation_queue = Queue()
data_value_queue = Queue()
flow_queue = Queue()
anomaly_queue = Queue()
meta_alert_queue = Queue()
TIMEOUT = 120 
COUNT_INIT = TIMEOUT / 0.01


def listener():
    ep = broker.Endpoint()
    sub = ep.make_subscriber("edmand")
    ep.listen("127.0.0.1", 9999)

    total_time = 0
    count = 0
    while True:
        (t, msg)= sub.get()
        start = timeit.default_timer()
        t = str(t) 
        ev = broker.bro.Event(msg)
        if t == "edmand/packet_get":
            raw_packet_queue.put_nowait(ev.args())
        if t == "edmand/protocol_get":
            raw_operation_queue.put_nowait(ev.args())
        if t == "edmand/data_get":
            raw_data_value_queue.put_nowait(ev.args())
        if t == "edmand/bro_done":
            ep.shutdown()
            #print("Listener quit!")
            if count != 0:
                print("Listener time: " + str(total_time/count))
                return;
        #print("got message")
        total_time += timeit.default_timer() - start
        count += 1
        gevent.sleep(0)


def packet_parser(n):
    countdown = COUNT_INIT
    total_time = 0
    count = 0
    while countdown > 0:
        try:
            while True:
                #print(count)
                raw_packet = raw_packet_queue.get_nowait()
                start = timeit.default_timer()
                packet = parse_packet(raw_packet)
                packet_queue.put_nowait(packet)
                total_time += timeit.default_timer() - start
                count += 1
                countdown = COUNT_INIT
                gevent.sleep(0)
        except Empty:
            countdown -= 1
            gevent.sleep(0.01)
    #print('Packet parser %s quit!' % (n))
    if count != 0:
        print("Packet parser time: " + str(total_time/count))


def operation_parser(n):
    countdown = COUNT_INIT
    total_time = 0
    count = 0
    while countdown > 0:
        try:
            while True:
                #print(count)
                raw_operation = raw_operation_queue.get_nowait()
                start = timeit.default_timer()
                operation = parse_operation(raw_operation)
                operation_queue.put_nowait(operation)
                total_time += timeit.default_timer() - start
                count += 1
                countdown = COUNT_INIT
                gevent.sleep(0)
        except Empty:
            countdown -= 1
            gevent.sleep(0.01)
    #print('Operation parser %s quit!' % (n))
    if count != 0:
        print("Operation parser time: " + str(total_time/count))


def data_value_parser(n):
    countdown = COUNT_INIT
    total_time = 0
    count = 0
    while countdown > 0:
        try:
            while True:
                #print(count)
                raw_data_value = raw_data_value_queue.get_nowait()
                start = timeit.default_timer()
                data_value = parse_data_value(raw_data_value)
                data_value_queue.put_nowait(data_value)
                total_time += timeit.default_timer() - start
                count += 1
                countdown = COUNT_INIT
                gevent.sleep(0)
        except Empty:
            countdown -= 1
            gevent.sleep(0.01)
    #print('Data value parser %s quit!' % (n))
    if count != 0:
        print("Content parser time: " + str(total_time/count))


def traffic_generator(n):
    generator = TrafficGenerator(packet_queue, operation_queue, data_value_queue)
    generator.generate()
    print('Traffic generator %s quit!' % (n))


def packet_analyzer(n):
    countdown = COUNT_INIT
    anl = PacketAnalyzer(anomaly_queue, flow_queue)
    packet_time = [] 
    count = 0
    while countdown > 0:
        try:
            while True:
                packet = packet_queue.get_nowait()
                #print(packet)
                start = timeit.default_timer()
                anl.analyze(packet)
                packet_time.append(timeit.default_timer() - start)
                count += 1
                countdown = COUNT_INIT
                gevent.sleep(0)
        except Empty:
            countdown -= 1
            gevent.sleep(0.01)
    #print('Packet analyzer %s quit!' % (n))
    if count != 0:
        packet_array = numpy.array([packet_time])
        print("Packet analyzer time: " + str(numpy.mean(packet_array, axis=1)))
        print("Packet analyzer num: " + str(len(packet_time)))
        print("Packet analyzer std: " + str(numpy.std(packet_array, axis=1)))


def flow_analyzer(n):
    countdown = COUNT_INIT
    anl = FlowAnalyzer(anomaly_queue)
    flow_time = [] 
    count = 0
    while countdown > 0:
        try:
            while True:
                flow = flow_queue.get_nowait()
                #print(flow)
                start = timeit.default_timer()
                anl.analyze(flow)
                flow_time.append(timeit.default_timer() - start)
                count += 1
                countdown = COUNT_INIT
                gevent.sleep(0)
        except Empty:
            countdown -= 1
            gevent.sleep(0.01)
    #print('Flow analyzer %s quit!' % (n))
    if count != 0:
        flow_array = numpy.array([flow_time])
        print("Flow analyzer time: " + str(numpy.mean(flow_array, axis=1)))
        print("Flow analyzer num: " + str(len(flow_time)))
        print("Flow analyzer std: " + str(numpy.std(flow_array, axis=1)))


def operation_analyzer(n):
    countdown = COUNT_INIT
    anl = OperationAnalyzer(anomaly_queue)
    operation_time = [] 
    count = 0
    while countdown > 0:
        try:
            while True:
                operation = operation_queue.get_nowait()
                #print(operation)
                start = timeit.default_timer()
                anl.analyze(operation)
                operation_time.append(timeit.default_timer() - start)
                count += 1
                countdown = COUNT_INIT
                gevent.sleep(0)
        except Empty:
            countdown -= 1
            gevent.sleep(0.01)
    #print('Operation analyzer %s quit!' % (n))
    if count != 0:
        operation_array = numpy.array([operation_time])
        print("Operation analyzer time: " + str(numpy.mean(operation_array, axis=1)))
        print("Operation analyzer num: " + str(len(operation_time)))
        print("Operation analyzer std: " + str(numpy.std(operation_array, axis=1)))


def data_value_analyzer(n):
    countdown = COUNT_INIT
    anl = DataAnalyzer(anomaly_queue)
    content_time = []
    count = 0
    while countdown > 0:
        try:
            while True:
                data_value = data_value_queue.get_nowait()
                #print(data_value)
                start = timeit.default_timer()
                anl.analyze(data_value)
                content_time.append(timeit.default_timer() - start)
                count += 1
                countdown = COUNT_INIT
                gevent.sleep(0)
        except Empty:
            countdown -= 1
            gevent.sleep(0.01)
    #print('Data value analyzer %s quit!' % (n))
    if count != 0:
        content_array = numpy.array([content_time])
        print("Content analyzer time: " + str(numpy.mean(content_array, axis=1)))
        print("Content analyzer num: " + str(len(content_time)))
        print("Content analyzer std: " + str(numpy.std(content_array, axis=1)))


def anomaly_manager(n):
    countdown = COUNT_INIT
    mng = AnomalyManager(meta_alert_queue)
    manager_time = [] 
    count = 0
    while countdown > 0:
        try:
            while True:
                anomaly = anomaly_queue.get_nowait()
                start = timeit.default_timer()
                mng.manage(anomaly)
                manager_time.append(timeit.default_timer() - start)
                count += 1
                countdown = COUNT_INIT
                gevent.sleep(0)
        except Empty:
            countdown -= 1
            gevent.sleep(0.01)
    #mng.print_alerts()
    mng.stop()
    #print('Anomaly Manager %s quit!' % (n))
    if count != 0:
        manager_array = numpy.array([manager_time])
        print("Anomaly Manager time: " + str(numpy.mean(manager_array, axis=1)))
        print("Anomaly Manager num: " + str(len(manager_time)))
        print("Anomaly Manager std: " + str(numpy.std(manager_array, axis=1)))


def alert_sender(n):
    countdown = COUNT_INIT
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 9998))
    while countdown > 0:
        try:
            while True:
                meta_alert = meta_alert_queue.get_nowait()
                #pprint(meta_alert)
                data = pickle.dumps(meta_alert)
                client.send(data)
                ack = client.recv(512)
                assert(ack == "ACK")
                countdown = COUNT_INIT
                gevent.sleep(0)
        except Empty:
            countdown -= 1
            gevent.sleep(0.01)
    print('Alert sender %s quit!' % (n))
    client.close()


def main():
    if sys.argv[1] == "real":
        print("Real Traffic")
        gevent.joinall([
            gevent.spawn(listener),
            gevent.spawn(packet_parser, 1),
            gevent.spawn(operation_parser, 1),
            gevent.spawn(data_value_parser, 1),
            gevent.spawn(packet_analyzer, 1),
            gevent.spawn(flow_analyzer, 1),
            gevent.spawn(operation_analyzer, 1),
            gevent.spawn(data_value_analyzer, 1),
            gevent.spawn(anomaly_manager, 1),
            gevent.spawn(alert_sender, 1),
        ])
    else:
        print("Simulated Traffic")
        gevent.joinall([
            gevent.spawn(traffic_generator, 1),
            gevent.spawn(packet_analyzer, 1),
            gevent.spawn(flow_analyzer, 1),
            gevent.spawn(operation_analyzer, 1),
            gevent.spawn(data_value_analyzer, 1),
            gevent.spawn(anomaly_manager, 1),
            gevent.spawn(alert_sender, 1),
        ])
 

if __name__ == '__main__': main()
