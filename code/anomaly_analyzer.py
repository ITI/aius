import gevent
import pickle
import socket
import sys
import threading
import timeit
import numpy
from gevent import select
from gevent.queue import Queue, Empty
from pprint import pprint
from analyze_alert import AlertAnalyzer

meta_alert_queue = Queue()
EDMAND_NUM = 1
TIMEOUT = 120 


def alert_receiver(n):
    bind_ip = "127.0.0.1"
    bind_port = 9998

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((bind_ip, bind_port))
    server.listen(5)
    print("Listening on {}:{}".format(bind_ip, bind_port))

    
    def handle_client_connection(client_socket, address):
        print("Accepted connection from {}:{}".format(address[0], address[1]))
        data = client_socket.recv(655350)
        while len(data) > 0:
            meta_alert = pickle.loads(data)
            meta_alert_queue.put_nowait(meta_alert)
            client_socket.send("ACK")
            data = client_socket.recv(655350)
            gevent.sleep(0)
        print("Connection from {}:{} closed".format(address[0], address[1]))


    count = EDMAND_NUM
    while count > 0:
        client_sock, address = server.accept()
        client_handler = threading.Thread(
            target = handle_client_connection,
            args = (client_sock, address,)
        )
        client_handler.start()
        count -= 1
        gevent.sleep(0.01)


def alert_analyzer(n):
    countdown = TIMEOUT/0.01 
    aa = AlertAnalyzer()
    reasoning_time = [] 
    count = 0
    while countdown > 0:
        try:
           while True:
                meta_alert = meta_alert_queue.get_nowait()
                start = timeit.default_timer()
                aa.analyze(meta_alert)
                reasoning_time.append(timeit.default_timer() - start)
                countdown = TIMEOUT/0.01 
                gevent.sleep(0)
        except Empty:
            countdown -= 1 
            gevent.sleep(0.01)
    aa.print_alerts()
    aa.print_candidates()
    print("Alert analyzer {} quit!".format(n))
    if len(reasoning_time) > 0:
        reasoning_array = numpy.array([reasoning_time])
        print("Alert analyzer time: " + str(numpy.mean(reasoning_array, axis=1)))
        print("Alert analyzer num: " + str(len(reasoning_time)))
        print("Alert analyzer std: " + str(numpy.std(reasoning_array, axis=1)))
    

def main():
    gevent.joinall([
        gevent.spawn(alert_receiver, 1),
        gevent.spawn(alert_analyzer, 1),
    ])


if __name__ == '__main__': main()
