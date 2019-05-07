import datetime

class Flow:
    def __init__(self,
                start=None,
                end=None,
                orig=None,
                resp=None,
                protocol_type=None,
                service=None,
                tcp_flag_most=None,
                count_pkt_ab=0,
                count_pkt_ba=0,
                mean_bytes_ab=None,
                std_bytes_ab=None,
                mean_bytes_ba=None,
                std_bytes_ba=None,
                mean_iat_ab=None,
                std_iat_ab=None,
                mean_iat_ba=None,
                std_iat_ba=None,
                ):
        self.start = start 
        self.end = end 
        self.orig = orig 
        self.resp = resp 
        self.protocol_type = protocol_type
        self.service = service
        self.tcp_flag_most = tcp_flag_most
        self.count_pkt_ab = count_pkt_ab
        self.count_pkt_ba = count_pkt_ba
        self.mean_bytes_ab = mean_bytes_ab
        self.std_bytes_ab = std_bytes_ab
        self.mean_bytes_ba = mean_bytes_ba
        self.std_bytes_ba = std_bytes_ba
        self.mean_iat_ab = mean_iat_ab
        self.std_iat_ab = std_iat_ab
        self.mean_iat_ba = mean_iat_ba
        self.std_iat_ba = std_iat_ba


    def getDict(self):
        rst = {"start": self.start,
               "end": self.end,
               "orig": self.orig,
               "resp": self.resp,
               "protocol_type": self.protocol_type,
               "serivce": self.service,
               "tcp_flag_most": self.tcp_flag_most,
               "count_pkt_ab": self.count_pkt_ab,
               "count_pkt_ba": self.count_pkt_ba,
               "mean_bytes_ab": self.mean_bytes_ab,
               "std_bytes_ab": self.std_bytes_ab,
               "mean_bytes_ba": self.mean_bytes_ba,
               "std_bytes_ba": self.std_bytes_ba,
               "mean_iat_ab": self.mean_iat_ab,
               "std_iat_ab": self.mean_iat_ab,
               "mean_iat_ba": self.mean_iat_ba,
               "std_iat_ba": self.std_iat_ba}
        return rst


    def __str__(self):
        return '''
    start = {0}
    end = {1}
    orig = {2}
    resp = {3}
    protocol_type = {4}
    service = {5}
    tcp_flag_most = {6}
    count_pkt_ab = {7}
    count_pkt_ba = {8}
    mean_bytes_ab = {9}
    std_bytes_ab = {10}
    mean_bytes_ba = {11}
    std_bytes_ba = {12}
    mean_iat_ab = {13}
    std_iat_ab = {14}
    mean_iat_ba = {15}
    std_iat_ba = {16}
'''.format(
            datetime.datetime.fromtimestamp(self.start),
            datetime.datetime.fromtimestamp(self.end),
            self.orig,
            self.resp,
            self.protocol_type,
            self.service,
            self.tcp_flag_most,
            self.count_pkt_ab,
            self.count_pkt_ba,
            self.mean_bytes_ab,
            self.std_bytes_ab,
            self.mean_bytes_ba,
            self.std_bytes_ba,
            self.mean_iat_ab,
            self.std_iat_ab,
            self.mean_iat_ba,
            self.std_iat_ba,
            ) 
