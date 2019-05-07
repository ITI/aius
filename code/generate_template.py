import copy
from attack_template import AttackTemplate

class TemplateGenerator:

    def __init__(self, correlator, db):
        self.template_dict = dict()
        self.correlator = correlator
        self.db= db
        

    def generate(self):
        # TCP SYN Flooding 
        attack_info = {
            "name": "TCP SYN Flooding",
            "consequense": "Denial of Service",
            "severity": 3,
        }
        tcp_syn_flood = AttackTemplate(
            attack_info,
            self.correlator,
            self.db
        )
        tcp_syn_flood.addNode(
            node_id=0,
            node_name="address scan",
            children=[1],
            alerts=[
                [0.4, {"NEW_ORIG": []}],
                [0.6, {"NEW_RESP": []}],
            ],
            pi=0.02,
        )
        tcp_syn_flood.addNode(
            node_id=1,
            node_name="tcp syn flooding",
            parents=[0],
            q_list=[0.1],
            alerts=[
                [0.7, {"PACKET_AB_TOO_MANY": [], "PACKET_BA_TOO_MANY": []}],
                [0.2, {"PACKET_IAT": [], "OPERATION_TOO_LATE": []}],
                [0.1, {"MEAN_BYTES_AB_TOO_SMALL": [], "MEAN_BYTES_BA_TOO_SMALL": []}],
            ],
        )

        # TCP SYN Flooding (with rule)
        attack_info = {
            "name": "TCP SYN Flooding",
            "consequense": "Denial of Service",
            "severity": 3,
        }
        tcp_syn_flood_rule = AttackTemplate(
            attack_info,
            self.correlator,
            self.db
        )
        tcp_syn_flood_rule.addNode(
            node_id=0,
            node_name="address scan",
            children=[1],
            alerts=[
                [0.4, {"NEW_ORIG": []}],
                [0.6, {"NEW_RESP": []}],
            ],
            pi=0.02,
        )
        tcp_syn_flood_rule.addNode(
            node_id=1,
            node_name="tcp syn flooding",
            parents=[0],
            q_list=[0.1],
            alerts=[
                [0.7, {"PACKET_AB_TOO_MANY": [[["flow.tcp_flag_most", 2]]], "PACKET_BA_TOO_MANY": [[["flow.tcp_flag_most", 2]]]}],
                [0.2, {"PACKET_IAT": [], "OPERATION_TOO_LATE": []}],
                [0.1, {"MEAN_BYTES_AB_TOO_SMALL": [], "MEAN_BYTES_BA_TOO_SMALL": []}],
            ],
        )

        # Data Integrity Attack 
        attack_info = {
            "name": "Data Integrity Attack",
            "consequense": "Tampering of Measurement Data",
            "severity": 2,
        }
        data_integrity = AttackTemplate(
            attack_info,
            self.correlator,
            self.db
        )
        data_integrity.addNode(
            node_id=0,
            node_name="man in the middle",
            children=[2],
            alerts=[
                [1, {"PACKET_IAT": [], "OPERATION_TOO_LATE": []}],
            ],
            pi=0.05,
        )
        data_integrity.addNode(
            node_id=1,
            node_name="compromised node",
            children=[2],
            alerts=[],
            pi=0.03,
        )
        data_integrity.addNode(
            node_id=2,
            node_name="data integrity attack",
            node_type="OR",
            parents=[0, 1],
            q_list=[0.3, 0.05],
            alerts=[
                [1, {"BINARY_FAULT": [], "ANALOG_TOO_LARGE": [], "ANALOG_TOO_SMALL": []}],
            ],
        )

        # Voltage Tampering Attack 
        attack_info = {
            "name": "Voltage Tampering Attack",
            "consequense": "Tampering of Voltage Measurement Data",
            "severity": 2,
        }
        voltage_tampering = AttackTemplate(
            attack_info,
            self.correlator,
            self.db
        )
        voltage_tampering.addNode(
            node_id=0,
            node_name="man in the middle",
            children=[2],
            alerts=[
                [1, {"PACKET_IAT": [], "OPERATION_TOO_LATE": []}],
            ],
            pi=0.05,
        )
        voltage_tampering.addNode(
            node_id=1,
            node_name="compromised node",
            children=[2],
            alerts=[],
            pi=0.03,
        )
        voltage_tampering.addNode(
            node_id=2,
            node_name="voltage tampering attack",
            node_type="OR",
            parents=[0, 1],
            q_list=[0.3, 0.05],
            alerts=[
                [1, {"ANALOG_TOO_LARGE": [[["measurement_type", "Voltage"]]], "ANALOG_TOO_SMALL": [[["measurement_type", "Voltage"]]]}],
            ],
        )

        # Command Injection 
        attack_info = {
            "name": "Command Injection",
            "consequense": "",
            "severity": 3,
        }
        command_injection = AttackTemplate(
            attack_info,
            self.correlator,
            self.db
        )
        command_injection.addNode(
            node_id=0,
            node_name="man in the middle",
            children=[3],
            alerts=[
                [1, {"PACKET_IAT": [], "OPERATION_TOO_LATE": []}],
            ],
            pi=0.05,
        )
        command_injection.addNode(
            node_id=1,
            node_name="address scan",
            children=[2],
            alerts=[
                [0.4, {"NEW_ORIG": []}],
                [0.6, {"NEW_RESP": []}],
            ],
            pi=0.02,
        )
        command_injection.addNode(
            node_id=2,
            node_name="service scan",
            parents=[1],
            q_list=[0.3],
            children=[3],
            alerts=[
                [1, {"NEW_SERVICE": []}],
            ],
        )
        command_injection.addNode(
            node_id=3,
            node_name="command injection",
            node_type="OR",
            parents=[0, 2],
            q_list=[0.3, 0.5],
            alerts=[
                [1, {"NEW_OPERATION": []}],
            ],
        )

        # COLD_RESTART Command Injection 
        attack_info = {
            "name": "COLD_RESTART Command Injection",
            "consequense": "",
            "severity": 3,
        }
        coldrestart_command_injection = AttackTemplate(
            attack_info,
            self.correlator,
            self.db
        )
        coldrestart_command_injection.addNode(
            node_id=0,
            node_name="man in the middle",
            children=[3],
            alerts=[
                [1, {"PACKET_IAT": [], "OPERATION_TOO_LATE": []}],
            ],
            pi=0.05,
        )
        coldrestart_command_injection.addNode(
            node_id=1,
            node_name="address scan",
            children=[2],
            alerts=[
                [0.4, {"NEW_ORIG": []}],
                [0.6, {"NEW_RESP": []}],
            ],
            pi=0.02,
        )
        coldrestart_command_injection.addNode(
            node_id=2,
            node_name="service scan",
            parents=[1],
            q_list=[0.3],
            children=[3],
            alerts=[
                [1, {"NEW_SERVICE": []}],
            ],
        )
        coldrestart_command_injection.addNode(
            node_id=3,
            node_name="COLD_RESTART command injection",
            node_type="OR",
            parents=[0, 2],
            q_list=[0.3, 0.5],
            alerts=[
                [1, {"NEW_OPERATION": [[["operation.fc", 13]]]}],
            ],
        )

        #self.template_dict["TCP SYN Flooding"] = tcp_syn_flood
        #self.template_dict["Command Injection"] = command_injection
        #self.template_dict["Data Integrity Attack"] = data_integrity
        self.template_dict["TCP SYN Flooding (with rule)"] = tcp_syn_flood_rule
        self.template_dict["Voltage Tampering Attack"] = voltage_tampering 
        self.template_dict["COLD_RESTART Command Injection"] = coldrestart_command_injection


    def getTemplates(self):
        rst = dict() 
        for attack_name, template in self.template_dict.iteritems():
            rst[attack_name] = [template.copy()]
        return rst 
