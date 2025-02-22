import pandas as pd
import numpy as np
from scapy.all import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
import random
import time

class TrafficSimulator:
    def __init__(self, normal_data_path=None, anomaly_data_path=None):
        """Initialize with synthetic data"""
        # Create synthetic normal traffic patterns
        self.normal_data = pd.DataFrame({
            'protocol': [6, 17] * 50,  # TCP and UDP
            'length': np.random.normal(500, 100, 100),  # Normal distribution of packet sizes
            'src_port': np.random.randint(1024, 65535, 100),
            'dst_port': np.random.randint(1024, 65535, 100)
        })
        
        # Create synthetic anomaly patterns
        self.anomaly_data = pd.DataFrame({
            'protocol': [6] * 20,  # TCP only
            'length': np.random.normal(1500, 200, 20),  # Larger packets
            'src_port': np.random.randint(1, 1024, 20),  # Well-known ports
            'dst_port': np.random.randint(1, 1024, 20)
        })
        
        self.current_index = 0
        
    def create_packet(self, row):
        """Create a scapy packet from dataset row"""
        # Create basic packet structure
        packet = (
            Ether()/
            IP(
                src=f"192.168.1.{random.randint(1, 254)}", 
                dst=f"192.168.1.{random.randint(1, 254)}"
            )
        )
        
        # Add TCP or UDP layer based on protocol
        if row.get('protocol') == 6:  # TCP
            packet = packet / TCP(
                sport=int(row.get('src_port', random.randint(1024, 65535))),
                dport=int(row.get('dst_port', random.randint(1024, 65535)))
            )
        else:  # UDP
            packet = packet / UDP(
                sport=int(row.get('src_port', random.randint(1024, 65535))),
                dport=int(row.get('dst_port', random.randint(1024, 65535)))
            )
        
        # Add payload to match packet length
        payload_size = int(row.get('length', 64)) - len(packet)
        if payload_size > 0:
            packet = packet / Raw(load='X' * payload_size)
            
        return packet
    
    def generate_normal_traffic(self, count=10):
        """Generate normal traffic packets"""
        packets = []
        for _ in range(count):
            row = self.normal_data.iloc[self.current_index % len(self.normal_data)]
            packets.append(self.create_packet(row))
            self.current_index += 1
        return packets
    
    def generate_anomaly_traffic(self, count=5):
        """Generate anomalous traffic packets"""
        if self.anomaly_data is None:
            # If no anomaly dataset, create synthetic anomalies
            packets = []
            for _ in range(count):
                # Create large packets with unusual ports
                packet = (
                    Ether()/
                    IP(
                        src="192.168.1.100",
                        dst="192.168.1.1"
                    )/
                    TCP(
                        sport=random.randint(1, 1024),
                        dport=random.randint(1, 1024)
                    )/
                    Raw(load='X' * random.randint(1500, 2000))
                )
                packets.append(packet)
            return packets
        else:
            # Use actual anomaly data
            packets = []
            for _ in range(count):
                row = self.anomaly_data.iloc[random.randint(0, len(self.anomaly_data)-1)]
                packets.append(self.create_packet(row))
            return packets 