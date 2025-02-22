import scapy.all as scapy
from scapy.layers.inet import IP
from collections import defaultdict
import statistics
import threading
import time
from datetime import datetime
from traffic_simulator import TrafficSimulator
import random
from ai_analyzer import AISecurityAnalyzer

class NetworkMonitor:
    def __init__(self):
        # Enable libpcap correctly
        scapy.conf.use_pcap = True
        self.packet_counts = defaultdict(int)
        self.packet_sizes = []
        self.baseline_mean = None
        self.baseline_std = None
        self.is_monitoring = False
        # Initialize simulator with synthetic data
        self.simulator = TrafficSimulator()
        self.anomaly_logs = []  # Add this line to store anomaly logs
        self.ai_analyzer = AISecurityAnalyzer()
        
    def simulate_traffic(self, duration=5, inject_anomaly=False):
        """Simulate network traffic"""
        # Clear previous packets for this window
        self.packet_sizes = []
        self.packet_counts.clear()
        
        # Generate normal traffic
        normal_packets = self.simulator.generate_normal_traffic(count=10)
        for packet in normal_packets:
            if scapy.IP in packet:
                src_ip = packet[scapy.IP].src
                self.packet_counts[src_ip] += 1
                self.packet_sizes.append(len(packet))
        
        # Inject anomaly if requested
        if inject_anomaly:
            anomaly_packets = self.simulator.generate_anomaly_traffic(count=5)
            for packet in anomaly_packets:
                if scapy.IP in packet:
                    src_ip = packet[scapy.IP].src
                    self.packet_counts[src_ip] += 1
                    self.packet_sizes.append(len(packet))
    
    def capture_packets(self, interface=None, duration=60):
        """Simulate packet capture instead of real capture"""
        self.simulate_traffic(duration=duration, inject_anomaly=random.random() < 0.2)  # 20% chance of anomaly
    
    def establish_baseline(self, interface=None, duration=60):
        """Establish baseline using simulated normal traffic"""
        print(f"Establishing baseline over {duration} seconds...")
        # Generate more traffic for baseline
        for _ in range(5):  # Generate 5 batches of normal traffic
            normal_packets = self.simulator.generate_normal_traffic(count=20)
            for packet in normal_packets:
                if scapy.IP in packet:
                    src_ip = packet[scapy.IP].src
                    self.packet_counts[src_ip] += 1
                    self.packet_sizes.append(len(packet))
        
        if self.packet_sizes:
            self.baseline_mean = statistics.mean(self.packet_sizes)
            self.baseline_std = statistics.stdev(self.packet_sizes)
            print(f"Baseline established - Mean: {self.baseline_mean:.2f}, Std: {self.baseline_std:.2f}")
        
    def detect_anomalies(self, packet_sizes, threshold=2):
        """Detect anomalies using z-score and provide human-readable explanation"""
        if not self.baseline_mean or not self.baseline_std:
            return False
            
        current_mean = statistics.mean(packet_sizes)
        z_score = abs(current_mean - self.baseline_mean) / self.baseline_std
        
        # If anomaly detected, log it with explanation
        if z_score > threshold:
            # Determine the type and severity of anomaly
            severity = "Moderate" if z_score < 3 else "Severe"
            size_change = "larger" if current_mean > self.baseline_mean else "smaller"
            percent_change = abs((current_mean - self.baseline_mean) / self.baseline_mean * 100)
            
            # Create explanation based on the anomaly characteristics
            explanation = f"""
            {severity} anomaly detected in network traffic:
            • Packet sizes are {size_change} than normal by {percent_change:.1f}%
            • Average packet size is {current_mean:.0f} bytes (normally around {self.baseline_mean:.0f} bytes)
            • This could indicate {'data exfiltration or file transfers' if size_change == 'larger' else 'scanning or probing activity'}
            • Unusual activity from {len(self.packet_counts)} different IP addresses
            """
            
            anomaly_info = {
                'timestamp': datetime.now(),
                'z_score': round(z_score, 2),
                'current_mean': round(current_mean, 2),
                'baseline_mean': round(self.baseline_mean, 2),
                'packet_count': len(packet_sizes),
                'unique_ips': len(self.packet_counts),
                'top_ips': dict(sorted(self.packet_counts.items(), key=lambda x: x[1], reverse=True)[:3]),
                'severity': severity,
                'explanation': explanation.strip()
            }
            
            # Get AI analysis
            ai_analysis = self.ai_analyzer.analyze_anomaly(anomaly_info)
            anomaly_info['ai_analysis'] = ai_analysis
            
            self.anomaly_logs.append(anomaly_info)
            
        return z_score > threshold
        
    def monitor_network(self, interface="en0", window_size=60):
        """Continuous network monitoring"""
        self.is_monitoring = True
        while self.is_monitoring:
            current_packets = []
            print(f"\nMonitoring network traffic - {datetime.now()}")
            
            # Capture packets for window_size seconds
            self.packet_sizes = []
            self.capture_packets(interface, window_size)
            
            if self.packet_sizes:
                is_anomaly = self.detect_anomalies(self.packet_sizes)
                if is_anomaly:
                    print("⚠️ ANOMALY DETECTED! Unusual network behavior observed.")
                    self.print_statistics()
                else:
                    print("Network behavior appears normal.")
                    
    def print_statistics(self):
        """Print current network statistics"""
        print("\nNetwork Statistics:")
        print(f"Total packets captured: {len(self.packet_sizes)}")
        print(f"Unique IPs: {len(self.packet_counts)}")
        print("Top 5 IP sources by packet count:")
        for ip, count in sorted(self.packet_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count} packets")

def main():
    print("Available interfaces:", scapy.get_if_list())
    
    interface = "lo0"  # Changed to loopback interface for testing
    monitor = NetworkMonitor()
    
    print("Establishing baseline over 30 seconds...")
    monitor.establish_baseline(duration=30)
    
    # Start monitoring
    try:
        monitor.monitor_network(window_size=30)
    except KeyboardInterrupt:
        print("\nStopping network monitor...")
        monitor.is_monitoring = False

if __name__ == "__main__":
    main() 