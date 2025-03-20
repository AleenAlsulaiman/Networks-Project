import scapy.all as scapy
from collections import defaultdict
import threading
import time
import logging
import matplotlib.pyplot as plt
import signal
import sys
from typing import Dict, List, Set, Tuple

# Logging setup
logging.basicConfig(
    filename="network_events.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)


class TrafficMonitor:
    def __init__(self):
        """Initialize data structures for monitoring network traffic."""
        self.data_volume = defaultdict(int)  # Track total data volume per protocol
        self.connection_timestamps: Dict[Tuple[str, str], Dict[str, float]] = {}  # Latency tracking
        self.observed_ips: Set[str] = set()  # Unique IP addresses
        self.observed_macs: Set[str] = set()  # Unique MAC addresses
        self.packet_details: Dict[str, List[int]] = defaultdict(list)  # Packet sizes by protocol

        self.throughput_tracker = defaultdict(list)  # Throughput over time
        self.delay_records = []  # Latency data
        self.protocol_activity = defaultdict(int)  # Count packets by protocol

        self.shutdown_flag = threading.Event()  # Flag to terminate monitoring
        self.capture_start = time.time()  # Start time for capturing packets

    def monitor_traffic(self):
        """Start monitoring traffic."""
        signal.signal(signal.SIGINT, self.terminate)
        stats_thread = threading.Thread(target=self.display_stats_periodically)
        stats_thread.start()

        try:
            print("Monitoring traffic... Press Ctrl+C to stop.")
            scapy.sniff(prn=self.analyze_packet, store=False, filter="ip")
        except Exception as err:
            logging.error(f"Error during monitoring: {err}")
            self.cleanup()

    def analyze_packet(self, pkt):
        """Analyze each captured packet and update metrics."""
        try:
            current_time = time.time()

            # Extract Ethernet data
            if pkt.haslayer(scapy.Ether):
                mac_src = pkt[scapy.Ether].src
                mac_dest = pkt[scapy.Ether].dst
                self.update_traffic("Ethernet", mac_src, mac_dest, len(pkt), current_time)

            # Extract IP data
            if pkt.haslayer(scapy.IP):
                ip_src = pkt[scapy.IP].src
                ip_dest = pkt[scapy.IP].dst
                self.update_traffic("IP", ip_src, ip_dest, len(pkt[scapy.IP]), current_time)

                # TCP Protocol
                if pkt.haslayer(scapy.TCP):
                    self.protocol_activity["TCP"] += 1
                    self.update_traffic(
                        "TCP",
                        f"{ip_src}:{pkt[scapy.TCP].sport}",
                        f"{ip_dest}:{pkt[scapy.TCP].dport}",
                        len(pkt[scapy.TCP]),
                        current_time,
                    )

                # UDP Protocol
                elif pkt.haslayer(scapy.UDP):
                    self.protocol_activity["UDP"] += 1
                    self.update_traffic(
                        "UDP",
                        f"{ip_src}:{pkt[scapy.UDP].sport}",
                        f"{ip_dest}:{pkt[scapy.UDP].dport}",
                        len(pkt[scapy.UDP]),
                        current_time,
                    )

                # Log packet details
                logging.info(
                    f"Packet - Src: {ip_src}, Dst: {ip_dest}, Protocol: {pkt[scapy.IP].proto}, "
                    f"Size: {len(pkt)} bytes"
                )

        except Exception as err:
            logging.error(f"Error analyzing packet: {err}")

    def update_traffic(
        self, protocol: str, src: str, dest: str, pkt_size: int, timestamp: float
    ):
        """Update traffic data and latency metrics."""
        self.data_volume[protocol] += pkt_size
        elapsed = timestamp - self.capture_start
        self.throughput_tracker[protocol].append((elapsed, pkt_size))

        if protocol == "Ethernet":
            self.observed_macs.update([src, dest])
        else:
            self.observed_ips.update([src, dest])

        self.packet_details[protocol].append(pkt_size)

        if protocol in ["TCP", "UDP"]:
            connection_key = (src, dest)
            if connection_key not in self.connection_timestamps:
                self.connection_timestamps[connection_key] = {"start": timestamp}
            else:
                latency = (timestamp - self.connection_timestamps[connection_key]["start"]) * 1000
                self.delay_records.append(latency)
                self.connection_timestamps[connection_key] = {"start": timestamp}

    def display_stats_periodically(self):
        """Display metrics periodically."""
        while not self.shutdown_flag.is_set():
            print("\n--- Network Statistics ---")
            print(f"Unique IPs: {len(self.observed_ips)}")
            print(f"Unique MACs: {len(self.observed_macs)}")
            self.calculate_throughput()
            self.calculate_latency()
            time.sleep(30)

    def calculate_throughput(self, interval: int = 10):
        """Calculate and print throughput for each protocol."""
        print("\n--- Throughput (bps) ---")
        for protocol, total_bytes in self.data_volume.items():
            throughput = (total_bytes * 8) / interval
            self.data_volume[protocol] = 0  # Reset data volume
            print(f"{protocol}: {throughput:.2f} bps")

    def calculate_latency(self):
        """Calculate and print average latency."""
        if self.delay_records:
            avg_latency = sum(self.delay_records) / len(self.delay_records)
            print(f"\nAverage Latency: {avg_latency:.2f} ms")
        else:
            print("\nNo latency data available.")

    def visualize_results(self):
        """Generate visualizations for network metrics."""
        try:
            fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 18))

            # Throughput graph
            colors = {"Ethernet": "orange", "IP": "pink", "TCP": "blue", "UDP": "red"}
            for protocol, values in self.throughput_tracker.items():
                if values:
                    times, sizes = zip(*values)
                    cumulative_sizes = [sum(sizes[:i + 1]) for i in range(len(sizes))]
                    ax1.plot(times, cumulative_sizes, label=protocol, color=colors.get(protocol, "purple"))
            ax1.set_title("Throughput Over Time")
            ax1.set_xlabel("Time (s)")
            ax1.set_ylabel("Bytes")
            ax1.legend()

            # Latency histogram
            if self.delay_records:
                ax2.hist(self.delay_records, bins=30, color="pink", edgecolor="black")
                ax2.set_title("Latency Distribution")
                ax2.set_xlabel("Latency (ms)")
                ax2.set_ylabel("Frequency")

            # Protocol activity
            protocols, counts = zip(*self.protocol_activity.items())
            ax3.bar(protocols, counts, color="red")
            ax3.set_title("Protocol Usage")
            ax3.set_xlabel("Protocol")
            ax3.set_ylabel("Packet Count")

            plt.tight_layout()
            plt.savefig("network_analysis.png")
            plt.close()

        except Exception as err:
            logging.error(f"Error visualizing results: {err}")

    def terminate(self, signum, frame):
        """Handle termination signal."""
        print("\nTerminating monitoring...")
        self.cleanup()

    def cleanup(self):
        """Perform cleanup operations."""
        self.shutdown_flag.set()
        self.visualize_results()
        print("Graphs have been successfully saved as 'network_analysis.png'")
        print("Log details have been recorded in 'network_events.log'")
        sys.exit(0)


if __name__ == "__main__":
    monitor = TrafficMonitor()
    monitor.monitor_traffic()

