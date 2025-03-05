#!/usr/bin/env python3
"""
Network Packet Dumper

This tool can be used to dump complete network packets for debugging
the Gateway Router application's HTTP traffic.
"""

import argparse
import socket
import sys
import time
import logging
from datetime import datetime

try:
    import scapy.all as scapy
except ImportError:
    print("Scapy not installed. Install with: pip install scapy")
    print("Note: This tool is optional and not required for the Gateway Router.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('packet_dump.log')
    ]
)
logger = logging.getLogger('PacketDumper')

def packet_callback(packet):
    """Process each captured packet."""
    if packet.haslayer(scapy.TCP) and (packet.haslayer(scapy.Raw) or packet.haslayer(scapy.HTTP)):
        # Get source and destination information
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
        
        # Log basic packet info
        timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')
        logger.info(f"[{timestamp}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        
        # Try to extract HTTP data if present
        if packet.haslayer(scapy.Raw):
            try:
                payload = packet[scapy.Raw].load
                payload_str = payload.decode('utf-8', errors='replace')
                
                # Check if this is HTTP traffic
                if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'HTTP/')):
                    logger.info(f"HTTP Data: {payload_str[:1000]}")
                else:
                    # Log first part of payload for any TCP traffic
                    logger.debug(f"TCP Data: {payload_str[:500]}")
            except Exception as e:
                logger.error(f"Error processing packet payload: {str(e)}")

def start_capture(interface, port, duration):
    """Start packet capture on the specified interface and port."""
    logger.info(f"Starting packet capture on interface {interface}, port {port} for {duration} seconds")
    
    # BPF filter to capture only traffic on the specified port
    filter_str = f"tcp port {port}"
    
    try:
        # Start sniffing
        scapy.sniff(
            iface=interface,
            filter=filter_str,
            prn=packet_callback,
            store=0,
            timeout=duration
        )
    except KeyboardInterrupt:
        logger.info("Packet capture stopped by user")
    except Exception as e:
        logger.error(f"Error during packet capture: {str(e)}")

def main():
    """Main entry point for the packet dumper."""
    parser = argparse.ArgumentParser(description='Network Packet Dumper for Gateway Router')
    parser.add_argument('--interface', '-i', default='eth0', help='Network interface to capture on')
    parser.add_argument('--port', '-p', type=int, default=8080, help='Port to capture traffic on')
    parser.add_argument('--duration', '-d', type=int, default=60, help='Duration of capture in seconds')
    args = parser.parse_args()
    
    start_capture(args.interface, args.port, args.duration)

if __name__ == "__main__":
    main()