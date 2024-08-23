import argparse
import ipaddress
import random
import socket
import time
import logging
from concurrent.futures import ThreadPoolExecutor

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_udp_packet(protocol):
    logger.debug(f"Generating UDP packet for protocol: {protocol}")
    if protocol == "ntp":
        return b'\x1b' + b'\0' * 47  # NTP mode 3 (client) packet
    elif protocol == "dns":
        return b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
    else:
        logger.warning(f"Unknown protocol: {protocol}")
        return b''  # Empty packet for unknown protocols

def create_udp_socket(src_ip, src_port, dst_ip, dst_port, protocol):
    logger.debug(f"Creating UDP socket: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        logger.error("Permission denied when creating socket")
        raise
    except Exception as e:
        logger.error(f"Error creating socket: {e}")
        raise

    # Construct IP header
    ip_header = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
    ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
    ip_header += b'\x40\x11\x00\x00'  # TTL, Protocol | Header Checksum
    ip_header += socket.inet_aton(src_ip)
    ip_header += socket.inet_aton(dst_ip)
    
    # Construct UDP header
    udp_header = src_port.to_bytes(2, byteorder='big')
    udp_header += dst_port.to_bytes(2, byteorder='big')
    udp_header += b'\x00\x08\x00\x00'  # Length | Checksum (0 for now)
    
    # Payload
    payload = generate_udp_packet(protocol)
    
    # Calculate UDP checksum
    udp_length = len(udp_header) + len(payload)
    udp_header = udp_header[:4] + udp_length.to_bytes(2, byteorder='big') + b'\x00\x00'
    
    pseudo_header = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + b'\x00\x11' + udp_length.to_bytes(2, byteorder='big')
    checksum = calculate_checksum(pseudo_header + udp_header + payload)
    udp_header = udp_header[:6] + checksum.to_bytes(2, byteorder='big')
    
    packet = ip_header + udp_header + payload
    return sock, packet

def calculate_checksum(data):
    checksum = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) + data[i+1]
        else:
            word = data[i] << 8
        checksum += word
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF

def open_close_socket(src_ip, src_port, dst_ip, dst_port, protocol):
    try:
        sock, packet = create_udp_socket(src_ip, src_port, dst_ip, dst_port, protocol)
        logger.debug(f"Sending packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        sock.sendto(packet, (dst_ip, dst_port))
        sock.close()
        logger.debug("Socket closed successfully")
    except Exception as e:
        logger.error(f"Error in open_close_socket: {e}")

def generate_sessions(scenario, dst_ip, dst_subnet, concurrent_sessions, rate):
    logger.info(f"Starting session generation: {scenario}")
    src_ip_pool = tuple(map(str, ipaddress.ip_network('10.0.0.0/8').hosts()))
    dst_ips = (dst_ip,) if dst_ip else tuple(map(str, ipaddress.ip_network(dst_subnet).hosts()))
    
    total_sessions = concurrent_sessions
    sessions_per_second = rate
    
    logger.info(f"Generating {total_sessions} sessions at a rate of {sessions_per_second} sessions/second")
    estimated_time = total_sessions / sessions_per_second
    logger.info(f"Generating {total_sessions} sessions at a rate of {sessions_per_second} sessions/second")
   
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=min(1000, sessions_per_second)) as executor:
        for i in range(total_sessions):
            src_ip = src_ip_pool[i % len(src_ip_pool)]
            src_port = random.randint(15000, 30000)
            dst_ip = random.choice(dst_ips)
            dst_port = 123 if random.choice(['ntp', 'dns']) == 'ntp' else 53
            protocol = 'ntp' if dst_port == 123 else 'dns'
            
            executor.submit(open_close_socket, src_ip, src_port, dst_ip, dst_port, protocol)
            
            if (i + 1) % sessions_per_second == 0:
                time.sleep(max(0, 1 - (time.time() - (start_time + i // sessions_per_second))))
    
    end_time = time.time()
    logger.info(f"Actual time taken: {end_time - start_time:.2f} seconds")

def main():
    parser = argparse.ArgumentParser(description="UDP Session Generator for Palo Alto NAT Testing")
    parser.add_argument("scenario", choices=["65K", "512K", "4M"], help="Testing scenario")
    parser.add_argument("--dst_ip", help="Destination IP for 65K scenario")
    parser.add_argument("--dst_subnet", help="Destination subnet for 512K and 4M scenarios")
    args = parser.parse_args()

    logger.info(f"Starting script with scenario: {args.scenario}")

    try:    
        if args.scenario == "65K":
            dst_ip = args.dst_ip or "192.168.69.69"
            generate_sessions(args.scenario, dst_ip, None, 65000, 10000)
        elif args.scenario == "512K":
            dst_subnet = args.dst_subnet or "192.168.68.0/22"
            generate_sessions(args.scenario, None, dst_subnet, 512000, 10000)
        elif args.scenario == "4M":
            dst_subnet = args.dst_subnet or "192.168.64.0/18"
            generate_sessions(args.scenario, None, dst_subnet, 4000000, 10000)
    except Exception as e:
        logger.error(f"An error occurred during script execution: {e}")

if __name__ == "__main__":
    main()