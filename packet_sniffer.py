from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
import textwrap

TAB_1 = "\t - "
TAB_2 = "\t\t - "
TAB_3 = "\t\t\t - "
TAB_4 = "\t\t\t\t - "

DATA_TAB_1 = "\t "
DATA_TAB_2 = "\t\t "
DATA_TAB_3 = "\t\t\t "
DATA_TAB_4 = "\t\t\t\t "

def main():
    try:
        sniff(prn=process_packet, store=False)
    except Exception as e:
        print(f"Error: {e}")

def process_packet(packet):
    try:
        if packet.haslayer(Ether):
            eth = packet[Ether]
            print("\nEthernet Frame:")
            print(TAB_1 + "Destination MAC Address: {}, Source MAC Address: {}, Protocol: {}".format(
                eth.dst, eth.src, eth.type))

            if eth.haslayer(IP):
                ip = eth[IP]
                print(TAB_1 + 'IPv4 Packet:')
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(ip.version, ip.ihl, ip.ttl))
                print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ip.proto, ip.src, ip.dst))

                if ip.haslayer(ICMP):
                    icmp = ip[ICMP]
                    print(TAB_1 + 'ICMP Packet:')
                    print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp.type, icmp.code, icmp.chksum))
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, icmp.payload))

                elif ip.haslayer(TCP):
                    tcp = ip[TCP]
                    print(TAB_1 + 'TCP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.sport, tcp.dport))
                    print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(tcp.seq, tcp.ack))
                    print(TAB_2 + "Flags:")
                    print(TAB_3 + 'URG: {}, ACK {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(
                        tcp.flags.U, tcp.flags.A, tcp.flags.P, tcp.flags.R, tcp.flags.S, tcp.flags.F))
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, tcp.payload))

                elif ip.haslayer(UDP):
                    udp = ip[UDP]
                    print(TAB_1 + 'UDP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(
                        udp.sport, udp.dport, udp.len))
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, udp.payload))
    except Exception as e:
        print(f"Error processing packet: {e}")

def format_multi_line(prefix, string, size=80):
    if isinstance(string, bytes):
        string = string.decode(errors='ignore')
    size = max(size, 1)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == "__main__":
    main()
