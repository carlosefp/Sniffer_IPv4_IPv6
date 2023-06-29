import socket
import struct
import sys
import textwrap
import keyboard as kb


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '


DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '




class HTTP:


   def __init__(self, raw_data):
       try:
           self.data = raw_data.decode('utf-8')
       except:
           self.data = raw_data




def main():
   try:
       sockFD = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))


   except socket.error:
       print('Failed to create a socket')
       sys.exit()


   print('Socket created')
   arquivo = open('dadosRede.txt', 'w')
   count = True


   while True:
       if kb.is_pressed('e'):
           arquivo.close()
           break


       raw_data, addr = sockFD.recvfrom(65536)
       dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
       
       if count:
           print('Gerando dados... ')
           count = False


       # Check for IPV4
       if eth_proto == 8:
           version, header_length, ttl, proto, src, target, total_length, identification, flags_offset, checksum = ipv4_packet(data)

           arquivo.write('\n' + TAB_1 + 'IPv4 Packet:')
           arquivo.write('\n' + TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
           arquivo.write('\n' + TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
           arquivo.write('\n' + TAB_2 + 'Total Length: {}'.format(total_length))
           arquivo.write('\n' + TAB_2 + 'Identificador: {}, Flags: {}'.format(identification, flags_offset))


           if proto == 1:
               icmp_type, code, checksum, data = icmp_packet(data)
               arquivo.write('\n' + TAB_1 + 'ICMP Packet:')
               arquivo.write('\n' + TAB_2 + 'Type: {}, Code: {}, Checksum: {}, '.format(icmp_type, code, checksum))
               arquivo.write('\n' + TAB_2 + 'Data:')
               arquivo.write('\n' + format_multi_line(DATA_TAB_3, data))




           # TCP
           elif proto == 6:
               src_port, dest_port, sequence, ack, offset_reserved_flags, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(
                   data)
               arquivo.write('\n' + TAB_1 + 'TCP Segment:')
               arquivo.write('\n' + TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
               arquivo.write('\n' + TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, ack))
               arquivo.write('\n' + TAB_2 + 'Flags:')
               arquivo.write('\n' + TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
               arquivo.write('\n' + TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))
               arquivo.write('\n' + TAB_2 + 'Data:')


               if len(data) > 0:


                   # HTTP
                   if src_port == 80 or dest_port == 80:
                       arquivo.write('\n' + TAB_2 + 'HTTP Data:')
                       try:
                           http = HTTP(data)
                           http_info = str(http.data).split('\n')
                           for line in http_info:
                               arquivo.write('\n' + DATA_TAB_3 + str(line))
                       except:
                           arquivo.write('\n' + format_multi_line(DATA_TAB_3, data))


           # UDP
           elif proto == 17:
               src_port, dest_port, size, data = udp_segment(data)
               arquivo.write('\n' + TAB_1 + 'UDP Segment:')
               arquivo.write(
                   '\n' + TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}\n UDP Data: {}'.format(src_port,
                                                                                                            dest_port,
                                                                                                            size,
                                                                                                            data))


           # Other IPv4
           else:
               arquivo.write('\n' + TAB_1 + '\nOther IPv4 Data:')
               arquivo.write('\n' + format_multi_line(DATA_TAB_2, data))


       if eth_proto == 56710:
           version, traffic_flow, payload_length, next_header, hop_limit, src, target, data = ipv6_packet(data)
           arquivo.write('\n' + TAB_1 + 'IPv6 Packet:')
           arquivo.write(
               '\n' + TAB_2 + 'Version: {}, Traffic Flow: {}, Payload Length: {}'.format(version, traffic_flow,
                                                                                         payload_length))
           arquivo.write('\n' + TAB_2 + 'Hop Limit: {}, Source: {}, Target: {}'.format(hop_limit, src, target))
           arquivo.write('\n' + TAB_2 + 'NEXT HEADER: {}'.format(next_header))

           if next_header == 58:
               icmp_type, code, checksum, data = icmp_packet(data)
               arquivo.write('\n' + TAB_1 + 'ICMP Packet:')
               arquivo.write('\n' + TAB_2 + 'Type: {}, Code: {}, Checksum: {}, '.format(icmp_type, code, checksum))
               arquivo.write('\n' + TAB_2 + 'Data:')
               arquivo.write('\n' + format_multi_line(DATA_TAB_3, data))


           # TCP
           elif next_header == 6:
               src_port, dest_port, sequence, ack, offset_reserved_flags, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(
                   data)
               arquivo.write('\n' + TAB_1 + 'TCP Segment:')
               arquivo.write('\n' + TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
               arquivo.write('\n' + TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, ack))
               arquivo.write('\n' + TAB_2 + 'Flags:')
               arquivo.write('\n' + TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
               arquivo.write('\n' + TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))
               arquivo.write('\n' + TAB_2 + 'Data:')


               if len(data) > 0:


                   # HTTP
                   if src_port == 80 or dest_port == 80:
                       arquivo.write('\n' + TAB_2 + '\nHTTP Data:')
                       try:
                           http = HTTP(data)
                           http_info = str(http.data).split('\n')
                           for line in http_info:
                               arquivo.write('\n' + DATA_TAB_3 + str(line))
                       except:
                           arquivo.write('\n' + format_multi_line(DATA_TAB_3, data))


           # UDP
           elif next_header == 17:
               src_port, dest_port, size, data = udp_segment(data)
               arquivo.write('\n' + TAB_1 + 'UDP Segment:')
               arquivo.write(
                   '\n' + TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {} \n UDP-Data:'.format(src_port,
                                                                                                          dest_port,
                                                                                                          size, data))


           elif next_header == 33:
               icmp_type, code, checksum, data = icmp_packet(data)
               arquivo.write('\n' + TAB_1 + 'IPv6 Routing Header:')
               arquivo.write('\n' + TAB_2 + 'Type: {}, Code: {}, Checksum: {}, '.format(icmp_type, code, checksum))
               arquivo.write('\n' + TAB_2 + 'Data:')
               arquivo.write('\n' + format_multi_line(DATA_TAB_3, data))


           elif next_header == 46:
               icmp_type, code, checksum, data = icmp_packet(data)
               arquivo.write('\n' + TAB_1 + 'IPv6 Encapsulating Security Payload:')
               arquivo.write('\n' + TAB_2 + 'Type: {}, Code: {}, Checksum: {}, '.format(icmp_type, code, checksum))
               arquivo.write('\n' + TAB_2 + 'Data:')
               arquivo.write('\n' + format_multi_line(DATA_TAB_3, data))




# Unpack the ethernet frame
def ethernet_frame(data):
   dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
   return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]




# Return a formatted mac address (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
   bytes_str = map('{:02x}'.format, bytes_addr)
   return ':'.join(bytes_str).upper()



def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    total_length, identification, flags_frag_offset = struct.unpack('! H H H', data[2:8])
    ttl, proto, checksum = struct.unpack('! B B H', data[8:12])
    src_address = struct.unpack('! 4s', data[12:16])[0]
    target_address = struct.unpack('! 4s', data[16:20])[0]

    src_address = ipv4(src_address)
    target_address = ipv4(target_address)

    return version, header_length, ttl, proto, src_address, target_address, total_length, identification, flags_frag_offset, data[header_length:]


# Return properly formatted IPv4 address
def ipv4(addr):
   return '.'.join(map(str, addr))




# Unpack ICMP packet
def icmp_packet(data):
   icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
   return icmp_type, code, checksum, data[4:]




# Unpacks TCP packet
def tcp_segment(data):
   (src_port, dest_port, sequence, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
   offset = (offset_reserved_flags >> 12) * 4
   flag_urg = (offset_reserved_flags & 32) >> 5
   flag_ack = (offset_reserved_flags & 16) >> 4
   flag_psh = (offset_reserved_flags & 8) >> 3
   flag_rst = (offset_reserved_flags & 4) >> 2
   flag_syn = (offset_reserved_flags & 2) >> 1
   flag_fin = offset_reserved_flags & 1
   return src_port, dest_port, sequence, ack, offset_reserved_flags, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[
                                                                                                                                 offset:]




# Unpack UDP segments
def udp_segment(data):
   src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
   return src_port, dest_port, size, data[:8]




# Format multi-line data
def format_multi_line(prefix, string, size=80):
   size -= len(prefix)
   if isinstance(string, bytes):
       string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
       if size % 2:
           size -= 1
   return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])




def ipv6_packet(data):
   version_traffic_flow = struct.unpack('! I', data[:4])
   version = (version_traffic_flow[0] >> 28) & 0x0F
   traffic_flow = version_traffic_flow[0] & 0xFFFFFFF
   payload_length, next_header, hop_limit = struct.unpack('! H B B', data[4:8])
   src = data[8:24]
   target = data[24:40]
   return version, traffic_flow, payload_length, next_header, hop_limit, ipv6(src), ipv6(target), data[40:]




# Return properly formatted IPv6 address
def ipv6(addr):
   parts = [addr[i:i + 2].hex() for i in range(0, len(addr), 2)]
   return ':'.join(parts)




if __name__ == '__main__':
   # TEM QUE RODAR COMO SUDOER
   main()
   
