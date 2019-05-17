import socket
from struct import pack, unpack
import time

# Pcap defaults:
PCAP_GLOBAL_HEADER_FMT = '@ I H H i I I I '
PCAP_MAGICAL_NUMBER = 2712847316
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 1


def pretty_mac(raw_mac):
    hex_max = map("{:x}".format, raw_mac)
    return ":".join(hex_max).upper()


def pretty_ip(raw_ip):
    str_ip = map(str, raw_ip)
    return ".".join(str_ip)


def extract_ether_header(raw_data):
    data = raw_data[14:]
    header = raw_data[:14]
    raw_recv_mac, raw_send_mac, proto = unpack('! 6s 6s H', header)
    print("Ethernet Header:\nDestination MAC:{}\tSource MAC:{} \t proto:{}".format(pretty_mac(raw_recv_mac), pretty_mac(raw_send_mac), socket.htons(proto)))
    return socket.htons(proto), data


def extract_ip_header(raw_data):
    header = raw_data[:20]
    version_length, tos, length, id, frag, ttl, protocol_num, checksum, raw_src_addr, raw_dest_addr = unpack('! B B H H H B B H 4s 4s', header)

    # first lets calculate version and header_length:
    ip_version = version_length >> 4
    header_length = (version_length & 15) * 4
    data = raw_data[header_length:]

    # and now lets calculate frag offset and flags:
    fragment_offset = frag & 0x3fff
    ip_flag = frag >> 13

    # make ips pretty:
    src_addr = pretty_ip(raw_src_addr)
    dest_addr = pretty_ip(raw_dest_addr)

    # and now printing the whole header:
    print("IP Header:\nIP Version:{}\tHeader Length:{}\tType Of Service:{}\tTotal Packet Length:{}\nID:{}\tIP Flags:{}"
          "\tFragment Offset:{}\nTTL:{}\tProtocol Num.:{}\n"
          "Header Checksum:{}\nSource IP:{}\t Destination IP:{}".format(ip_version, header_length, tos, length, id,
                                                                        ip_flag, fragment_offset, ttl, protocol_num,
                                                                        hex(checksum), src_addr, dest_addr))
    return protocol_num, data


def extract_icmp_header(raw_data):
    data = raw_data[8:]
    first_header = raw_data[:4]
    second_header = raw_data[4:8]
    icmp_type, code, checksum = unpack('! B B H', first_header)
    print("ICMP Header:\nType:{}\tCode:{} \t Checksum:{}\nrest of the header:{}\ndata:{}".
          format(icmp_type, code, hex(checksum), "".join(map("{:x}".format, second_header)).upper(),
                 "".join(map("{:x}".format, data)).upper()))


def extract_udp_header(raw_data):
    data = raw_data[8:]
    header = raw_data[:8]
    src, dest, length, checksum = unpack('! H H H H', header)
    print("UDP Header:\nSource Port:{}\tDestination Port:{} \t Total Length:{}\tChecksum:{}".format(src, dest, length, hex(checksum)))
    return src, dest, data


def extract_tcp_header(raw_data):
    header = raw_data[:20]
    src_port, dest_port, seq_num, ack_num, offset_flags, window_size, checksum, urg_pointer =\
        unpack('! H H I I H H H H', header)

    # first lets calculate app data offset and flags:
    offset = (offset_flags >> 12) * 4
    flags = offset_flags & 0x01ff
    flag_dict = {}

    flag_dict['ns']  = (flags & 0b100000000) >> 8
    flag_dict['cwr'] = (flags & 0b010000000) >> 7
    flag_dict['ece'] = (flags & 0b001000000) >> 6
    flag_dict['urg'] = (flags & 0b000100000) >> 5
    flag_dict['ack'] = (flags & 0b000010000) >> 4
    flag_dict['psh'] = (flags & 0b000001000) >> 3
    flag_dict['rst'] = (flags & 0b000000100) >> 2
    flag_dict['syn'] = (flags & 0b000000010) >> 1
    flag_dict['fin'] = (flags & 0b000000001)

    data = raw_data[offset:]
    print("TCP Header:\nSource Port:{}\tDestination Port:{}\nSequence Number:{}\tAck Number:{}\nData Offset:{}\t"
          "Flags:{}\tWindow Size:{}\nChecksum:{}\t Urgent Pointer:{}".format(src_port, dest_port, seq_num, ack_num,
                                                                             offset, flag_dict, window_size, hex(checksum),
                                                                             urg_pointer))
    return src_port, dest_port, data


def extract_dns_header(app_data):
    header = app_data[:12]
    data = app_data[12:]
    id, control, q_count, ans_count, auth_count, add_count = unpack('! H H H H H H', header)

    # now lets split control bits:
    mes_type = 'query'
    if control >> 15 is 1:
        mes_type = 'response'
    opcode = (control & 0x7fff) >> 11
    aa = bool(control & 0x0400)
    tc = bool(control & 0x0200)
    rd = bool(control & 0x0100)
    ra = bool(control & 0x0080)
    rcode = control & 0x000f
    print("DNS Header:\nmessage Id:{}\tmessage type: {}\nopcode:{}\trcode:{}\nAuthenticative Answer:{}\tTruncuated:{}\t"
          "Recursion Desired:{}\tRecursion Available:{}\n#Questions={}\t#Answers={}\t#Authority={}\t#Additional={}".
          format(id, mes_type, opcode, rcode, aa, tc, rd, ra, q_count, ans_count, auth_count, add_count))
    # know lets see the data:
    # question:
    k = data[0]
    qname = []
    while k > 0:
        qname.append(data[1:k+1].decode('ascii'))
        data = data[k+1:]
        k = data[0]
    # skipping the zero:
    data = data[1:]
    qtype, qclass = unpack('H H', data[:4])
    print("Questions:\nquery:{}\tType:{}\tClass:{}".format(".".join(qname), qtype, qclass))
    # answers
    #....................................................................................................
    return


def extract_arp_header(raw_data):
    h_type, p_type, h_len , p_len , oper,  = unpack('! H H B B H', raw_data[:8])
    sender_h_addr, sender_p_addr, target_h_addr, target_p_addr = unpack('! {}s {}s {}s {}s'.format(h_len, p_len, h_len, p_len), raw_data[8:])

    # make ips pretty:
    sender_p_addr = pretty_ip(sender_p_addr)
    target_p_addr = pretty_ip(target_p_addr)

    # make macs pretty:
    sender_h_addr = pretty_mac(sender_h_addr)
    target_h_addr = pretty_mac(target_h_addr)
    if oper == 1:
        oper = 'request'
    else:
        oper = 'reply'
    if h_type == 1:
        h_type = 'Ethernet'
    if p_type == 0x0800:
        p_type = 'Ip'
    # and now printing the whole data:

    print("ARP Header:\nHardware Type:{}\t\tHardware addr length:{}\nProtocol Type:{}\t\tProtocol addr length:{}\n"
          "Operation:{}\nSender addresses: {} : {}\tTarget addresses: {} : {}".format(h_type, h_len, p_type, p_len, oper,
                                                                                sender_p_addr, sender_h_addr,
                                                                                target_p_addr, target_h_addr))


def extract_http_header(app_data):
    print("HTTP Message:")
    print_data = ""
    app_data_copy = app_data
    while True:
        itr = app_data.find("\r\n".encode())
        if itr < 0:
            if len(print_data):
                print(print_data)
            if len(app_data):
                print(app_data)
            return
        else:
            try:
                print_data = print_data + app_data[:itr + 2].decode()
            except:
                print(app_data_copy)
                return
            app_data = app_data[itr + 2:]


#
# def extract_http_header(app_data):
#     print("HTTP Message:")
#     itr = app_data.find("\r\n\r\n".encode())
#     if itr < 0:
#         print(app_data)
#     else:
#         print(app_data[:itr+4].decode(), app_data[itr+4:])


def extract_ftp_header(app_data):
    print("FTP Message:")
    itr = app_data.find("\r\n".encode())
    if itr < 0:
        print(app_data)
    else:
        print(app_data[:itr + 2].decode(), app_data[itr + 2:])


class Pcap:
    def __init__(self, filename, link_type=PCAP_DATA_LINK_TYPE):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(
            pack('@ I H H i I I I ', PCAP_MAGICAL_NUMBER, PCAP_MJ_VERN_NUMBER, PCAP_MI_VERN_NUMBER, PCAP_LOCAL_CORECTIN,
                 PCAP_ACCUR_TIMSTAMP, PCAP_MAX_LENGTH_CAP, link_type))
        print("[+] Link Type : {}".format(link_type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()


if __name__ == "__main__":
    # creating a sniffing socket:
    comm = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    mypcap = Pcap("dump.pcap")
    while True:
        raw_data = comm.recv(65535)
        mypcap.write(raw_data)
        print("###########Frame###########")
        # unpacking raw data step by step:
        # Ethernet Header first:
        ether_proto, raw_data = extract_ether_header(raw_data)
        if ether_proto == 8:
            # next is ip header :
            protocol_num, raw_data = extract_ip_header(raw_data)
            if protocol_num == 1:
                # last unpacking with ICMP header extractor:
                extract_icmp_header(raw_data)
            elif protocol_num == 6:
                # next is tcp header:
                source_port, dest_port, app_data = extract_tcp_header(raw_data)
                # last unpacking for tcp occurs if its a HTTP or FTP application data:
                if source_port == 80 or dest_port == 80:
                    extract_http_header(app_data)
                elif source_port == 20 or dest_port == 20 or source_port == 21 or dest_port == 21:
                    extract_ftp_header(app_data)
                else:
                    print("".join(map("{:x}".format, app_data)).upper())

            elif protocol_num == 17:
                # next is udp header:
                source_port, dest_port, app_data = extract_udp_header(raw_data)
                # last unpacking for udp occurs if its a DNS application data:
                if source_port == 53 or dest_port == 53:
                    extract_dns_header(app_data)
                else:
                    print("".join(map("{:x}".format, app_data)).upper())

        elif ether_proto == 1544:
            extract_arp_header(raw_data)
        print("\n\n")