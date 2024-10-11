import sys
import struct
from packet_struct import *

new_connections = {
    "src_ip": "",
    "dst_ip": "",
    "src_port": 0,
    "dst_port": 0,
    "src_to_dst_packet_count": 0,
    "dst_to_src_packet_count": 0,
    "src_to_dst_byte_count": 0,
    "dst_to_src_byte_count": 0,
    "SYN": 0,
    "ACK": 0,
    "FIN": 0,
    "RST": 0,
    'complete': False,
    'start_time': 0,
    'end_time': 0,
    'duration': 0,
    'total_win': 0,
    'min_win': 0,
    'max_win': 0,
}

# all connections list
connections = []
# global variable
connection = 0

def read_global(f):
    # read global header
    global_header = f.read(24)
    my_global_header = Global_Header()
    my_global_header.get_global_header(global_header)

    endianness = my_global_header.endianness
    return f, endianness

# analyze each packet
def analyze_packet(f, endianness):
    global connection
    global connections
    # read packet header
    try:
        packet_header = f.read(16)
        if not packet_header:
            raise Exception("EOF")
    except:
        raise Exception("EOF")
    
    my_packet_header = Packet_Header()
    my_packet_header.get_packet_header(packet_header, endianness)
    incl_len = my_packet_header.incl_len
    
    # read ethernet header
    f.read(14)
    
    # read ip header
    ip_header = f.read(20)
    my_ip_header = IP_Header()
    my_ip_header.get_IP_header(ip_header)
    ip_optional = my_ip_header.ip_header_len - 20
    if ip_optional > 0:
        f.read(ip_optional)

    # read tcp header
    tcp_header = f.read(20)
    my_tcp_header = TCP_Header()
    my_tcp_header.get_TCP_header(tcp_header)
    tcp_optional = incl_len - my_ip_header.ip_header_len - 14 - 20
    if tcp_optional > 0:
        f.read(tcp_optional)

    # read data
    src_port = my_tcp_header.src_port
    dst_port = my_tcp_header.dst_port
    src_ip = my_ip_header.src_ip
    dst_ip = my_ip_header.dst_ip
    flags = my_tcp_header.flags
    total_len = my_ip_header.total_len
    byte_count = total_len - my_ip_header.ip_header_len - my_tcp_header.data_offset
    window_size = my_tcp_header.window_size
    
    for conn in connections:
        src_ip_conn = conn['src_ip']
        dst_ip_conn = conn['dst_ip']
        src_port_conn = conn['src_port']
        dst_port_conn = conn['dst_port']
        if src_ip == src_ip_conn and dst_ip == dst_ip_conn and src_port == src_port_conn and dst_port == dst_port_conn:
            conn['src_to_dst_packet_count'] += 1
            conn['src_to_dst_byte_count'] += byte_count
            conn['SYN'] += flags['SYN']
            conn['ACK'] += flags['ACK']
            conn['FIN'] += flags['FIN']
            conn['RST'] += flags['RST']
            # end time updates until last FIN
            if flags['FIN'] > 0:
                conn['complete'] = True
                conn['end_time'] = my_packet_header.timestamp
                duration = round(conn['end_time'] - conn['start_time'], 6)
                conn['duration'] = duration
            # window size data of single connection
            conn['total_win'] += window_size
            if window_size < conn['min_win']:
                conn['min_win'] = window_size
            if window_size > conn['max_win']:
                conn['max_win'] = window_size
            break
        if src_ip == dst_ip_conn and dst_ip == src_ip_conn and src_port == dst_port_conn and dst_port == src_port_conn:
            conn['dst_to_src_packet_count'] += 1
            conn['dst_to_src_byte_count'] += byte_count
            conn['SYN'] += flags['SYN']
            conn['ACK'] += flags['ACK']
            conn['FIN'] += flags['FIN']
            conn['RST'] += flags['RST']
            # end time updates until last FIN
            if flags['FIN'] > 0:
                conn['complete'] = True
                conn['end_time'] = my_packet_header.timestamp
                duration = round(conn['end_time'] - conn['start_time'], 6)
                conn['duration'] = duration
            # window size data of single connection
            conn['total_win'] += window_size
            if window_size < conn['min_win']:
                conn['min_win'] = window_size
            if window_size > conn['max_win']:
                conn['max_win'] = window_size
            break
    else:
        # new connection
        new_connections['src_ip'] = src_ip
        new_connections['dst_ip'] = dst_ip
        new_connections['src_port'] = src_port
        new_connections['dst_port'] = dst_port
        new_connections['src_to_dst_packet_count'] = 1
        new_connections['src_to_dst_byte_count'] = byte_count
        new_connections['SYN'] = flags['SYN']
        new_connections['ACK'] = flags['ACK']
        new_connections['FIN'] = flags['FIN']
        new_connections['RST'] = flags['RST']
        new_connections['start_time'] = my_packet_header.timestamp
        new_connections['total_win'] = window_size
        new_connections['min_win'] = window_size
        new_connections['max_win'] = window_size
        connections.append(new_connections.copy())
        connection += 1


def analyze_connection():
    Connection_Info.orig_time = connections[0]['start_time']
    Connection_Info.min_duration = connections[0]['duration']
    Connection_Info.min_packet_number = connections[0]['src_to_dst_packet_count'] + connections[0]['dst_to_src_packet_count']
    total_duration = 0
    total_window_size = 0
    Connection_Info.min_window_size = connections[0]['min_win']
    Connection_Info.max_window_size = connections[0]['max_win']
    
    for conn in connections:
        if conn['complete']:
            Connection_Info.complete_count += 1
            if conn['duration'] < Connection_Info.min_duration:
                Connection_Info.min_duration = conn['duration']
            if conn['duration'] > Connection_Info.max_duration:
                Connection_Info.max_duration = conn['duration']
            packet_number = conn['src_to_dst_packet_count'] + conn['dst_to_src_packet_count']
            Connection_Info.total_packet_number += packet_number
            if packet_number < Connection_Info.min_packet_number:
                Connection_Info.min_packet_number = packet_number
            if packet_number > Connection_Info.max_packet_number:
                Connection_Info.max_packet_number = packet_number
            total_duration += conn['duration']
            Connection_Info.mean_duration = round(total_duration / Connection_Info.complete_count, 6)
            Connection_Info.mean_packet_number = round(Connection_Info.total_packet_number / Connection_Info.complete_count, 6)
            total_window_size += conn['total_win']
            Connection_Info.mean_window_size = round(total_window_size / Connection_Info.total_packet_number, 6)
            if conn['min_win'] < Connection_Info.min_window_size:
                Connection_Info.min_window_size = conn['min_win']
            if conn['max_win'] > Connection_Info.max_window_size:
                Connection_Info.max_window_size = conn['max_win']
        if conn['RST'] > 0:
            Connection_Info.reset_count += 1
        if not conn['complete']:
            Connection_Info.open_count += 1

def print_all():
    print('A) Total number of connections:', connection)
    print('________________________________________________')
    print('')
    print('B) Connections\' details')
    print('')
    print_connection()
    print('C) General')
    print('')
    print('Total number of complete TCP connections:', Connection_Info.complete_count)
    print('Number of reset TCP connections:', Connection_Info.reset_count)
    print('Number of TCP connections that were still open when the trace capture ended:', Connection_Info.open_count)
    print('________________________________________________')
    print('')
    print('D) Complete TCP connections')
    print('')
    print('Minimum time duration:', Connection_Info.min_duration, 'seconds')
    print('Mean time duration:', Connection_Info.mean_duration, 'seconds')
    print('Maximum time duration:', Connection_Info.max_duration, 'seconds')
    print('')
    print('Minimum RTT value:')
    print('Mean RTT value:')
    print('Maximum RTT value:')
    print('')
    print('Minimum number of packets including both send/received:',Connection_Info. min_packet_number)
    print('Mean number of packets including both send/received:', Connection_Info.mean_packet_number)
    print('Maximum number of packets including both send/received:', Connection_Info.max_packet_number)
    print('')
    print('Minimum receive window size including both send/received:', Connection_Info.min_window_size, 'bytes')
    print('Mean receive window size including both send/received:', Connection_Info.mean_window_size, 'bytes')
    print('Maximum receive window size including both send/received:', Connection_Info.max_window_size, 'bytes')
    print('________________________________________________')


def print_connection():
    for conn in connections:
        print('Connection ', connections.index(conn)+1, ':', sep='')
        print('Source Address:', conn['src_ip'])
        print('Destination Address:', conn['dst_ip'])
        print('Source Port:', conn['src_port'])
        print('Destination Port:', conn['dst_port'])
        print('Status: ', end='')
        print('S'+str(conn['SYN'])+'F'+str(conn['FIN']), end='')
        if conn['RST'] > 0:
            print('/R')
        else:
            print('')
        if conn['complete']:
            start= round(conn['start_time'] - Connection_Info.orig_time, 6)
            print('Start Time:', start, 'seconds')
            end = round(conn['end_time'] - Connection_Info.orig_time, 6)
            print('End Time:', end, 'seconds')
            print('Duration:', conn['duration'], 'seconds')
            print('Number of packets sent from Source to Destination:', conn['src_to_dst_packet_count'])
            print('Number of packets sent from Destination to Source:', conn['dst_to_src_packet_count'])
            total_number_of_packets = conn['src_to_dst_packet_count'] + conn['dst_to_src_packet_count']
            total_number_of_bytes = conn['src_to_dst_byte_count'] + conn['dst_to_src_byte_count']
            print('Total number of packets:', total_number_of_packets)
            print('Number of data bytes sent from Source to Destination:', conn['src_to_dst_byte_count'])
            print('Number of data bytes sent from Destination to Source:', conn['dst_to_src_byte_count'])
            print('Total number of data bytes:', total_number_of_bytes)
        print("END")
        if connections.index(conn) != connection - 1:
            print("++++++++++++++++++++++++++++++++")
        else:
            print("________________________________________________")
            print('')

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <trace file>")
        sys.exit(1)
    else:
        trace_file = sys.argv[1]
        f = open(trace_file, "rb")
        f, endianness = read_global(f)
        while True:
            try:
                analyze_packet(f, endianness)
            except:
                break
        analyze_connection()
        print_all()
        f.close()
        


if __name__ == "__main__":
    main()