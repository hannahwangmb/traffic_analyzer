import struct
import sys

class Global_Header:
    magic_number = None #<type 'int'>
    version_major = None #<type 'int'>
    version_minor = None #<type 'int'>
    thiszone = None #<type 'int'>
    sigfigs = 0 #<type 'int'>
    snaplen = None #<type 'int'>
    network = None #<type 'int'>
    endianness = None #<type 'str'>
    
    def __init__(self):
        self.magic_number = None
        self.version_major = None
        self.version_minor = None
        self.thiszone = None
        self.sigfigs = None
        self.snaplen = None
        self.network = None
        self.endianness = None

    def __str__(self):
        attributes = "\n".join(f"{key}: {value}" for key, value in self.__dict__.items())
        return f"{self.__class__}:\n{attributes}"
 
    def magic_number_set(self, magic_number):
        self.magic_number = magic_number

    def version_major_set(self, version_major):
        self.version_major = version_major

    def version_minor_set(self, version_minor):
        self.version_minor = version_minor

    def thiszone_set(self, thiszone):
        self.thiszone = thiszone

    def sigfigs_set(self, sigfigs):
        self.sigfigs = sigfigs

    def snaplen_set(self, snaplen):
        self.snaplen = snaplen

    def network_set(self, network):
        self.network = network

    def endianness_set(self, endianness):
        self.endianness = endianness

    def get_magic_number(self, buffer):
        # buffer is the bytes object for the magic number
        # magic number is the first 4 bytes in the global header
        self.magic_number_set(struct.unpack('I', buffer)[0])
        return None
    
    def get_version_major(self, buffer):
        # buffer is the bytes object for the version major
        # version major is the 2 bytes after the magic number
        format_string = self.endianness + 'H'
        self.version_major_set(struct.unpack(format_string, buffer)[0])
        return None
    
    def get_version_minor(self, buffer):
        # buffer is the bytes object for the version minor
        # version minor is the 2 bytes after the version major
        format_string = self.endianness + 'H'
        self.version_minor_set(struct.unpack(format_string, buffer)[0])
        return None
    
    def get_thiszone(self, buffer):
        # buffer is the bytes object for the thiszone
        # thiszone is the 4 bytes after the version minor
        format_string = self.endianness + 'I'
        self.thiszone_set(struct.unpack(format_string, buffer)[0])
        return None
    
    def get_sigfigs(self, buffer):
        # buffer is the bytes object for the sigfigs
        # sigfigs is the 4 bytes after the thiszone
        format_string = self.endianness + 'I'
        self.sigfigs_set(struct.unpack(format_string, buffer)[0])
        return None
    
    def get_snaplen(self, buffer):
        # buffer is the bytes object for the snaplen
        # snaplen is the 4 bytes after the sigfigs
        format_string = self.endianness + 'I'
        self.snaplen_set(struct.unpack(format_string, buffer)[0])
        return None
    
    def get_network(self, buffer):
        # buffer is the bytes object for the network
        # network is the 4 bytes after the snaplen
        format_string = self.endianness + 'I'
        self.network_set(struct.unpack(format_string, buffer)[0])
        return None
    
    def get_endianness(self):
        # check the endianness of the magic number
        if self.magic_number == 0xD4C3B2A1:
            # big endian
            self.endianness_set(">")
        elif self.magic_number == 0xA1B2C3D4:
            # little endian
            self.endianness_set("<")
        else:
            print("Error: invalid magic number")
            sys.exit(1)
        return None

    def get_global_header(self, buffer):
        # buffer is the bytes object for the global header
        # get the magic number, version major, version minor, thiszone, sigfigs, snaplen, network
        self.get_magic_number(buffer[0:4])
        self.get_endianness()
        self.get_version_major(buffer[4:6])
        self.get_version_minor(buffer[6:8])
        self.get_thiszone(buffer[8:12])
        self.get_sigfigs(buffer[12:16])
        self.get_snaplen(buffer[16:20])
        self.get_network(buffer[20:24])
        return None

class Packet_Header:
    ts_sec = None #<type 'int'>
    ts_usec = None #<type 'int'>
    incl_len = None #<type 'int'>
    orig_len = None #<type 'int'>
    timestamp = 0
    
    def __init__(self):
        self.ts_sec = None
        self.ts_usec = None
        self.incl_len = None
        self.orig_len = None
        self.timestamp = 0

    def __str__(self):
        attributes = "\n".join(f"{key}: {value}" for key, value in self.__dict__.items())
        return f"{self.__class__}:\n{attributes}"
    
    def ts_sec_set(self, ts_sec):
        self.ts_sec = ts_sec
        
    def ts_usec_set(self, ts_usec):
        self.ts_usec = ts_usec
        
    def incl_len_set(self, incl_len):
        self.incl_len = incl_len
        
    def orig_len_set(self, orig_len):
        self.orig_len = orig_len
        
    def get_ts_sec(self, buffer, endianness):
        # buffer is the bytes object for the ts_sec
        # ts_sec is the first 4 bytes in the packet header
        format_string = endianness + 'I'
        self.ts_sec_set(struct.unpack(format_string, buffer)[0])
        return None
    
    def get_ts_usec(self, buffer, endianness):
        # buffer is the bytes object for the ts_usec
        # ts_usec is the 4 bytes after the ts_sec
        format_string = endianness + 'I'
        self.ts_usec_set(struct.unpack(format_string, buffer)[0])
        return None
    
    def timestamp_set(self):
        #buffer1: the bytes object for ts_sec
        #buffer2: the bytes object for ts_usec
        self.timestamp = round(self.ts_sec+self.ts_usec*0.000001,6)
        #print(self.timestamp,self.packet_No)
    
    def get_incl_len(self, buffer, endianness):
        # buffer is the bytes object for the incl_len
        # incl_len is the 4 bytes after the ts_usec
        format_string = endianness + 'I'
        self.incl_len_set(struct.unpack(format_string, buffer)[0])
        return None
    
    def get_orig_len(self, buffer, endianness):
        # buffer is the bytes object for the orig_len
        # orig_len is the 4 bytes after the incl_len
        format_string = endianness + 'I'
        self.orig_len_set(struct.unpack(format_string, buffer)[0])
        return None
    
    def get_packet_header(self, buffer, endianness):
        # buffer is the bytes object for the packet header
        # get the ts_sec, ts_usec, incl_len, orig_len
        self.get_ts_sec(buffer[0:4], endianness)
        self.get_ts_usec(buffer[4:8], endianness)
        self.get_incl_len(buffer[8:12], endianness)
        self.get_orig_len(buffer[12:16], endianness)
        self.timestamp_set()
        return None

class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0

    def __str__(self):
        attributes = "\n".join(f"{key}: {value}" for key, value in self.__dict__.items())
        return f"{self.__class__}:\n{attributes}"
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
        
    def get_IP(self,buffer1,buffer2):
        #buffer1 and buffer2 are bytes objects for src and dst fields in IP header
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        # value is the bytes object for the IHL field
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        # buffer is the two-byte total length field in IP header
        # total length = ipv4 header + its payload
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)

    def get_IP_header(self,buffer):
        # buffer is the bytes object for the IP header
        # get the src and dst IP addresses, header length, total length
        self.get_header_len(buffer[0:1])
        self.get_total_len(buffer[2:4])
        self.get_IP(buffer[12:16],buffer[16:20])
        return None

class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size =0
    checksum = 0
    ugp = 0
    
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size =0
        self.checksum = 0
        self.ugp = 0
        

    def __str__(self):
        attributes = "\n".join(f"{key}: {value}" for key, value in self.__dict__.items())
        return f"{self.__class__}:\n{attributes}"
  
    
    def src_port_set(self, src):
        self.src_port = src
        
    def dst_port_set(self,dst):
        self.dst_port = dst
        
    def seq_num_set(self,seq):
        self.seq_num = seq
        
    def ack_num_set(self,ack):
        self.ack_num = ack
        
    def data_offset_set(self,data_offset):
        self.data_offset = data_offset
        
    def flags_set(self,ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin
    
    def win_size_set(self,size):
        self.window_size = size
        
    def get_src_port(self,buffer):
        # get the source port number
        # buffer is the bytes object of the source port number in tcp header(2 bytes)
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        #print(self.src_port)
        return None
    
    def get_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        #print(self.dst_port)
        return None
    
    def get_seq_num(self,buffer):
        #get the sequence number
        #buffer here is the bytes object of the seq number (4 bytes
        seq = struct.unpack(">I",buffer)[0]
        self.seq_num_set(seq)
        #print(seq)
        return None
    
    def get_ack_num(self,buffer):
        ack = struct.unpack('>I',buffer)[0]
        self.ack_num_set(ack)
        return None
    
    def get_flags(self,buffer):
        # get flags such as SYN, RST, ACK
        # buffer is the bytes object for the 1 byte flag field
        value = struct.unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags_set(ack, rst, syn, fin)
        return None
    
    def get_window_size(self,buffer1,buffer2):
        # set window size
        # buffer1 + buffer2 is the 2-byte window size field in TCP header
        buffer = buffer2+buffer1
        size = struct.unpack('H',buffer)[0]
        self.win_size_set(size)
        return None
        
    def get_data_offset(self,buffer):
        # get the length of the header
        # buffer is the 4-bit data offset field
        value = struct.unpack("B",buffer)[0]
        length = ((value & 240)>>4)*4
        self.data_offset_set(length)
        #print(self.data_offset)
        return None
    
    def relative_seq_num(self,orig_num):
        # calculate the relative seq_num
        # orig_num is the first packet in the trace
        if(self.seq_num>=orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        #print(self.seq_num)
        
    def relative_ack_num(self,orig_num):
        # similar to the above method
        if(self.ack_num>=orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)

    def get_TCP_header(self,buffer):
        # buffer is the bytes object for the TCP header
        # get the src and dst port numbers, sequence number, ack number, data offset, flags, window size
        self.get_src_port(buffer[0:2])
        self.get_dst_port(buffer[2:4])
        self.get_seq_num(buffer[4:8])
        self.get_ack_num(buffer[8:12])
        self.get_data_offset(buffer[12:13])
        self.get_flags(buffer[13:14])
        self.get_window_size(buffer[14:15],buffer[15:16])
        return None

class Connection_Info:
    orig_time = 0
    complete_count = 0
    reset_count = 0
    open_count = 0
    min_duration = 0
    max_duration = 0
    mean_duration = 0
    min_window_size = 0
    max_window_size = 0
    mean_window_size = 0
    min_rtt = 0
    max_rtt = 0
    mean_rtt = 0
    min_packet_number = 0
    max_packet_number = 0
    mean_packet_number = 0
    total_packet_number = 0
