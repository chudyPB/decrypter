import getopt
import subprocess
import re
import binascii
import socket
import random
import sys
import os
import distutils

from scapy.utils import PcapWriter
from scapy.all import *

class decrypter(object):

	"""Decrypter initialization."""

	def __init__(self, argv):

		#define help msg
		help_msg = """
python decrypter.py -i <input.pcap> -o <output.pcap> options

Type -h or --help for more help.
		"""

		#if no input specified
		if len(argv) == 0:
			print help_msg

		#parse input parameter and define options
		try:
			opts, args = getopt.getopt(argv, 'hsvi:o:m:p:',['help', 'ssl-only', '--version', 'input=', 'output=', 'master=', 'ports='])
		#if exception -> print help msg
		except getopt.GetoptError:
			print help_msg
		#iterate through arguments
		for opt, arg in opts:
			#if -h, --help -> print help
			if opt in ('-h','--help'):
				print """
python decrypter.py -i <input.pcap> -o <output.pcap> options

Command line arguments:

-h, --help 				Print help.
-i, --input     (required)			Input pcap file (pcap to be decrypted).
-m, --master    (required)			Master secret file.
-o, --output    (required)			Output pcap file.
-p, --ports					Ports which will be decrypted (default: all ports). Syntax:
						a) -p- (all ports)
						b) -p port_min-port_max (port range, eg. 21-25)
						c) -p port1,port2,...,portN (specific ports, eg. 21,22,25)
-s, --ssl-only					If set, output pcap will not include unencrypted traffic.
-v, --version 					Run tshark test (if installed + GnuTLS + GnuTLS version).
				"""
				sys.exit()
			#if -i, --input -> save input pcap file path
			elif opt in ('-i', '--input'):
				#check if path exists
				if os.path.isfile(arg):
					#save input file
					self.input = arg
				#if path does not exist -> quit with error
				else:
					sys.exit('Provided input file does not exist!')		
			#if -o, --output -> save output pcap file path
			elif opt in ('-o', '--output'):
				self.output = arg
			#if -m, --master -> save master secret file path
			elif opt in ('-m', '--master'):
				#check if path exists
				if os.path.isfile(arg):
					#save master secret
					self.master = arg
				#if path does not exist -> quit with error
				else:
					sys.exit('Provided master secret file does not exist!')
			#if -p, --ports -> define ports which will be decrypted
			elif opt in ('-p', '--ports'):
				#check syntax provided by user
				#allowed syntax:
				#a) -p - (all ports)
				if arg == '-':
					self.ports = xrange(0, 65536)
				#b) -p 20-25 (port range)
				elif arg.count('-') == 1 and len(arg) > 2:
					try:
						port_min, port_max = arg.split('-')
						self.ports = xrange(int(port_min), int(port_max))
					except:
						pass
				#c) -p 21,22,25,..,80 (specific ports)
				elif ',' in arg:
					ports = list()
					for port in arg.split(','):
						#try to parse the string as int, if not able to parse -> skip
						try:
							ports.append(int(port))
						except:
							print (port + ' could not be parsed as port! Skipping.')
					if len(ports) > 0:
						self.ports = ports

				#if no self.ports -> something is wrong with the syntax
				if not hasattr(self, 'ports'):
					sys.exit('Something is wrong with the provided port syntax.')
			#if -s, --ssl-only -> do not include unencrypted payload in the .pcap
			elif opt in ('-s', '--ssl-only'):
				self.ssl_only = True
			#if -v, --version -> test tshark and print output
			elif opt in ('-v', '--version'):
				self.check_tshark(True)

		#if no input pcap -> exit
		if not hasattr(self, 'input'):
			sys.exit('Input pcap file was not provided!')
		#if no output pcap -> exit
		if not hasattr(self, 'output'):
			sys.exit('Output pcap file was not provided!')
		#if no master secret-> exit
		if not hasattr(self, 'master'):
			sys.exit('Master secret file was not provided!')
		#if no ports specified -> by default decrypt all ports
		if not hasattr(self, 'ports'):
			self.ports = xrange(0, 65536)
		#if no ssl_only flag -> set it to False
		if not hasattr(self, 'ssl_only'):
			self.ssl_only = False

	def check_tshark(self, print_success = False):

		"""This function checks whether tshark is installed
		and if it is compiled with appropriate version of GnuTLS
		Inputs: 
			- print_succes: (True or False) - if True, prints message concerning proper tshark build and quits
		"""

		#try to run tshark -v (Version) -> if no output, probably tshark is not installed
		try:
			out = subprocess.check_output(['tshark', '-v'])
		except:
			sys.exit('Command `tshark -v` provided no output, probably tshark is not installed.')

		#split out and check if GnuTLS with proper version is available
		for dependencies in out.split(','):
			#if `with GnuTLS` in string
			if 'with GnuTLS' in dependencies:
				#get version
				version = dependencies.split(' ')[-1]
				#if version is higher or equal to 2.2.2
				if distutils.version.StrictVersion(version) < distutils.version.StrictVersion('2.2.2'):
					sys.exit('Tshark is compiled with GnuTLS, but GnuTLS version seems to be lower than 2.2.2')
				else:
					if print_success:
						sys.exit('Tshark is compiled with GnuTLS and GnuTLS version is higher or equal to 2.2.2. QUITTING.')
					#quit function and continue with the code
					return
			
		#if GnuTLS not found
		sys.exit('Tshark is installed but it seems that it is not compiled with GnuTLS')

	def gen_handshake(self, source_ip, dest_ip, source_mac, dest_mac, sport, dport):

		"""This function is resposnbile for handshake generation. It generates TCP handshake
		and saves it into specified output .pcap file

		Inputs:
			- source_ip:  string - source IP of TCP connection initializer,
			- dest_ip:    string - destination IP of receiver,
			- source_mac: string - source MAC of TCP connection initializer,
			- dest_mac:   string - destination MAC of receiver,
			- sport:      int    - source port used by initializer,
			- dport:      int    - destination port

		Outputs:
			- seq:        int    - new sequence number
			- ack:        int    - new ack number
		"""

		packet_list = list()

		#get rand seq and ack
		seq = random.randint(1024, (2 ** 32) -1)
		ack = random.randint(1024, (2 ** 32) -1)

		#generate SYN
		packet_list.append(Ether(src = source_mac, dst = dest_mac) / IP(src = source_ip, dst = dest_ip) / TCP(sport = sport, dport = dport, flags = 2, seq = seq, ack = 0))
		#timestamp 
		packet_list[-1].time = self.last_timestamp
		self.last_timestamp += 0.03
		#generate SYN+ACK
		packet_list.append(Ether(src = dest_mac, dst = source_mac) / IP(src = dest_ip, dst = source_ip) / TCP(sport = dport, dport = sport, flags = 18, seq = ack, ack = seq + 1))
		#timestamp 
		packet_list[-1].time = self.last_timestamp
		self.last_timestamp += 0.03		
		#generate ACK
		packet_list.append(Ether(src = source_mac, dst = dest_mac) / IP(src = source_ip, dst = dest_ip) / TCP(sport = sport, dport = dport, flags = 16, seq = seq + 1, ack = ack + 1))
		#timestamp 
		packet_list[-1].time = self.last_timestamp
		self.last_timestamp += 0.03

		for pack in packet_list:
			wrpcap(self.output, pack, append = True)

		return seq + 1, ack + 1

	def append_pcap(self, source_ip, dest_ip, source_mac, dest_mac, sport, dport, pack_list):

		"""This function takes list of packets and appends output .pcap file with new packets.

		Inputs:
			- source_ip:  string - source IP of TCP connection initializer,
			- dest_ip:    string - destination IP of receiver,
			- source_mac: string - source MAC of TCP connection initializer,
			- dest_mac:   string - destination MAC of receiver,
			- sport:      int    - source port used by initializer,
			- dport:      int    - destination port

		"""		

		#generate handshake and get seq,ack numbers
		seq, ack = self.gen_handshake(source_ip, dest_ip, source_mac, dest_mac, sport, dport)

		#for every packet
		for packet in pack_list:
			#if packet sent by source
			if packet['source'] == source_ip:
				new_pack = Ether(src = source_mac, dst = dest_mac) / IP(src = source_ip, dst = dest_ip) / TCP(sport = sport, dport = dport, flags = 24, seq = seq, ack = ack) / packet['payload'].decode('hex')
				#add timestmap
				new_pack.time = packet['timestamp']
				self.last_timestamp = packet['timestamp']

				seq += len(packet['payload'].decode('hex'))
			#if packet sent by dest
			else:
				new_pack = Ether(src = dest_mac, dst = source_mac) / IP(src = dest_ip, dst = source_ip) / TCP(sport = dport, dport = sport, flags = 24, seq = ack, ack = seq) / packet['payload'].decode('hex')
				#add timestmap
				new_pack.time = packet['timestamp']
				self.last_timestamp = packet['timestamp']

				ack += len(packet['payload'].decode('hex'))
			#save packet to pcap
			wrpcap(self.output, new_pack, append=True)

		#close connection -> FIN-ACK
		new_pack = Ether(src = source_mac, dst = dest_mac) / IP(src = source_ip, dst = dest_ip) / TCP(sport = sport, dport = dport, flags = 17, seq = seq, ack = ack)
		#timestamps
		new_pack.time = self.last_timestamp + 0.03
		self.last_timestamp += 0.03
		wrpcap(self.output, new_pack, append=True)		
		
		new_pack = Ether(src = dest_mac, dst = source_mac) / IP(src = dest_ip, dst = source_ip) / TCP(sport = dport, dport = sport, flags = 16, seq = ack, ack = seq + 1)
		#timestamps
		new_pack.time = self.last_timestamp + 0.03
		self.last_timestamp += 0.03
		wrpcap(self.output, new_pack, append=True)	

	def parse_pcap(self):

		"""This function parses input pcap and chooses which packets should be decrypted."""

		#check tshark
		self.check_tshark()
		#call tshark and create output file
		subprocess.call('tshark -r %s -o ssl.keylog_file:%s -o "tcp.relative_sequence_numbers: FALSE" -S "//NEW FRAME//" -Vx >  outfile.txt' % (self.input, self.master), shell=True)

		#initialize dicts
		ssl_dict = dict()
		self.stream_dict = dict()
		#ipv4 regex
		ipv4_regex = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
		#mac regex
		mac_regex = '[a-fA-F0-9][a-fA-F0-9]:[a-fA-F0-9][a-fA-F0-9]:[a-fA-F0-9][a-fA-F0-9]:[a-fA-F0-9][a-fA-F0-9]:[a-fA-F0-9][a-fA-F0-9]:[a-fA-F0-9][a-fA-F0-9]'

		#TLS handshake flag
		#if TLS handshake finish is present in the packet, tshark will add additional 'Decrypted SSL' in the output file.
		#If TLS handshake finish is set, code will check whether it is first or second occurence of 'Decrypted SSL'
		handfinish_flag = False

		#TCP Payload flag (for each stream)
		#check if TCP Payload was present
		payload_flag = dict()

		#SSL Flag (for each stream)
		#check if SSL layer is present
		ssl_flag = dict()

		#open file
		with open('outfile.txt') as f:

			line = f.readline()
			while line:
				#if Frame number -> new packet
				if re.search(r'^Frame \d{1,}:', line):
					# minus 1 -> to have the same indexing as in python
					curr_frame = int(line.split('Frame ')[1].split(':')[0]) - 1
				#if ethernet frame -> get src and dst MAC
				if re.search(r'Ethernet II, Src:',line):
					curr_source_mac, curr_dest_mac = list(set(re.findall(mac_regex, line)))
					# curr_source_mac = ''.join(curr_source_mac.split(':'))
					# curr_dest_mac = ''.join(curr_dest_mac.split(':'))
				#if Epoch time -> get timestamp
				elif re.search(r'    Epoch Time:', line):
					timestamp = float(re.findall(r'[-+]?[0-9]*\.?[0-9]+', line)[0])
				#if source ip -> get source ip
				elif re.search(r'    Source: ' + ipv4_regex, line):
					curr_source_ip = re.findall(ipv4_regex,line)[0]
				#if destination ip -> get source ip
				elif re.search(r'    Destination: ' + ipv4_regex, line):
					curr_dest_ip = re.findall(ipv4_regex, line)[0]
				#if source port -> get current sport
				elif re.search(r'    Source Port: \d{1,5}', line):
					curr_sport = int(line.split('    Source Port: ')[-1])
				#if destination port -> get current dport
				elif re.search(r'    Destination Port: \d{1,5}', line):
					curr_dport = int(line.split('    Destination Port: ')[-1])
				#if stream index -> get current tcp stream
				elif re.search(r'    \[Stream index: \d{1,}\]', line):
					curr_stream = int(line.split('    [Stream index: ')[-1].split(']')[0])			
					#if curr_stream not in dict -> add
					if curr_stream not in self.stream_dict:
						self.stream_dict.update({curr_stream:{'source_ip':curr_source_ip, 'dest_ip':curr_dest_ip, 'source_mac':curr_source_mac, \
							'dest_mac':curr_dest_mac, 'sport':curr_sport, 'dport':curr_dport, 'first_timestamp':timestamp, 'pack_list':list()}})
					#add curr_stream to payload_flag and ssl_flag dictionaries
					payload_flag.update({curr_stream:{'flag':False, 'len': int()}})
					ssl_flag.update({curr_stream:int()})
				#if sequence number -> get current sequence number
				elif re.search(r'    Sequence number: \d{1,}', line):
					curr_seq = int(line.split('Sequence number: ')[1].split(' ')[0])
				#if akcnowledgment number -> get current sequence number
				elif re.search(r'    Acknowledgment number: \d{1,}', line):
					curr_ack = int(line.split('Acknowledgment number: ')[1].split(' ')[0])
				#check if TCP Payload is present
				elif re.search(r'   TCP payload ', line):
					#save payload flag and get length of payload
					payload_flag[curr_stream]['flag'] = True
					payload_flag[curr_stream]['len'] = int(line.split('    TCP payload (')[-1].split(' bytes)')[0])
				#check if SSL layer is present
				elif 'Secure Sockets Layer' == line[0:20]:
					ssl_flag[curr_stream] = True
				#if TLS handshake finish flag
				elif re.search(r'    TLSv1.2 Record Layer: Handshake Protocol: Finished', line):
					handfinish_flag = True
				#if payload string has started 
				elif re.search(r'^[a-fA-F0-9]+$', line[0:4]):
					#if TCP payload and no SSL and ssl_only flag not set-> get unencrypted payload and save payload
					if payload_flag[curr_stream]['flag'] and not ssl_flag[curr_stream] and not self.ssl_only:
						#initialize string for frame_str
						frame_str= str()
						#add bytes to frame
						frame_str += line.split('  ')[1].replace(' ','')
						#read next lines and get payload
						while True:
							#new line
							line = f.readline()
							#if first four characters are numbers -> frame bytes 
							if re.search(r'^[a-fA-F0-9]+$', line[0:4]):
								frame_str += line.split('  ')[1].replace(' ','')
							#if not -> end of frame
							else:
								break				
						#get payload -> substract payload length
						frame_payload = frame_str[len(frame_str) - 2 * payload_flag[curr_stream]['len']::]
						#append payload to pack_list
						self.stream_dict[curr_stream]['pack_list'].append({'frame':curr_frame, 'timestamp':timestamp, 'source':curr_source_ip, 'payload':frame_payload})

						#continue
						continue

				#if Decrypted SSL in the beginning of line and destination port in port list -> decrypted data
				elif 'Decrypted SSL' == line[0:13] and self.stream_dict[curr_stream]['dport'] in self.ports:

					#if TLS handshake finish flag -> reset the flag and skip this payload (description in the beginning of this function)
					if handfinish_flag:
						handfinish_flag = False
						f.readline()
						continue

					#read next lines and append payload
					ssl_dict.update({curr_frame:str()})
					while True:
						#new line
						line = f.readline()
						#if first four characters are numbers -> payload 
						if re.search(r'^[a-fA-F0-9]+$', line[0:4]):
							#append hex payload
							ssl_dict[curr_frame] +=  line.split('  ')[1].replace(' ','')
						#if not -> end of payload
						else:
							break
					
					#append payload to pack_list
					self.stream_dict[curr_stream]['pack_list'].append({'frame':curr_frame, 'timestamp':timestamp, 'source':curr_source_ip, 'payload':ssl_dict[curr_frame]})
					
					#continue
					continue

				#get new line
				line = f.readline()	

	def generate_pcap(self):

		"""This function initializes output .pcap generation procedure."""

		#for every stream -> create new packets
		new_packets = list()
		for stream in self.stream_dict:
			
			#timestamp of SYN -> temporary solution
			#take first byte of found payload, decrease by 0.1 and save
			#in the future -> tak timestamp from original handshake
			self.last_timestamp = self.stream_dict[stream]['first_timestamp'] - 0.1

			#append pcap with streams
			self.append_pcap(self.stream_dict[stream]['source_ip'], self.stream_dict[stream]['dest_ip'], self.stream_dict[stream]['source_mac'], self.stream_dict[stream]['dest_mac'], \
				self.stream_dict[stream]['sport'], self.stream_dict[stream]['dport'], self.stream_dict[stream]['pack_list'])

if __name__ == "__main__":

	#initialize decrypter class
	decrypter = decrypter(sys.argv[1::])

	#parse pcap
	decrypter.parse_pcap()

	#if anything in stream_dict (anything decrypted) -> generate new pcaps
	if len(decrypter.stream_dict) > 0:
	    #generate new pcap
	    decrypter.generate_pcap()

