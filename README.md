# decrypter

This is the first version of SSL decrypter, which converts .pcap file with SSL traffic into .pcap file with unencrypted traffic.
It was mainly tested on HTTPS and SMTP traffic, thus bugs may be found and new features may be required.

**IMPORTANT NOTE**

I'm not a programmer and this code was written very quickly (at least first version of the project - this information may be outdated in near future;). If you have any concerns regarding the code or if you would like to just tell me how bad it is - go ahead and post an issue. 

**Requirements:**
  Python 2.7
  Python scapy
  Wireshark + tshark
  Wireshark compiled with GnuTLS >= 2.2.2

**What do I need to decrypt .pcap?**

You need a file with logged master secrets. More details:
  https://wiki.wireshark.org/SSL#Using_the_.28Pre.29-Master-Secret
  https://sharkfesteurope.wireshark.org/assets/presentations17eu/15.pdf
  https://jimshaver.net/2015/02/11/decrypting-tls-browser-traffic-with-wireshark-the-easy-way/
 
**How does it work?**

This first version of decrypter implements pretty messy way to decrypt .pcaps. 
It uses wireshark/tshark functionallity, which is able to decrypt .pcap files using master secrets. However, wireshark/tshark is unable to save a new .pcap file with the decrypted traffic. It is most probably connected with the fact, that high interference with the packets is required in that case (removal of SSL layer, recalculation of SEQ/ACK numbers and others).

Although it's impossible to write new decrypted .pcap with wireshark/tshark right now, they can still return decrypted payload in the .txt file, using tshark `-Vx` options.

This messy walkaround implemented in decrypter uses tshark to create .txt file with all the info about packes printed (together with the decrypted payload). Then it digs through the output .txt file and recreates TCP sessions. Some details which may save you some time:
  - it generates new TCP handshake (seq and ack numbers are randomized right now)
  - original timestamps of TCP handshake are not preserved (it will be changed soon),
  - it also generates its own TCP connection closing sequence.

**Why do I hate those .txt files?**

Because these are large and parsing is slow.
Approximately, test_pcap.txt will be about **30 times bigger** than the test_pcap.pcap files. So if you are planning to parse a large .pcap file, be sure that:
  - you have a plenty of time (actually it's not that bad, unless you are parsing .pcaps bigger than 1GB),
  - you have a lot of free disk space (maybe RAM too),
  - or you have splitted your large .pcap file into smaller ones (yes - it will be added as a feature soon).

**Usage**

`
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
`
