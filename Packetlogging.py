import socket
import os
from datetime import datetime  # to import datetime class for logging system details such as date, time
from scapy.all import sniff, IP, TCP, UDP, IPv6  # modules for scapy

block_ip = ["192.168.1.100", '10.0.0.23', '185.199.108.154']  # IP based fitlering to block certain ip addresses
block_port = [22, 80, 443, 55784]  # similarly to block certain ports

Protocol_services = {
    # mapping porotocl numbers to their respective strings. Not having this results in protocol only showing numbers. Used website: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    6: 'TCP',
    17: 'UDP',
    2: 'IGMP',
    41: 'IPv6',
    58: 'ICMPv6'
}


def logging_packet(packet, log_file,
                   action="allowed"):  # function to start logging the packets. we take 3 variables, packet, the file to which we want data to be logged, and whether to allow the packet to reach its destination or block it
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # extracting system information such as date, time etc.
    protocol = "N/A"  # initialzes the protocol with not avaible as we don't know the network protocol the packet is using as of this point
    source_ip = destination_ip = "N/A"  # similar to the above, we don't know the source or destination of the IP
    source_port = destination_port = "N/A"  # Port numbers have not been extracted as of this point
    packet_summary = packet.summary()  # to create a summary of the packet that tells us which protocol that packet is using

    if IP in packet:  # condition to check if the packet is in ipv4 layer. IP in scapy automatically refers to IPv4
        source_ip = packet[IP].src  # source IP is extracted from the packet. src is a keyword in the scapy library
        destination_ip = packet[IP].dst  # destination IP is extracted from the packet. dst is also a keyword
        protocol_num = packet[IP].proto  # protocol number is retrived from the packet.
        protocol = Protocol_services.get(protocol_num,
                                         f"Unknown({protocol_num})")  # the protcol number retrived from the above line is mapped to the corresponding string in the dictornary. If no protocol name is found, then it returns a string unknwon
    elif IPv6 in packet:  # if the packet is in ipv6 layer
        source_ip = packet[IPv6].src  # source IP is extracted from the packet
        destination_ip = packet[IPv6].dst
        protocol_num = packet[
            IPv6].nh  # Retrives the next header (nh) in the packet. SInce IPv6 is 8 segments long of 32 hexadecimals each, it will move onto the next group header and extract its contents
        protocol = Protocol_services.get(protocol_num,
                                         f"Unknown({protocol_num})")  # similar to the above where the protocol number extracted is mapped to the corresponding string in the dictionary. If the number is unknown, then unown message prints out

    if TCP in packet:  # if TCP protocol is found in the packet
        source_port = packet[TCP].sport  # source port is extracted from the packet
        destination_port = packet[TCP].dport  # similary destination port is extracted from the packet
    elif UDP in packet:  # if UDP protocol is present in the packet
        source_port = packet[UDP].sport  # source port is extracted from the packet
        destination_port = packet[UDP].dport  # destination port is extracted from the packet

    else:  # if neither TCP nor UDP is found in the packet

        log_entry = f"{timestamp} | Action: {action} | Packet Summary: {packet_summary} | Size: {len(packet)} bytes\n"  # a log file that gives us the summary of the packet is created and displayed which tells us which layer the packet is from
        log_file.write(log_entry)  # writes the details of the network packets into the file txt
        log_file.flush()  # I am using this beacuse I'm calling a buffer operation below. This ensures that the output is written to the disk immediately in the .txt file. FLush is being used ensure that all the data is succesfully stored in the disk
        return

    packet_size = len(packet)  # calculates the size of the packet returning the totla lenght of the packet in bytes.
    log_entry = (  # the main details of the packet are being shown in this line
        f"{timestamp} | Action: {action} | Protocol: {protocol} | "
        f"Source: {source_ip}:{source_port} | Destination: {destination_ip}:{destination_port} | "
        f"Size: {packet_size} bytes\n"
    )
    log_file.write(log_entry)  # writing the details of the above packet into the file
    log_file.flush()


def filter_packet(
        packet):  # this is a fucntion that is used to check if a packet is allowed or blocked from source to destination based on the above rules. Currenrlt the rules include blocked IP address and port. It only extracts source ip and destination port based on the logic defined above for blocking where we are blocking only the ip adress and the port number

    source_ip = destination_ip = None
    source_port = destination_port = None

    if IP in packet:  # if packet is in IPv4
        source_ip = packet[IP].src  # source Ip is extracted
    elif IPv6 in packet:  # if packet is in IPv6
        source_ip = packet[IPv6].src  # source IP extracted

    if TCP in packet:  # If TCP ptorocol is in packet
        destination_port = packet[TCP].dport  # destiontion port number extracted from the packet
    elif UDP in packet:
        destination_port = packet[UDP].dport

    if source_ip in block_ip:  # if the source ip extracted from above matches with the blocked ip from the above
        return "blocked"  # then we return a block

    elif destination_port in block_port:  # if destination port matches the port blocked in the above
        return "blocked"  # then we return a block

    else:
        return "allowed"  # else we allow


def packet_callback(packet,
                    log_file):  # this function is acting as the intermediary between the packet filtering and packet logging methonds. This function is using the above rules to check if the packet should be allowed or blocked. It then calles the logging packet function to write information about the packet with the three arguements passing into the function.

    try:
        action = filter_packet(
            packet)  # this determines whether the packet shoukd be allowed or blocked based on the above rules
        logging_packet(packet, log_file,
                       action)  # function logging_packet is called where the arguements packet (current packet), logfile (obeject that writes the log) and action (the rules allowing or blocking) are passed through it
    except Exception as e:  # exception handling
        print(f"There was an error processing the packet: {e}")  # packet could not be processed


def analyze_packet():
    log_filename = "packet_log.txt"  # file which is created where logging takes place
    open(log_filename,
         "a").close()  # the file is created with "a" which means for appending the file therefore new data is being written into the file.

    with open(log_filename, "a",
              buffering=1) as log_file:  # file output is written line by line as buffering=1. log_filename is the file object used to write data into the file.
        print("Creating packet logs along with packet filtering")  # packet logging is going to start
        sniff(prn=lambda x: packet_callback(x, log_file),
              store=False)  # sniff is a function from scapy to capture packets. This is a lambda function where prn is used to execute each and every packet where prn is acting as a callback function to itself. The lambda function call the earlier method packet_callback with the packet itself and the log_file object where the details of the packets are being written. The store tells scappy not to store packets in memory which is uselful for long term capture of packets.


analyze_packet()
