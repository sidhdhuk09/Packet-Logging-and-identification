This code uses scapy to capture, log and filter packets based on the host machine's network traffic. This script handles both IPv4 as well as IPv6 protocols and supports TCP as well as UDP protocols. Protocols that are neither TCP nor UDP are given a separate log that details what protocol those packets are from. 

I used pycharm for this project. To install scapy, go to the bottom of the pycharm window, click on terminal and write: pip install scapy or pip3 install scapy

This will install the necessary packages for scapy. After that, you can click on run. The output should display "Creating packet logs along with packet filtering". Stopping the program execution will create the packet_log.txt in the pycharm project folder which is also accessible in the project window on the left. 

Note: Packet_log.txt is only created when stopping the program execution or letting the program run for at least a few minutes however, doing so would result in an extremely big file size. Stopping the program and checking the packet_log.txt would ensure that the file size does not get too big. 
