# pcap
A PING program which provides IP source route ability
<pre>
Notice: The program must be executed by superuser privileges.
System Configure: Ubuntu disables source routing by default. Type the following command to turn it on:
                    echo 1 > /proc/sys/net/ipv4/conf/all/accept_source_route
                    echo 1 > /proc/sys/net/ipv4/ip_forward
                  Install pcap library in your PC:
                    sudo apt-get install libpcap-dev
Usage: ./myping -g gateway [-w timeout (in msec)] [-c count] target_ip
</pre>
