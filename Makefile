all : clean myping

myping : main.c
	gcc -o myping main.c pcap.c pcap.h fill_packet.c fill_packet.h -lpcap
clean :
	-rm myping 
