#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "fill_packet.h"
#include "pcap.h"
#include <time.h>
#include <ctype.h>
#include <sys/time.h>

pid_t pid;
u16 icmp_req = 1;
struct timeval stop, start;
int main(int argc, char* argv[])
{
	int sockfd;
	int on = 1;
	int usageInform = 0;

	pid = getpid();
	struct sockaddr_in dst;
	int count = DEFAULT_SEND_COUNT;
	int timeout = DEFAULT_TIMEOUT;
	char *gatewayIP, *dstIP;

	srand(time(NULL));

	/*usage information*/
	if(argc != 4 && argc != 6 && argc != 8){
		usageInform = 1;
	}
	else{
		if(strcmp(argv[1], "-g") != 0 || !IsValidIP(argv[2])){
			usageInform = 1;
		}
		else{
			if(argc == 4){
				if(!IsValidIP(argv[3])){
					usageInform = 1;
				}
			}
			else if(argc == 6){
				if(strcmp(argv[3], "-w") != 0 && strcmp(argv[3], "-c") != 0){
					usageInform = 1;
				}
				else if(!IsNumber(argv[4]) || atoi(argv[4]) <= 0){
					usageInform = 1;
				}
				else if(!IsValidIP(argv[5])){
					usageInform = 1;
				}
			}
			else if(argc == 8){
				if((strcmp(argv[3], "-w") != 0 || strcmp(argv[5], "-c") != 0) && (strcmp(argv[5], "-w") != 0 || strcmp(argv[3], "-c") != 0)){
					usageInform = 1;
				}
				else if(!IsNumber(argv[4]) || !IsNumber(argv[6]) || atoi(argv[4]) <= 0 || atoi(argv[6]) <= 0){
					usageInform = 1;
				}
				else if(!IsValidIP(argv[7])){
					usageInform = 1;
				}
			}
		}
	}
	//need superuser authority to start server
	if(getuid() != 0){
		usageInform = 1;
	}
	if(usageInform){
		printf("usage: sudo ./myping -g gateway [-w timeout(in msec)] [-c count] target_ip\n");
		exit(1);
	}
	else{
		gatewayIP = argv[2];
		if(argc == 4){
			dstIP = argv[3];
		}
		else if(argc == 6){
			dstIP = argv[5];
			if(strcmp(argv[3], "-c") == 0){
				count = atoi(argv[4]);
			}
			else if(strcmp(argv[3], "-w") == 0){
				timeout = atoi(argv[4]);			
			}
		}
		else if(argc == 8){
			dstIP = argv[7];
			if(strcmp(argv[3], "-w") == 0 && strcmp(argv[5], "-c") == 0){
				count = atoi(argv[6]);
				timeout = atoi(argv[4]);			
			}
			else if(strcmp(argv[3], "-c") == 0 && strcmp(argv[5], "-w") == 0){
				count = atoi(argv[4]);
				timeout = atoi(argv[6]);			
			}
		}
	}
	/* 
	* in pcap.c, initialize the pcap
	*/
	pcap_init(gatewayIP , timeout);



	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0)
	{
		perror("socket");
		exit(1);
	}

	if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		exit(1);
	}



	/*
	*   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
	*   to get the "ICMP echo response" packets.
	*	 You should reset the timer every time before you send a packet.
	*/
	dst.sin_family = AF_INET;
	inet_aton(gatewayIP, &(dst.sin_addr));
	printf("Ping %s (data size = %d, id = 0x%x, timeout = %d ms, count = %d):\n", dstIP, ICMP_DATA_SIZE, pid, timeout, count);
	for(int i = 0; i < count; i++){
		//fill ip option
		myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
		//no operation
		int nop = IPOPT_NOP;
		memcpy(&(packet->ip_option[0]), (u8 *)&nop, IP_OPTION_SIZE);
		//type = loose source route
		int type = IPOPT_LSRR;
		memcpy(&(packet->ip_option[1]), (u8 *)&type, IP_OPTION_SIZE - 1);
		//length = 7(+ nop = 8)
		int len = 7;
		memcpy(&(packet->ip_option[2]), (u8 *)&len, IP_OPTION_SIZE - 2);
		//pointer
		int pointer = 4;
		memcpy(&(packet->ip_option[3]), (u8 *)&pointer, IP_OPTION_SIZE - 3);
		//source route(only one => destination ip)
		unsigned char value[4] = {0};
		int index = 0;
		for(int i = 0; i < strlen(dstIP); i++){
			if(isdigit(dstIP[i])){
				value[index] *= 10;
				value[index] += dstIP[i] - '0';
			}
			else{
				index++;
			}
		}
		memcpy(&(packet->ip_option[4]), (u8 *)&value, 32);
		//fill icmp payload
		int payload = rand() % 3 + 1;
		memcpy(packet->data, (char *)&payload, ICMP_DATA_SIZE);
		//fill ip and icmp header
		fill_iphdr(&(packet->ip_hdr), gatewayIP);
		fill_icmphdr(&(packet->icmp_hdr));
		//set timer
		gettimeofday(&start, NULL);
		if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		{
			perror("sendto");
			exit(1);
		}
		free(packet);
		int n = pcap_get_reply(dstIP);
		printf("Reply from %s: ", dstIP);
		if(n == 0){
			printf("time = *\n");
		}	
		else{
			double duration = (double)(stop.tv_usec - start.tv_usec) / 1000.0;
			printf("time = %.3lfms\n", duration);
			printf("\tRouter: %s\n", gatewayIP);
		}
		//stop = clock();
		//printf("time : %lf\n", (double)(stop - start) / CLOCKS_PER_SEC * 1000);
		//increase sequence number by 1 after successfully receive ACK
		icmp_req++;
		usleep(100);
	}
	return 0;
}

