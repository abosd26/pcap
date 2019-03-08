#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

extern u16 icmp_req;
void 
fill_iphdr ( struct ip *ip_hdr , const char* dst_ip)
{
	//initialization
	memset(ip_hdr, 0, sizeof(struct ip));
	//ip version
	ip_hdr->ip_v = IPVERSION;
	//header length = 28 bytes
	ip_hdr->ip_hl = 7;
	//total length = 92 bytes
	ip_hdr->ip_len = PACKET_SIZE;
	//id = 0	
	ip_hdr->ip_id = 0;
	//flag = don't fragment
	ip_hdr->ip_off |= htons(IP_DF);
	//TTL = 64
	ip_hdr->ip_ttl = 64;
	//protocol  = icmp
	ip_hdr->ip_p = IPPROTO_ICMP;
	//destnation ip
	inet_aton(dst_ip, &(ip_hdr->ip_dst));
}

void
fill_icmphdr (struct icmphdr *icmp_hdr)
{
	//initialization
	memset(icmp_hdr, 0, sizeof(struct icmphdr));
	//type = 8(request)
	icmp_hdr->type = 8;
	//id = process id
	icmp_hdr->un.echo.id = getpid();	
	//sequence number(start from 1)
	icmp_hdr->un.echo.sequence = htons(icmp_req);
	//payload(don't fill all 0, size correspond with IP header)
	//checksum(should initalize it to 0 first)
	icmp_hdr->checksum = fill_cksum(&(*icmp_hdr));
	//printf("pid : %d\n", icmp_hdr->un.echo.id);
}

//u8 = unsigned char, u16 = unsigned short, u32 = unsigned int
u16
fill_cksum(struct icmphdr* icmp_hdr)
{	
	int nleft = ICMP_PACKET_SIZE;
        int sum = 0;
        unsigned short *w = (unsigned short *)icmp_hdr;
        unsigned short answer = 0;
        
        while( nleft > 1 ) {
                sum += *w++;
                nleft -= 2;
        }
        
        if( nleft == 1 ) {
                *(unsigned char *) (&answer) = *(unsigned char *) w;
                sum += answer;
        }
        
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        answer = ~sum;
        return (answer);
}
int IsValidIP(const char* str){
        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, str, &(sa.sin_addr));
        if(result == 1){
                return 1;
        }
        return 0;
}
int IsNumber(const char* str){
	for(int i = 0; i < strlen(str); i++){
		if(!isdigit(str[i])){
			return 0;	
		}
	}
	return 1;
}

