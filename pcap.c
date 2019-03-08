#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>

extern pid_t pid;
extern u16 icmp_req;
extern struct timeval stop;
static const char* dev = "eth0";
//static const char* dev = "enp0s3";
static char* net;
static char* mask;

static char filter_string[FILTER_STRING_SIZE] = "";

static pcap_t *p;
static struct pcap_pkthdr hdr;
//
static char fixed_filter[FILTER_STRING_SIZE] = "";
/*
 * This function is almost completed.
 * But you still need to edit the filter string.
 */
void pcap_init( const char* dst_ip ,int timeout )
{	
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	
	struct in_addr addr;
	//bpf : Berkeley Packet Filter => for packet capture	
	struct bpf_program fcode;
	//give the device name, return one of the ip(store in netp) and corresponding netmask(store in maskp)
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	addr.s_addr = netp;
	net = inet_ntoa(addr);	
	if(net == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	if(mask == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	//open the device store in dev to create a sniffing session for reading bytes in received packets in Promiscuous mode(sniff all traffic on wire); return value p = session handle	
	p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
	if(!p){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	/*
	 *    you should complete your filter string before pcap_compile
	 */
	//destination IP should be router IP
	strcat(strcat(filter_string, "src "), dst_ip);
	//icmp type should be ping reply packet
	strcat(filter_string, " and icmp[icmptype] == icmp-echoreply");
	//id in icmp packet should be the same as the icmp request
	//proto[expr : size], icmp id is spreading across the 5th and 6th byte
	strcat(filter_string, " and icmp[4:2] == ");
	char tmp[50]; 
	sprintf(tmp, "0x%x", htons(pid));
	strcat(filter_string, tmp);
	strcpy(fixed_filter, filter_string);
	//the sequence number in icmp packet is the same as icmp request
	strcat(filter_string, " and icmp[6:2] == ");
	sprintf(tmp, "0x%x", icmp_req);
	strcat(filter_string, tmp);		
	//compile to apply the filter, use fcode(struct bpf_program) to store the compiled version of the filter, use maskp to specified the netmask of the net that filter applies to
	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
	//apply the filter
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
}


int pcap_get_reply( const char* dst_ip )
{
	const u_char *ptr;
	struct bpf_program fcode;
	bpf_u_int32 maskp;

	//reset the filter because sequence number is increase after each packet
	memset(filter_string, 0, strlen(filter_string));
	strcpy(filter_string, fixed_filter);
	char tmp[50];
	strcat(filter_string, " and icmp[6:2] == ");
        sprintf(tmp, "0x%x", icmp_req);
        strcat(filter_string, tmp);
	//strcat(filter_string, "1");
	inet_aton(mask, (struct in_addr *)&maskp);
	//printf("filter string : %s\n", filter_string);
	//printf("id : %u, seq : %u\n", pid, icmp_req);
	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
	//apply the filter
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
	ptr = pcap_next(p, &hdr);
	/*
	 * google "pcap_next" to get more information
	 * and check the packet that ptr pointed to.
	 */
	//stop = clock();
	//printf("Reply from %s: ", dst_ip);
	if(ptr != NULL){
		//printf("packet len : %d\npacket caplen : %d\n", hdr.len, hdr.caplen);
		//myicmp *pkg = (myicmp *)&(ptr[14]);
		//printf("icmp id : %d\n", pkg->icmp_hdr.un.echo.id);
		//printf("icmp seq : %u\n", ntohs(pkg->icmp_hdr.un.echo.sequence));
		//struct ip* pkg = (struct ip*)ptr;
		//printf("icmp id : %d\n", pkg);
		//pcap_close(p);
		//printf("time = %.3lfms\n", (double)(stop - start) / CLOCKS_PER_SEC * 1000);
		//printf("\tRouter: %s\n", inet_ntoa(pkg->ip_hdr.ip_src));
		stop = hdr.ts;		
		return 1;
	}
	//printf("time = *\n");
	return 0;
}
