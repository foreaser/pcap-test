#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


void print_dst_mac(const u_char *dmac){
	printf("Destination Mac Address : ");
	for(int i = 0; i<6; i++){
		if(i<5){
			printf("%02x:",dmac[i]);
		}
		else{
			printf("%02x\n",dmac[i]);
		}
	}
}
void print_src_mac(const u_char *smac){
	printf("Source Mac Address : ");
	for(int i = 0; i<6; i++){
		if(i<5){
			printf("%02x:",smac[i]);
		}
		else {
			printf("%02x\n",smac[i]);
		}
	}
}


void tcp_port(const u_char* packet){
	printf("Source TCP Port : ");
	unsigned int result1= (packet+34)[0]<<8 | (packet+34)[1];
	printf("%d\n",result1);
	printf("Destination TCP Port : ");
	unsigned int result2= (packet+34)[2]<<8 | (packet+34)[3];
	printf("%d\n",result2);

}


void src_ip(const u_char* packet){
	printf("source IP : ");
	for(int i = 0; i<4; i++){
		if(i<3)
			printf("%d.",(packet+26)[i]);
		else
			printf("%d\n",(packet+26)[i]);
	}
}

void dst_ip(const u_char* packet){
	printf("Destination IP : ");
	for(int i = 0; i<4; i++){
		if(i<3)
			printf("%d.",(packet+30)[i]);
		else
			printf("%d\n",(packet+30)[i]);
	}
}

void print_payload(const u_char* packet){
	const u_char* payload = packet + 54;
	if((payload) == NULL)
		printf("Data Size : 0 byte\n");
	else{
		printf("Data : ");
		for(int i = 0; i<8; i++){
			printf("%02x ",payload[i]);
			/*
			if(payload[i+1] == NULL) 
				break;
			*/
		}
			
	}
	printf("\n");

}









int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
				if( (packet+23)[0] == 0x6){
				
					printf("----------Captured TCP----------\n");
					printf("%u bytes captured\n", header->caplen);
					tcp_port(packet);
					
					src_ip(packet);
					dst_ip(packet);
					
					print_src_mac(&packet[6]);
					print_dst_mac(&packet[0]);
					
					print_payload(packet);
				}
	}

	pcap_close(pcap);
}
