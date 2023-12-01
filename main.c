/*
    Network Tools

    Requires:
        libpcap (shocker)

    Features:
        > Finds control panel urls of broadcasting printers (-findprinters)
            * This was mainly why I wrote the program lamo
        > General packet sniffing
            * List amount of packets found (-onlynum)
            * Dump all packet data (launch netTool with no args)
*/

// Standard C libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Other
#include <pcap.h> // the goat (does all the heavy lifiting tbh)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <net/ethernet.h>


// Data structs
typedef struct{
    char* name;
    char ip[13];
    char subnet_mask[13];

    // Raw data
    bpf_u_int32 ip_raw;
    bpf_u_int32 subnet_mask_raw;

    struct in_addr address;
} NTool_Device;

// Functions
void PrintIntro();

void GetDevices();

void ReadPackets();

void HandlePacket(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet_body);

// Global vars
NTool_Device wlan0; // Wireless card

char printerUrls[256][256]; // All Printer URLS
int printers = 0; // Amount of printers

int packet_count_limit = 1;
int timeout_limit = 10  ; //10000;
int ethernet_header_length = 14;

int numPackets = 0;

FILE* fp; // Printer files idk maybe

// Settings
int printDebug = 1;
int getPrint = 0;
int onlyNum = 0;
int printData = 0;

int main(int argc, char* args[]){
    for(int i = 0; i < argc; i++){
        if(strcmp(args[i], "-findprinters") == 0){
            getPrint = 1;
            printDebug = 0;
        }
        if(strcmp(args[i], "-onlynum") == 0){
            onlyNum = 1;
            printDebug = 0;
        }
        if(strcmp(args[i], "-printdata") == 0){
            printData = 1;
        }
    }
    fp = fopen("PRINTERS.TXT", "w");
    PrintIntro();
    GetDevices();

    // Begin reading packets
    printf("==========\n");
    if(getPrint) printf("Printer configuation Page List: \n");
    ReadPackets();
}


void PrintIntro(){
    printf("===========================\n");
    printf("       NETWORK TOOLS       \n");
    printf("===========================\n");
    printf("*** Obligitory legal disclaimer: ***\n");
    printf("Idk i mean this is probabbly illegal (maybe? idk man) to run\non networks you dont own or dont\nhave permission to go\nsnooping around on, idk tho\nim not a lawyer (thank god)\nso just be careful and not stupid");
    printf("\n************************************\n");
    if(getPrint) printf("> Find Printer Admin Panel mode\n");
    if(onlyNum) printf("> Display packet statistics mode\n");
}

/*
    Despite its name it only grabs the wireless card
*/
void GetDevices(){
    //
    printf("--------------------------\n");
    printf("Getting wireless card...\n");
    char error_buffer[PCAP_ERRBUF_SIZE];

    // Get name
    wlan0.name = pcap_lookupdev(error_buffer);
    if(wlan0.name == NULL){
        printf("ERROR: %s\n", error_buffer);
        exit(-1);
    }
    // Get device info
    if(
        pcap_lookupnet(
            wlan0.name,
            &(wlan0.ip_raw),
            &(wlan0.subnet_mask_raw),
            error_buffer
        ) == -1
    ){
        printf("ERROR: %s\n", error_buffer);
        exit(-1);
    }
    
    // Get human readable form
    wlan0.address.s_addr = wlan0.ip_raw;
    strcpy(wlan0.ip, inet_ntoa(wlan0.address));

    wlan0.address.s_addr = wlan0.subnet_mask_raw;
    strcpy(wlan0.subnet_mask, inet_ntoa(wlan0.address));


    // Print out data
    printf("------ WLAN0 ------\n");
    printf("DEV_NAME: %s\n", wlan0.name);
    printf("IP ADDR: %s\n", wlan0.ip);  
    printf("SUBNET MASK: %s\n", wlan0.subnet_mask);
    printf("-------------------\n");
}

/*
    Begin reading packets and setup pcap_loop
*/
void ReadPackets(){
    pcap_t *handle;
    const uint8_t *packet;
    struct pcap_pkthdr packet_header;
    char error_buffer[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(
        wlan0.name,
        BUFSIZ,
        packet_count_limit,
        timeout_limit,
        error_buffer
    );

    if(handle == NULL){
        printf("ERROR: %s\n", error_buffer);
        exit(-1);
    }
    pcap_set_timeout(handle, timeout_limit);
    pcap_loop(handle, 0, HandlePacket, NULL);
   
}

/*
    The real main part of the program
*/
void HandlePacket(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet){
    // Increment amount of packets found
    numPackets++;

    // 
    if(printDebug){
        printf("==== PACKET ====\n");
        printf("Packet total length %d\n", header->len);
    }
    
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    
    int isWorth = 0;

    switch(ntohs(eth_header->ether_type)){
        case ETHERTYPE_IP:
            if(printDebug)
                printf("Packet Type IP\n");
            isWorth = 1;
            break;
        case ETHERTYPE_ARP:
            if(printDebug)
                printf("Packet Type ARP\n");
            break;
        case ETHERTYPE_REVARP:
            if(printDebug)
                printf("Packet Type REVERSE ARP\n");
            break;
        default:
            break;
    }

    if(isWorth){
        // Its an IP packet then we do stuff
        const uint8_t *ip_header;
        const uint8_t *tcp_header;
        const uint8_t *payload;

        int ip_header_length;
        int tcp_header_length;
        int payload_length;

        ip_header = packet + ethernet_header_length;
        ip_header_length = ((*ip_header) & 0x0F); // Get second half of ip_header (cuz it have the lenth)
        ip_header_length *= 4;

        if(printDebug)
            printf("IP Header Length: %d\n", ip_header_length);

        tcp_header = packet + ethernet_header_length + ip_header_length;
        tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
        tcp_header_length = tcp_header_length * 4;

        int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length; // so we know how far until the payload


        payload_length = header->caplen - total_headers_size;

        
        if(printDebug)
            printf("TOTAL HEADER SIZE %d\n", total_headers_size);

        payload = packet + total_headers_size;
        const uint8_t *temp_pointer = payload;
        int byte_count = 0;
        
        if(payload_length > 0){

            char data[payload_length];

            while (byte_count++ < payload_length) {
                if(printData)
                    printf("%c", *temp_pointer);
                data[byte_count] = *temp_pointer;
                temp_pointer++;
            }
            if(printData)
                printf("\n");


            
            // PRINTER CHECK
            // THIS IS ACTUALLY $H!T
            // THERE IS PROBABBLY A MUCH BETTER WAY TO DO IT
            if(getPrint){
                for(int i = 0; i < payload_length - 16; i++){
                    if(data[i] == 'h' && data[i+1] == 't' && data[i+2] == 't' && data[i+3] == 'p'){
                        int run = 0, c = 1;
                        char url[256] = {0};
                        url[0] = 'h';
                        while(run != 2){
                            if(i > payload_length) break;
                            if(c > 256) break;  
                            if(data[i++] == '.') run++;
                            if(run != 2 && data[i] != "\\")
                                url[c++] = data[i];
                            else break;
                        }

                        // has the url already been found 
                        int pri = 0;
                        for(int j = 0; j < printers; j++){
                            if(strcmp(url, printerUrls[j]) == 0){
                                pri = 1;
                            }
                        }
                        // if not, save it and print it
                        if(!pri){
                            for(int k = 0; k < c; k++){
                                printerUrls[printers][k] = url[k];
                            }
                            printers++;
                            fwrite(url, sizeof(char), c, fp);
                            fwrite("\n", sizeof(char), 2, fp);
                            printf("> %s\n", url);
                        }
                        break;
                    }
                }
            }


            // Print IP ADDRS
            if(!getPrint){
                // tmp struct for src to dest
                struct in_addr addrs;

                char sHost[INET_ADDRSTRLEN], dHost[INET_ADDRSTRLEN];

                // Src host
                addrs.s_addr = eth_header->ether_shost;
                strcpy(sHost, inet_ntoa(addrs));

                // Dest host
                addrs.s_addr = eth_header->ether_dhost;
                strcpy(dHost, inet_ntoa(addrs));
                
                printf("%d bytes from %s to %s\n", payload_length, sHost, dHost);
            }
        }

    }

    // Only num
    if(onlyNum){
        printf("Packets: %d\r", numPackets);
    }

    


}