/***********************************
 *                                 *
 *          Matus Tvarozny         *
 *             xtvaro00            *
 *        IPK 2.projekt(ZETA)      *
 *             Sniffer             *
 *                                 *
 ***********************************/

#include <iostream>             
#include <string>
#include <string.h>
#include <pcap.h>               /*pcap funkcie*/
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <iomanip>              /*RFC3339*/
#include <chrono>               /*RFC3339*/
#include <ctime>                /*RFC3339*/
#include <sstream>
#include <netinet/ip.h>	        /*struct iphdr, arphdr*/
#include <net/ethernet.h>	    /*struct ether_header*/
#include <netinet/ip_icmp.h>	/*struct icmphdr*/
#include <netinet/in.h>
#include <netinet/tcp.h>        /*struct tcphdr*/
#include <netinet/udp.h>        /*struct udphdr*/
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>        /*IPV6 packety*/
//using namespace std;


bool udp;
bool tcp;
bool icmp;
bool arp;
int port = -1;
std::string interface = "";
std::string filter = "";
int packets_count = 1;


/*Funkcia vypise vsetky dostupne rozhrania a pomocou funkcie pcap_freealldevs()
  uvolni zoznam alokovany funkciou pcap_findalldevs()*/
void PrintInterfaces(pcap_if_t *list_of_interfaces)
{
    while (list_of_interfaces->next != NULL) {
        printf("%s\n", list_of_interfaces->name);
        list_of_interfaces = list_of_interfaces->next;
    }
    pcap_freealldevs(list_of_interfaces);
    exit(0);
}


/*Funkcia nacita vsetky dostupne rozhrania pomocou funkcie pcap_findalldevs() 
  a vrati ukazatel na prve z nich*/
pcap_if_t *LoadInterfaces()
{
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_if_t *list_of_interfaces;
    if (pcap_findalldevs(&list_of_interfaces, errbuff) == PCAP_ERROR) {
        fprintf(stderr, "ERROR: No interfaces available.\n");
        exit(1);
    }
    return list_of_interfaces;
}


/*Funkcia skontroluje ci zadane rozhranie zo vstupu je medzi dostupnymi rozhraniami*/
void CheckInterface(std::string needle, pcap_if_t *list_of_interfaces)
{
    bool correct = false;
    while (list_of_interfaces->next != NULL) {
        if (strcmp(needle.c_str(), list_of_interfaces->name) == 0) {
            correct = true;
        }
        list_of_interfaces = list_of_interfaces->next;
    }
    if (correct == false) {
        pcap_freealldevs(list_of_interfaces);
        fprintf(stderr, "ERROR: Invalid interface.\n");
        exit(1);
    }
}


/*Funckia parsujuca vstupne argumenty*/
void ArgumentParser(int argc, char *argv[])
{
    pcap_if_t *list_of_interfaces = LoadInterfaces();  //zoznam dostupnych rozhrani
    std::string arg;

    //ak nie je zadany ziadny vstupny argument su vypisane vsetky dostupne rozhrania
    if (argc == 1) {
        PrintInterfaces(list_of_interfaces);
    } 

    //ak prepinac -i/--interface nie je zadany alebo je, ale rozhranie uz nie je specifikovane, 
    //su vypisane vsetky dostupne rozhrania a je jedno ktory v poradi tento prepinac je, 
    //preto su vstupne argumenty kvoli tomuto prepinacu prechadzane samostatne
    bool assigned;
    for (int i = 1; i < argc; i++) {
        arg = std::string(argv[i]);
        if (arg == "-i" || arg == "--interface") {
            assigned = true;
            try {
                interface = std::string(argv[i + 1]);
            } catch (std::exception const&) {
                PrintInterfaces(list_of_interfaces);
            }
            CheckInterface(interface, list_of_interfaces);
        }
    }
    if (assigned == false) {
        PrintInterfaces(list_of_interfaces);
    }

    //prechadzanie ostatnych vstupnych argumentov, ako su moznosti protokolov, pocet packetov,
    //ktore budu sniffovane alebo vyhradny port na sniffovanie
    for (int i = 1; i < argc; i++) {
        arg = std::string(argv[i]);
        if (arg == "-i" || arg == "--interface") {
            i++;  //preskocenie zadaneho rozhrania, to je nacitane pri prvom prechode
        } else if (arg == "-t" || arg == "--tcp") {
            tcp = true;
        } else if (arg == "-u" || arg == "--udp") {
            udp = true;
        } else if (arg == "--icmp") {
            icmp = true;
        } else if (arg == "--arp") {
            arp = true;
        } else if (arg == "-p") {
            try {
                port = std::stoi(std::string(argv[i + 1]));
                i++;
                if (port < 0) {
                    fprintf(stderr, "ERROR: Invalid port number.\n");
                    exit(1);
                }
            } catch (std::exception const&) {
                fprintf(stderr, "ERROR: Invalid port number.\n");
                exit(1);
            }
        } else if (arg == "-n") {
            try {
                packets_count = std::stoi(std::string(argv[i + 1]));
                i++;
                if (packets_count < 0) {
                    fprintf(stderr, "ERROR: Invalid packet number.\n");
                    exit(1);
                }
            } catch (std::exception const&) {
                fprintf(stderr, "ERROR: Invalid packet number.\n");
                exit(1);
            }
        } else {
            fprintf(stderr, "ERROR: Invalid entry argument.\n");
            exit(1);
        }
    }

    //pokial nebol zadany ziadny z moznych protokolov na sniffovanie, bude brane vsetky ako vyhovujuce
    if (udp == false && tcp == false && icmp == false && arp == false) {
        udp = true;
        tcp = true;
        icmp = true;
        arp = true;
    }
}

/*Funkcia, ktora na zaklade vstupnych prepinacov nastavi filter(zatial iba ako string)
  tak, aby boli sniffovane len tie packety, ktore su pozadovane */ 
void Filter()
{
    std::string port_str;
    std::stringstream ss;
    ss << port;
    ss >> port_str;

    if (udp) {
        if (port != -1){
            filter += "udp port " + port_str + " or ";
        } else {
            filter += "udp or ";
        }
    }
    if (tcp) {
        if (port != -1){
            filter += "tcp port " + port_str + " or ";
        } else {
            filter += "tcp or ";
        }
    }
    if (icmp) {
        filter += "icmp or ";
    }
    if (arp) {
        filter += "arp or ";
    }

    filter = filter.substr(0, filter.size() - 3); //orezanie "or"
    filter = filter + " or icmp6";  //prijimanie aj ipv6 packetov
}


/*Fukncia na vypis obsahu packetu
  https://www.programcreek.com/cpp/?code=mq1n%2FNoMercy%2FNoMercy-master%2FSource%2FClient%2FNM_Engine%2FINetworkScanner.cpp */
static void PrintPacket(const void *addr, int len) 
{
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;
	for (i = 0; i < len; i++) {
		if ((i % 16) == 0) {
			if (i != 0) {
				printf("  %s\n", buff);
            }
			printf("  %04x ", i);
		}
		printf(" %02x", pc[i]);
		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
			buff[i % 16] = '.';
        } else {
			buff[i % 16] = pc[i];
        }
		buff[(i % 16) + 1] = '\0';
	}
	while ((i % 16) != 0) {
		printf("   ");
		++i;
	}
	printf("  %s\n", buff);
}


/*Funckia na vypis casu v potrebnom formate(RFC3339) s nano sekundami
  https://stackoverflow.com/questions/54325137/c-rfc3339-timestamp-with-milliseconds-using-stdchrono*/
void PrintTime()
{
    std::stringstream ss;
    const auto now = std::chrono::system_clock::now();
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
    const auto c_now = std::chrono::system_clock::to_time_t(now);
    ss << std::put_time(std::gmtime(&c_now), "%FT%T") <<  '.' << std::setfill('0') << std::setw(3) << millis << "+02:00 ";
    printf("%s", ss.str().c_str());
}


/*Funkcia na vypis ipv6 adresy
  https://stackoverflow.com/questions/3727421/expand-an-ipv6-address-so-i-can-print-it-to-stdout */
void PrintIPv6Adress(const struct in6_addr * addr)
{
    printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
    (int)addr->s6_addr[0], (int)addr->s6_addr[1],
    (int)addr->s6_addr[2], (int)addr->s6_addr[3],
    (int)addr->s6_addr[4], (int)addr->s6_addr[5],
    (int)addr->s6_addr[6], (int)addr->s6_addr[7],
    (int)addr->s6_addr[8], (int)addr->s6_addr[9],
    (int)addr->s6_addr[10], (int)addr->s6_addr[11], 
    (int)addr->s6_addr[12], (int)addr->s6_addr[13],
    (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}


/*Hlavna funckia programu, ktora sa stara o rozlisovanie packetov ako takych.
  Mimo toho vola vsetky vyssie uvedene pomocne funkcie: Vypisuje cas, kedy bol packet sniffnuty,
  vypisuje jeho obsah zokodovany v 16-tkovej sustave, v pripade potreby ipv6 addresu.
  Z obdrazaneho paketu vie zisti adressu, popripade port.*/
void PacketSniffer(u_char *args, const struct pcap_pkthdr *header,  const u_char *packet) 
{
	struct ip *ip;  //IP hlavicka
    const struct iphdr *ip_hdr;  //IP hlavicka
    const struct ip6_hdr *ip6_hdr;  //IPv6 hlavicka
    const struct udphdr *udp_hdr;  //struktura UDP packetu
    const struct tcphdr *tcp_hdr;  //struktura TCP packetu
    const struct ether_header *ether_header;  //ethernetova struktura
    // const struct icmphdr *icmp_hdr;
    // const struct arphdr *arp_hdr;
    //MAC adresy vypisovane pri ARP protokoloch
    struct ether_addr mac_daddr;  //MAC adresa prijimatela
    struct ether_addr mac_saddr;  //MAC adresa odosielatela

    ip = (struct ip *)(packet + sizeof(struct ether_header));
    ip_hdr = (struct iphdr *)(packet + sizeof(struct ethhdr));
    ip6_hdr = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    ether_header = (struct ether_header *) packet;

    int iplen = ip->ip_hl*4; //vypocet pre ipv4
    
    PrintTime();

    switch(ntohs(ether_header->ether_type))
    {
        case ETHERTYPE_IP: //IPv4
            switch (ip_hdr->protocol)
            {
                case 1: //ICMPv4
                    printf("%s > ", inet_ntoa(ip->ip_src));
                    printf("%s", inet_ntoa(ip->ip_dst));
                    printf(", length %d bytes\n", header->len);

                    PrintPacket(packet, header->len);
                    break;
                case 6: //TCP
                    tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + iplen);

                    printf("%s : %d > ", inet_ntoa(ip->ip_src), ntohs(tcp_hdr->th_dport));
                    printf("%s : %d", inet_ntoa(ip->ip_dst), ntohs(tcp_hdr->th_sport));
                    printf(", length %d bytes\n", header->len);

                    PrintPacket(packet, header->len);
                    break;
                case 17: //UDP
                    udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + iplen);

                    printf("%s : %d > ", inet_ntoa(ip->ip_src), ntohs(udp_hdr->uh_dport));
                    printf("%s : %d", inet_ntoa(ip->ip_dst), ntohs(udp_hdr->uh_sport));
                    printf(", length %d bytes\n", header->len);

                    PrintPacket(packet, header->len);
                    break;
                default:
                    //iny IPv4 protokol
                    break;
            }
            break;
        case ETHERTYPE_IPV6: //IPv6
            switch(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt)
            {
                case 6: //TCP
                    printf("TCP - IPv6\n");
                    break;
                case 17: //UDP
                    printf("UDP - IPv6\n");
                    break;
                case 58: //ICMPv6
                    PrintIPv6Adress(&ip6_hdr->ip6_src);
                    printf(" > ");
                    PrintIPv6Adress(&ip6_hdr->ip6_dst);
                    printf(", length %d bytes\n", header->len);

                    PrintPacket(packet, header->len);
                    break;
                default:
                    //iny IPv6 protokol
                    break;
            }
            break;
        case ETHERTYPE_ARP: //ARP
            //naplnenie premennych s MAC adresami
            for (int i = 0; i < ETH_ALEN; i++){
                mac_saddr.ether_addr_octet[i] = ether_header->ether_shost[i];
                mac_daddr.ether_addr_octet[i] = ether_header->ether_dhost[i];
            }

            printf("%s > ", ether_ntoa(&mac_saddr));
            printf("%s", ether_ntoa(&mac_daddr));
            printf(", length %d bytes\n", header->len);

            PrintPacket(packet, header->len);
            break;
    }
}


/*Main programu*/
int main(int argc, char **argv)
{
    pcap_t *device;
    bpf_u_int32 ip;
    bpf_u_int32 mask;
    char errbuff[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_compiled;

    ArgumentParser(argc, argv);
    Filter();

    if ((device = pcap_open_live(interface.c_str(), 65535, 1, 1000, errbuff)) == NULL ) {
        fprintf(stderr, "ERROR: Failure during opening device for sniffing.\n");
        exit(1);
    }
    if (pcap_lookupnet(interface.c_str(), &ip, &mask, errbuff) == PCAP_ERROR) {
        fprintf(stderr, "ERROR: Can not find the network.\n");
        exit(1);
    }
    if (pcap_compile(device, &filter_compiled, filter.c_str(), 0, mask) == PCAP_ERROR) {
        fprintf(stderr, "ERROR: Filter compile failure.\n");
        exit(1);
    }
    if (pcap_setfilter(device, &filter_compiled) == PCAP_ERROR) {
        fprintf(stderr, "ERROR: Filter set failure.\n");
        exit(1);
    }
    if (pcap_loop(device, packets_count, PacketSniffer, NULL) == PCAP_ERROR) {
        fprintf(stderr, "ERROR: Failure during processing packets.\n");
        exit(1);
    }

    pcap_close(device); //zatvorenie "zariadenia" na sniffovanie
    pcap_freecode(&filter_compiled); //uvolnenie pamate alokovanej funkciou pcap_compile()
    return 0;
}