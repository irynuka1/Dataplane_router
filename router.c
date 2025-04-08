#include "queue.h"
#include "lib.h"
#include "list.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#define ETTIPV4 0x0800
#define ETTARP 0x0806
#define MAX_TABLE_LEN 100010
// LEN_PACKET este lungimea maxima pe care o poate
// suporta functia send_to_link
// (prin testare am observat ca nu merge o valoare mai mare)
#define LEN_PACKET 1512

// routeTable1 este tabela de routare cu duplicate
// routeTable este tabela de routare cu mastile maxime
struct route_table_entry routeTable[MAX_TABLE_LEN], routeTable1[MAX_TABLE_LEN];
struct arp_table_entry arpTable[MAX_TABLE_LEN];
int lenRouteTable, lenRouteTable1, lenArpTable;

// am declarat global pentru usurinta in a lucra
// cu informatiile necesare actualizarii header-elor
// in functia send_forward
struct Information {
	int interface;
	uint32_t ipSrc, ipDst;
	uint8_t *macSrc, *macDst;
	uint8_t type, code;
} info;

// functie de comparatie necesara functiei qsort
int fcmp(const void *x, const void *y) {
	struct route_table_entry *alpha = (struct route_table_entry *)x;
	struct route_table_entry *beta = (struct route_table_entry *)y;
	uint32_t prefixAlpha = ntohl(alpha->prefix);
	uint32_t maskAlpha = ntohl(alpha->mask);
	uint32_t prefixBeta = ntohl(beta->prefix);
	uint32_t maskBeta = ntohl(beta->mask);
	if ((prefixAlpha & maskAlpha) != (prefixBeta & maskBeta))
		return (maskAlpha & prefixAlpha) - (maskBeta & prefixBeta);
	return (maskAlpha - maskBeta);
}

// cautare in tabela de routare sortata si cu duplicatele eliminate pentru a avea cea mai mare masca
struct route_table_entry *find_route(uint32_t ipDst) {
	struct route_table_entry *route_found = NULL;
	int i, step;
	// initializare step cu cea mai mare putere a lui 2 mai mica decat lenRouteTable
	for (step = 1; step < lenRouteTable; step <<= 1);
	// aplicarea cautarii binare a lui Mihai Patrascu (cercetator roman la MIT)
	// OBS! aceasta cautare binara pe biti este de 4 ori mai eficienta decat cautarea binara clasica
	// deoarece construieste rezultatul dupa bitii acestuia
	for (i = 0; step; step >>= 1)
		if (i + step < lenRouteTable && (ntohl(routeTable[i + step].prefix) <= (ipDst & ntohl(routeTable[i + step].mask)))) {
			route_found = &routeTable[i + step];
			i += step;
		}
	// in cazul in care am gasit o ruta, atunci o returnez
	if (route_found && (ntohl(route_found->prefix) == (ipDst & ntohl(route_found->mask))))
		return route_found;
	// altfel returnez NULL
	return NULL;
}

// functia de constructie a pachetului de trimis
// si trimitere a acestuia mai departe in functie
// de campurile actualizate ale acestuia
void send_forward(char *buf) {
	// imi declar bufferul de trimis
    char *returnedPack = malloc(MAX_PACKET_LEN * sizeof(*returnedPack));
	// pe care il incarc cu datele din vechiul buffer
    memcpy(returnedPack, buf, MAX_PACKET_LEN);
	// iau din vechiul buffer ether header-ul
    struct ether_hdr * ethHdrICMP = (struct ether_hdr *) returnedPack;
	// inversez mac-urile dintre sursa si destinatie
	// in structura info adresele sunt puse invers din main
	memcpy(ethHdrICMP->ethr_dhost, info.macDst, 6);
	memcpy(ethHdrICMP->ethr_shost, info.macSrc, 6);
	// adaug header-ul de icmp in noul buffer
	struct icmp_hdr * icmpHdr = (struct icmp_hdr *)(returnedPack + sizeof(*ethHdrICMP) + sizeof(struct ip_hdr));
	// ii actualizez type-ul (daca e eroare ce tip de eroare este, iar daca nu este eroare il las 0)
	icmpHdr->mtype = info.type;
	icmpHdr->mcode = info.code;
	// actualizez checksumul doar pentru header-ul de icmp (nu este influentat de celelalte campuri)
	icmpHdr->check = 0;
	icmpHdr->check = htons(checksum((uint16_t*)icmpHdr, sizeof(*icmpHdr)));
	// adaug ip headerul (acesta este pus intre ether header si header-ul de icmp)
	struct ip_hdr * ipHdrICMP = (struct ip_hdr *)(returnedPack + sizeof(*ethHdrICMP));
	// calculez dimensiunea totala din buffer ce trebuie trimisa mai departe
	int totalSize = sizeof(*ethHdrICMP) + sizeof(*ipHdrICMP) + sizeof(icmpHdr);
	// adaug sa fie in cazul in care trebuie cei 8 bytes din ip header inainte de a face modificari asupra lui
	memcpy(returnedPack + totalSize, ipHdrICMP, 8);
	// interschimb si la nivelul acesta sursa cu destinatia
    ipHdrICMP->dest_addr = info.ipSrc;
    ipHdrICMP->source_addr = info.ipDst;
	// setez protocolul ales 1 pentru ICMP
    ipHdrICMP->proto = 1;
	// resetez ttl-ul la valoare initiala 64 (la protoccol si la ttl nu am facut transformari htons/ntohs/htonl/ntohl
	// pentru ca au dimensiunea de un octet)
    ipHdrICMP->ttl = 64;
	// setez tot_len la dimensiunea layer-elor de dupa ethernet
    ipHdrICMP->tot_len = htons(sizeof(*ipHdrICMP) + sizeof(*icmpHdr));
	// adaug cei 8 bytes despre care s-a spus in cerinta daca trebuie intors mesaj de eroare
	if (info.type == 11 || info.type == 3)
    	send_to_link(totalSize + 8 * sizeof(char), returnedPack, info.interface);
	else
		send_to_link(totalSize, returnedPack, info.interface);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);
	// citesc datele din tabela de routare
	lenRouteTable1 = read_rtable(argv[1], routeTable1);
	// sortez crescator dupa (prefix & masca), iar in caz de egalitate dupa marimea mastii
	qsort(routeTable1, lenRouteTable1, sizeof(struct route_table_entry), fcmp);
	// elimin rutele care au (prefix & masca) identic, si las doar ruta cu masca cea mai mare
	// pentru a putea eficientiza cautarea in pasii urmatori
	routeTable[lenRouteTable++] = routeTable1[0];
	for (int i = 1; i < lenRouteTable1; ++i)
		if ((ntohl(routeTable1[i].prefix) & ntohl(routeTable1[i].mask)) == (ntohl(routeTable1[i - 1].prefix) & ntohl(routeTable1[i - 1].mask)))
			routeTable[lenRouteTable - 1] = routeTable1[i];
		else
			routeTable[lenRouteTable++] = routeTable1[i];
	// imi creez coada care pastreaza bufferele ce trebuie trimise daca nu am gasit destinatia in tabela arp
	queue waitingMessages = create_queue();
	// imi creez coada de rute in care se adauga si se scot elemente simultan cu coada de buffere
	// aceasta coada eficientizeaza codul pentru a evita cautari in plus in tabele de routare
	queue waitingRoutes = create_queue();
	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ethr_type). The oposite is needed when
		sending a packet on the link, */
		// extrag macul destinatie
		uint8_t *macDestinatie = eth_hdr->ethr_dhost;
		uint8_t *macActual = malloc(6 * sizeof(*macActual));
		int broadcast_verif = 1;
		// extrag macul actual al routerului
		get_interface_mac(interface, macActual);
		// verific daca e broadcast
		for (int i = 0; i < 6; ++i)
			if (macDestinatie[i] != 0xff)
				broadcast_verif = 0;
		int verification = 1;
		// verific daca routerul este destinatie
		for (int i = 0; i < 6; ++i)
			if (!broadcast_verif && macActual[i] != macDestinatie[i])
				verification = 0;
		if (!verification)
			continue;
		// extrag ip-ul routerului
		uint32_t ipActual = inet_addr(get_interface_ip(interface));
		// vad pe ce caz merg IPV4 sau ARP
		if (ntohs(eth_hdr->ethr_type) == ETTIPV4) {
			// extrag ip headerul din buffer
			struct ip_hdr *ipHdr = (struct ip_hdr*)(buf + sizeof(*eth_hdr));
			// verific checksumul
			uint16_t checksumReceived = ntohs(ipHdr->checksum);
			ipHdr->checksum = 0;
			if (checksum((uint16_t *)ipHdr, sizeof(*ipHdr)) != checksumReceived)
				continue;
			// verific daca trebuie returnat mesaj de eroare
			if (ipHdr->ttl == 0 || ipHdr->ttl == 1) {
				info.interface = interface;
				info.ipSrc = ipHdr->source_addr;
				info.ipDst = ipHdr->dest_addr;
				info.macSrc = eth_hdr->ethr_shost;
				info.macDst = eth_hdr->ethr_dhost;
				info.type = 11;
				info.code = 0;
				send_forward(buf);
				continue;
			}
			--ipHdr->ttl;
			// actualizez checksumul dupa actualizarea ttl-ului
			ipHdr->checksum = 0;
			ipHdr->checksum = htons(checksum((uint16_t *)ipHdr, sizeof(*ipHdr)));
			// daca routerul este destinatie atunci trimit mai departe informatia
			if (ntohl(ipHdr->dest_addr) != ntohl(ipActual)) {
				// daca nu este destinatie si nu gasesc ruta spre destinatie returnez mesaj de eroare
				struct route_table_entry *route_found = find_route(ntohl(ipHdr->dest_addr));
				if (route_found == NULL) {
					info.interface = interface;
					info.ipSrc = ipHdr->source_addr;
					info.ipDst = ipHdr->dest_addr;
					info.macSrc = eth_hdr->ethr_shost;
					info.macDst = eth_hdr->ethr_dhost;
					info.type = 3;
					info.code = 0;
					send_forward(buf);
					continue;
				}
				// caut in tabela arp next hop
				int itReminder = 0;
				while (itReminder < lenArpTable && (arpTable[itReminder].ip != route_found->next_hop))
					++itReminder;
				// daca nu gasesc next hop atunci pun in asteptare bufferul actual si fac arp request
				if (itReminder == lenArpTable) {
					char *save = malloc(len * sizeof(*save));
					memcpy(save, buf, len);
					queue_enq(waitingMessages, save);
					queue_enq(waitingRoutes, route_found);
					int sizeRet = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
					char ret[sizeRet];
					struct ether_hdr *first_part = (struct ether_hdr*)ret;
					get_interface_mac(route_found->interface, first_part->ethr_shost);
					memset(first_part->ethr_dhost, 0xff, 6); // fac broadcast (255.255.255.255.255.255)
					first_part->ethr_type = htons(ETTARP);
					struct arp_hdr* second_part = (struct arp_hdr*)(ret + sizeof(*first_part));
					second_part->hw_len = 6; //dimensiune mac(6 octeti)
					second_part->proto_len = 4; //dimensiune ip(4 octeti)
					second_part->hw_type = htons(1);
					second_part->proto_type = eth_hdr->ethr_type;
					second_part->opcode = htons(1);
					get_interface_mac(route_found->interface, second_part->shwa);
					second_part->sprotoa = inet_addr(get_interface_ip(route_found->interface));
					memset(second_part->thwa, 0xff, 6); // fac broadcast
					second_part->tprotoa = route_found->next_hop;
			    	send_to_link(sizeRet, ret, route_found->interface);
				} else {
					memcpy(eth_hdr->ethr_shost, macActual, 6);
					memcpy(eth_hdr->ethr_dhost, arpTable[itReminder].mac, 6);
					send_to_link(len, buf, route_found->interface);
				}
			} else {
				info.interface = interface;
				info.ipSrc = ipHdr->source_addr;
				info.ipDst = ipHdr->dest_addr;
				info.macSrc = eth_hdr->ethr_shost;
				info.macDst = eth_hdr->ethr_dhost;
				info.type = 0;
				info.code = 0;
				send_forward(buf);
			}
		} else if (ntohs(eth_hdr->ethr_type) == ETTARP) {
			struct arp_hdr *arp = (struct arp_hdr *) (buf + sizeof(*eth_hdr));
			// daca sunt pe cazul de ARP verific ce tip de arp este (request sau reply)
			if (ntohl(arp->tprotoa) == ntohl(ipActual)) {
				// daca este request inversez sursa cu destinatia si trimit buffer
				// cu informatii de tip arp reply
				if ((ntohs(arp->opcode) == 1)) {
					uint32_t swap = arp->tprotoa;
					arp->tprotoa = arp->sprotoa;
					arp->sprotoa = swap;
					memcpy(arp->thwa, arp->shwa, 6);
					memcpy(arp->shwa, macActual, 6);
					memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
					memcpy(eth_hdr->ethr_shost, macActual, 6);
					arp->opcode = htons(2);
					send_to_link(LEN_PACKET, buf, interface);
				} else if(ntohs(arp->opcode) == 2) {
					// daca sunt in ARP reply actualizez tabela ARP
        			memcpy(arpTable[lenArpTable].mac, arp->shwa, 6);
					arpTable[lenArpTable++].ip = arp->sprotoa;
					// raspund la mesajele aflate in asteptare dupa ce am mai adaugat noi rute
					// in tabela ARP
        			while (!queue_empty(waitingMessages)) {
          				char* msg = queue_deq(waitingMessages);
						struct route_table_entry *route = queue_deq(waitingRoutes);
						struct ether_hdr *ethWaiting = (struct ether_hdr *) msg;
						int itReminder = 0;
						while (itReminder < lenArpTable && (arpTable[itReminder].ip != route->next_hop))
							++itReminder;
						// daca am gasit next hop in tabela ARP actualizez destinatia din ethernet si trimit mai departe
						// alftel astept in continuare sa se actualizeze tabela ARP cu noi rute
						if(itReminder != lenArpTable) {
							memcpy(ethWaiting->ethr_dhost, arpTable[itReminder].mac, 6);
							send_to_link(LEN_PACKET, msg, route->interface);
						} else {
							queue_enq(waitingMessages, msg);
							queue_enq(waitingRoutes, route);
						}
        			}
				}
			}
		}
	}
}