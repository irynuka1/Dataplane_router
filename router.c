#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define OP_REQUEST 0x0001
#define OP_REPLY 0x0002

struct route_table_entry *rtable;
struct arp_table_entry *arptable;
int rtable_size;
int arptable_size;

int rtable_cmp(const void *a, const void *b) {
	struct route_table_entry *ra = (struct route_table_entry *)a;
	struct route_table_entry *rb = (struct route_table_entry *)b;

	// First checking the prefix
	if ((ntohl(ra->prefix) != ntohl(rb->prefix))) {
		if (ntohl(ra->prefix) > ntohl(rb->prefix)) {
			return -1;
		} else {
			return 1;
		}
	}

	// If the prefix is the same, checking the mask
	if ((ntohl(ra->mask) > ntohl(rb->mask)))
		return -1;
	else
		return 1;
}

struct route_table_entry *get_best_route(uint32_t dest_ip) {
	struct route_table_entry *best = NULL;
    for (int i = 0; i < rtable_size; i++) {
        if ((dest_ip & rtable[i].mask) == (rtable[i].prefix & rtable[i].mask)) {
            if (best == NULL || ntohl(rtable[i].mask) > ntohl(best->mask)) {
                best = &rtable[i];
            }
        }
    }

    return best;
}

struct arp_table_entry *get_mac_entry(uint32_t ip) {
    for (int i = 0; i < arptable_size; i++) {
        if (arptable[i].ip == ip) {
            return &arptable[i];
        }
    }
    return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	arptable = malloc(sizeof(struct arp_table_entry) * 100000);

	// Reading the route table from file
	rtable_size = read_rtable(argv[1], rtable);
	DIE(rtable_size < 0, "read_rtable");

	// Initially the ARP table is empty
	arptable_size = 0;

	// Sorting the route table
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), rtable_cmp);

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
		struct ip_hdr *ip_hdr = (struct ip_hdr *) (buf + sizeof(struct ether_hdr));

		if (ntohs(eth_hdr->ethr_type) != ETHERTYPE_IP)
			continue;

		if (checksum((u_int16_t *) ip_hdr, sizeof(struct ip_hdr)) != 0)
			continue;

		struct route_table_entry *best_route = get_best_route(ip_hdr->dest_addr);
		if (best_route == NULL)
			continue;

		if (ip_hdr->ttl <= 1)
			continue;

		ip_hdr->ttl--;
		ip_hdr->checksum = 0;
		ip_hdr->checksum = checksum((u_int16_t *) ip_hdr, sizeof(struct ip_hdr));

		struct arp_table_entry *arp_entry = get_mac_entry(best_route->next_hop);
		if (arp_entry == NULL) {
			// Send ARP request
			continue;
		}

		memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6);
		uint8_t interface_mac[6];
		get_interface_mac(best_route->interface, interface_mac);
		memcpy(eth_hdr->ethr_shost, interface_mac, 6);
		send_to_link(best_route->interface, buf, len);

		// if (ntohs(eth_hdr->ethr_type) == ETHERTYPE_IP) {

		// 	// Need to send an IP packet

		// } else if (ntohs(eth_hdr->ethr_type) == ETHERTYPE_ARP) {

		// 	struct arp_hdr *arp_hdr = (struct arp_hdr *) (buf + sizeof(struct ether_hdr));

		// 	if (ntohs(arp_hdr->opcode) == OP_REQUEST)

		// 		// Need to send an ARP request

		// 	else if (ntohs(arp_hdr->opcode) == OP_REPLY)
			
		// 		// Need to send an ARP reply
		// }
	}
}