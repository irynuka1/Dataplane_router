/* router.c */
#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#define IP_ETHTYPE 0x0800
#define ARP_ETHTYPE 0x0806
#define MAC_LEN 6
#define HTYPE_ETHER 1
#define TIMEOUT 11
#define NO_HOST 3

struct route_table_entry *routing_entries;
struct arp_table_entry *arp_entries;
int routing_count;
int arp_count;
queue packet_queue;
int queued_packet_count;

static void refresh_ip_checksum(struct ip_hdr *hdr) {
    hdr->checksum = 0;
    hdr->checksum = htons(checksum((uint16_t *)hdr, sizeof(struct ip_hdr)));
}

static void reduce_ttl(struct ip_hdr *hdr) {
    int prev_ttl = hdr->ttl;
    uint16_t prev_chk = hdr->checksum;
    hdr->ttl--;
    hdr->checksum = ~(~prev_chk + ~((uint16_t)prev_ttl) + ((uint16_t)hdr->ttl)) - 1;
}

static void set_broadcast_mac(uint8_t *mac) {
    for (int i = 0; i < MAC_LEN; i++)
        mac[i] = 0xFF;
}

struct route_table_entry *route_lookup(uint32_t dest_ip) {
    struct route_table_entry *best = NULL;
    int low = 0, high = routing_count - 1;

    while (low <= high) {
        int mid = (low + high) / 2;
        if ((dest_ip & routing_entries[mid].mask) == routing_entries[mid].prefix) {
            if (!best || (ntohl(best->mask) < ntohl(routing_entries[mid].mask)))
                best = &routing_entries[mid];
        }
        if (ntohl(dest_ip) >= ntohl(routing_entries[mid].prefix))
            high = mid - 1;
        else
            low = mid + 1;
    }
    return best;
}

static void sort_routing_entries(struct route_table_entry *table, int count) {
    int i, j;
    for (i = 1; i < count; i++) {
        struct route_table_entry key = table[i];
        j = i - 1;
        while (j >= 0) {
            int cmp;
            if (ntohl(table[j].prefix) != ntohl(key.prefix))
                cmp = (ntohl(table[j].prefix) > ntohl(key.prefix)) ? -1 : 1;
            else
                cmp = (ntohl(table[j].mask) > ntohl(key.mask)) ? -1 : 1;
            
            if (cmp > 0) {
                table[j + 1] = table[j];
                j--;
            } else {
                break;
            }
        }
        table[j + 1] = key;
    }
}

static void arp_req_handler(int iface, char *buf, int len) {
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    arp->opcode = htons(2);

    memcpy(arp->thwa, arp->shwa, MAC_LEN);
    get_interface_mac(iface, arp->shwa);

    arp->tprotoa = arp->sprotoa;
    arp->sprotoa = inet_addr(get_interface_ip(iface));
    
    memcpy(eth->ethr_shost, arp->shwa, MAC_LEN);
    memcpy(eth->ethr_dhost, arp->thwa, MAC_LEN);
    
    send_to_link(len, buf, iface);
}

static void arp_rep_handler(int iface, char *buf, int len) {
    struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
    
    arp_entries[arp_count].ip = arp->sprotoa;
    memcpy(arp_entries[arp_count].mac, arp->shwa, MAC_LEN);
    arp_count++;
    
    int previous_queue_size = queued_packet_count;
    queued_packet_count = 0;
    for (int i = 0; i < previous_queue_size; i++) {
        struct packet_cache *pkt = (struct packet_cache *)queue_deq(packet_queue);
        struct ether_hdr *pkt_eth = (struct ether_hdr *)pkt->buf;
        if (ntohl(pkt->next_hop) == ntohl(arp->sprotoa)) {
            get_interface_mac(pkt->interface, pkt_eth->ethr_shost);
            memcpy(pkt_eth->ethr_dhost, arp->shwa, MAC_LEN);
            send_to_link(pkt->len, pkt->buf, pkt->interface);
            free(pkt);
        } else {
            queue_enq(packet_queue, pkt);
            queued_packet_count++;
        }
    }
}

static void cache_packet(struct route_table_entry *route, char *buf, int len) {
    struct packet_cache *cache = malloc(sizeof(struct packet_cache));
    if (!cache)
        DIE(1, "malloc failed for packet_cache");
    
    cache->len = len;
    cache->interface = route->interface;
    cache->next_hop = route->next_hop;
    cache->buf = malloc(len);
    if (!cache->buf)
        DIE(1, "malloc failed for packet buffer");
    memcpy(cache->buf, buf, len);
    
    queue_enq(packet_queue, cache);
    queued_packet_count++;
}

static int construct_arp_req(struct route_table_entry *route, char *buf, int len) {
    struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
    
    arp->hw_type = htons(HTYPE_ETHER);
    arp->proto_type = htons(IP_ETHTYPE);
    arp->hw_len = MAC_LEN;
    arp->proto_len = 4;
    arp->opcode = htons(1);
    
    arp->sprotoa = inet_addr(get_interface_ip(route->interface));
    get_interface_mac(route->interface, arp->shwa);
    arp->tprotoa = route->next_hop;
    
    uint8_t broad_mac[MAC_LEN];
    set_broadcast_mac(broad_mac);
    memcpy(arp->thwa, broad_mac, MAC_LEN);
    
    return len + sizeof(struct arp_hdr);
}

static int request_arp_and_cache(int iface, struct route_table_entry *route, char *buf, int len) {
    cache_packet(route, buf, len);
    
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    eth->ethr_type = htons(ARP_ETHTYPE);
    get_interface_mac(iface, eth->ethr_shost);
    
    uint8_t broad_mac[MAC_LEN];
    set_broadcast_mac(broad_mac);
    memcpy(eth->ethr_dhost, broad_mac, MAC_LEN);
    
    return construct_arp_req(route, buf, len);
}

static void finalize_icmp_hdr(struct icmp_hdr *icmp, uint8_t type, uint8_t code) {
    icmp->mtype = type;
    icmp->mcode = code;
    icmp->check = 0;
    icmp->check = htons(checksum((uint16_t *)icmp, sizeof(struct icmp_hdr)));
}

static void generate_icmp_echo_response(char *buf) {
    struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp = (struct icmp_hdr *)(ip + 1);
    
    uint32_t tmp = ip->source_addr;
    ip->source_addr = ip->dest_addr;
    ip->dest_addr = tmp;
    refresh_ip_checksum(ip);
    
    finalize_icmp_hdr(icmp, 0, 0);
}

static int generate_icmp_error(int iface, char *buf, int len, uint8_t error_type) {
    struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp = (struct icmp_hdr *)(ip + 1);
    
    finalize_icmp_hdr(icmp, error_type, 0);
    memcpy((icmp + 1), ip, 8);
    
    ip->dest_addr = ip->source_addr;
    ip->source_addr = inet_addr(get_interface_ip(iface));
    ip->ttl = 64;
    ip->proto = IPPROTO_ICMP;
    
    int new_len = len + sizeof(struct icmp_hdr) + 8;
    ip->tot_len = htons(ntohs(ip->tot_len) + sizeof(struct icmp_hdr) + 8);
    refresh_ip_checksum(ip);
    
    return new_len;
}

static void route_ip_packet(int iface, char *buf, int len) {
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
    
    if (ip->dest_addr == inet_addr(get_interface_ip(iface))) {
        generate_icmp_echo_response(buf);
        send_to_link(len, buf, iface);
        return;
    }
    
    if (checksum((uint16_t *)ip, sizeof(struct ip_hdr)) != 0)
        return;
    
    if (ip->ttl <= 1) {
        len = generate_icmp_error(iface, buf, len, TIMEOUT);
        send_to_link(len, buf, iface);
        return;
    }
    
    struct route_table_entry *rt_entry = route_lookup(ip->dest_addr);
    if (!rt_entry) {
        len = generate_icmp_error(iface, buf, len, NO_HOST);
        send_to_link(len, buf, iface);
        return;
    }
    
    reduce_ttl(ip);
    
    struct arp_table_entry *arp_entry = NULL;
	for (int i = 0; i < arp_count; i++) {
		if (arp_entries[i].ip == rt_entry->next_hop) {
			arp_entry = &arp_entries[i];
			break;
		}
	}

    if (!arp_entry) {
        len = request_arp_and_cache(iface, rt_entry, buf, len);
    } else {
        memcpy(eth->ethr_dhost, arp_entry->mac, MAC_LEN);
        uint8_t local_mac[MAC_LEN];
        get_interface_mac(rt_entry->interface, local_mac);
        memcpy(eth->ethr_shost, local_mac, MAC_LEN);
    }
    
    send_to_link(len, buf, rt_entry->interface);
}

static void handle_packet(size_t iface, char *buf, int len) {
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    uint16_t type = ntohs(eth->ethr_type);
    
    if (type == IP_ETHTYPE)
        route_ip_packet(iface, buf, len);
    else if (type == ARP_ETHTYPE) {
        struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
        uint16_t opcode = ntohs(arp->opcode);
        if (opcode == 1)
            arp_req_handler(iface, buf, len);
        else if (opcode == 2)
            arp_rep_handler(iface, buf, len);
    }
}

int main(int argc, char *argv[]) {
    char packet_buffer[MAX_PACKET_LEN];

    /* Do not modify */
    init(argv + 2, argc - 2);

    routing_entries = malloc(100000 * sizeof(struct route_table_entry));
    arp_entries = malloc(100 * sizeof(struct arp_table_entry));
    
    routing_count = read_rtable(argv[1], routing_entries);
    arp_count = 0;
    
	sort_routing_entries(routing_entries, routing_count);
    
    packet_queue = create_queue();
    queued_packet_count = 0;
    
    while (1) {
        size_t iface;
        size_t pkt_len;
        
        iface = recv_from_any_link(packet_buffer, &pkt_len);
        DIE(iface < 0, "recv_from_any_link");
        
        handle_packet(iface, packet_buffer, pkt_len);
    }
    
    return 0;
}
