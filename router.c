#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#define IP_ETHTYPE 0x0800
#define ARP_ETHTYPE 0x0806
#define MAC_LEN 6
#define TTL 64
#define HTYPE_ETHER 1
#define TIMEOUT 11
#define NO_HOST 3
#define ICMP_REPLY 0
#define METADATA_SIZE (sizeof(size_t) + sizeof(int) + sizeof(uint32_t))

struct route_table_entry *routing_entries;
struct arp_table_entry *arp_entries;
int routing_count;
int arp_count;
queue packet_queue;
int queued_packet_count;

/*      HELPER FUNCTIONS        */

// Reducing the TTL and updating the checksum
static void reduce_ttl(struct ip_hdr *hdr)
{
    int prev_ttl = (*hdr).ttl;
    uint16_t prev_checksum = (*hdr).checksum;
    (*hdr).ttl--;
    (*hdr).checksum = ~(~prev_checksum + ~((uint16_t)prev_ttl) + ((uint16_t)((*hdr).ttl))) - 1;
}

// Setting the boradcast MAC address to 0xFF:FF:FF:FF:FF:FF
static void set_broadcast_mac(uint8_t *mac)
{
    for (int i = 0; i < MAC_LEN; i++)
        mac[i] = 0xFF;
}

// Searching the best route that matches the destination IP using binary search
struct route_table_entry *route_lookup(uint32_t ip)
{
    struct route_table_entry *route = NULL;
    int left = 0;
    int right = routing_count - 1;

    while (left <= right) {
        int mid = (left + right) / 2;

        if ((ip & routing_entries[mid].mask) == routing_entries[mid].prefix)
            if (!route || (ntohl(routing_entries[mid].mask) > ntohl((*route).mask)))
                route = &routing_entries[mid];

        if (ntohl(ip) >= ntohl(routing_entries[mid].prefix))
            right = mid - 1;
        else
            left = mid + 1;
    }

    return route;
}

// Comparator for qsort
static int cmp_routing_entries(const void *a, const void *b)
{
    const struct route_table_entry *rt1 = (const struct route_table_entry *)a;
    const struct route_table_entry *rt2 = (const struct route_table_entry *)b;
    uint32_t prefix1 = ntohl((*rt1).prefix);
    uint32_t prefix2 = ntohl((*rt2).prefix);

    if (prefix1 != prefix2)
        return (prefix1 > prefix2) ? -1 : 1;

    uint32_t mask1 = ntohl((*rt1).mask);
    uint32_t mask2 = ntohl((*rt2).mask);

    if (mask1 != mask2)
        return (mask1 > mask2) ? -1 : 1;

    return 0;
}

// Setting packet details and enqueuing it
static void enq_packet(struct route_table_entry *route, char *buf, int len)
{
    char *block = malloc(METADATA_SIZE + len);

    *(size_t *)block = len;
    *(int *)(block + sizeof(size_t)) = (*route).interface;
    *(uint32_t *)(block + sizeof(size_t) + sizeof(int)) = (*route).next_hop;

    memcpy(block + METADATA_SIZE, buf, len);

    queue_enq(packet_queue, block);
    queued_packet_count++;
}

/*      ARP HANDLERS        */

// Handling ARP requests and sending ARP replies
static void arp_req_handler(int iface, char *buf, int len)
{
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    (*arp).opcode = htons(2);

    memcpy((*arp).thwa, (*arp).shwa, MAC_LEN);
    get_interface_mac(iface, (*arp).shwa);

    (*arp).tprotoa = (*arp).sprotoa;
    (*arp).sprotoa = inet_addr(get_interface_ip(iface));

    memcpy((*eth).ethr_shost, (*arp).shwa, MAC_LEN);
    memcpy((*eth).ethr_dhost, (*arp).thwa, MAC_LEN);

    send_to_link(len, buf, iface);
}


// Handling ARP replies by updating the ARP table and sending queued packets if possible
static void arp_rep_handler(int iface, char *buf, int len)
{
    struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    struct arp_table_entry entry;
    entry.ip = (*arp).sprotoa;
    memcpy(entry.mac, (*arp).shwa, MAC_LEN);
    arp_entries[arp_count++] = entry;

    int previous_queue_size = queued_packet_count;
    queued_packet_count = 0;

    for (int i = 0; i < previous_queue_size; i++) {
        char *block = (char *)queue_deq(packet_queue);
        size_t pkt_len = *(size_t *)block;
        int stored_iface = *(int *)(block + sizeof(size_t));
        uint32_t stored_next_hop = *(uint32_t *)(block + sizeof(size_t) + sizeof(int));
        char *packet_buf = block + METADATA_SIZE;
        struct ether_hdr *packet_eth = (struct ether_hdr *)packet_buf;

        if (ntohl(stored_next_hop) == ntohl((*arp).sprotoa)) {
            memcpy((*packet_eth).ethr_dhost, (*arp).shwa, MAC_LEN);
            memcpy((*packet_eth).ethr_shost, (*arp).thwa, MAC_LEN);
            send_to_link(pkt_len, packet_buf, stored_iface);
            free(block);
        } else {
            queue_enq(packet_queue, block);
            queued_packet_count++;
        }
    }
}

// Creating an ARP request packet
static int create_arp_req(struct route_table_entry *route, char *buf, int len)
{
    struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    (*arp).hw_type = htons(HTYPE_ETHER);
    (*arp).proto_type = htons(IP_ETHTYPE);
    (*arp).hw_len = MAC_LEN;
    (*arp).proto_len = 4;
    (*arp).opcode = htons(1);

    (*arp).sprotoa = inet_addr(get_interface_ip((*route).interface));
    get_interface_mac((*route).interface, (*arp).shwa);
    (*arp).tprotoa = (*route).next_hop;

    uint8_t broad_mac[MAC_LEN];
    set_broadcast_mac(broad_mac);
    memcpy((*arp).thwa, broad_mac, MAC_LEN);

    return len + sizeof(struct arp_hdr);
}

// Enqueueing the packet (when there is no ARP entry available) and creating an ARP request
static int enqueue_arp(int iface, struct route_table_entry *route, char *buf, int len)
{
    enq_packet(route, buf, len);

    struct ether_hdr *eth = (struct ether_hdr *)buf;
    (*eth).ethr_type = htons(ARP_ETHTYPE);
    get_interface_mac(iface, (*eth).ethr_shost);

    uint8_t broad_mac[MAC_LEN];
    set_broadcast_mac(broad_mac);
    memcpy((*eth).ethr_dhost, broad_mac, MAC_LEN);

    return create_arp_req(route, buf, len);
}

/*      ICMP HANDLER        */

// Creating an ICMP message based on the type
static int handle_icmp(int iface, char *buf, int len, uint8_t icmp_type)
{
    struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp = (struct icmp_hdr *)(ip + 1);

    (*ip).checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

    (*icmp).mtype = icmp_type;
    (*icmp).mcode = 0;
    (*icmp).check = htons(checksum((uint16_t *)icmp, sizeof(struct icmp_hdr)));

    if (icmp_type == ICMP_REPLY) {
        uint32_t aux = (*ip).source_addr;
        (*ip).source_addr = (*ip).dest_addr;
        (*ip).dest_addr = aux;
    } else {
        memcpy((icmp + 1), ip, 8);

        (*ip).source_addr = inet_addr(get_interface_ip(iface));
        (*ip).dest_addr = (*ip).source_addr;
        (*ip).ttl = TTL;
        (*ip).proto = IPPROTO_ICMP;

        len = len + sizeof(struct icmp_hdr) + 8;
        (*ip).tot_len = htons(ntohs((*ip).tot_len) + sizeof(struct icmp_hdr) + 8);
    }

    return len;
}

/*      IP PACKET HANDLER       */

// Validating and sending the ip packet
static void route_ip_packet(int iface, char *buf, int len)
{
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

    if ((*ip).dest_addr == inet_addr(get_interface_ip(iface))) {
        len = handle_icmp(iface, buf, len, ICMP_REPLY);
        send_to_link(len, buf, iface);
        return;
    }

    if (checksum((uint16_t *)ip, sizeof(struct ip_hdr)) != 0)
        return;

    if ((*ip).ttl <= 1) {
        len = handle_icmp(iface, buf, len, TIMEOUT);
        send_to_link(len, buf, iface);
        return;
    }

    struct route_table_entry *rt_entry = route_lookup((*ip).dest_addr);
    if (!rt_entry) {
        len = handle_icmp(iface, buf, len, NO_HOST);
        send_to_link(len, buf, iface);
        return;
    }

    reduce_ttl(ip);

    struct arp_table_entry *arp_entry = NULL;
    for (int i = 0; i < arp_count; i++)
        if (arp_entries[i].ip == (*rt_entry).next_hop) {
            arp_entry = &arp_entries[i];
            break;
        }

    if (!arp_entry) {
        len = enqueue_arp(iface, rt_entry, buf, len);
    } else {
        memcpy((*eth).ethr_dhost, (*arp_entry).mac, MAC_LEN);
        uint8_t local_mac[MAC_LEN];
        get_interface_mac((*rt_entry).interface, local_mac);
        memcpy((*eth).ethr_shost, local_mac, MAC_LEN);
    }

    send_to_link(len, buf, (*rt_entry).interface);
}

/*      PACKET HANDLER      */

// Checking the type of the packet and calling the appropriate handler
static void handle_packet(size_t iface, char *buf, int len)
{
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    uint16_t type = ntohs((*eth).ethr_type);

    if (type == IP_ETHTYPE) {
        route_ip_packet(iface, buf, len);
    } else if (type == ARP_ETHTYPE) {
        struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
        uint16_t opcode = ntohs((*arp).opcode);

        if (opcode == 1)
            arp_req_handler(iface, buf, len);
        else if (opcode == 2)
            arp_rep_handler(iface, buf, len);
    }
}

/*      MAIN        */

// Initializing the router and starting the main loop
int main(int argc, char *argv[])
{
    char packet_buffer[MAX_PACKET_LEN];

    /* Do not modify */
    init(argv + 2, argc - 2);

    routing_entries = malloc(100000 * sizeof(struct route_table_entry));
    arp_entries = malloc(100 * sizeof(struct arp_table_entry));

    routing_count = read_rtable(argv[1], routing_entries);
    qsort(routing_entries, routing_count, sizeof(struct route_table_entry), cmp_routing_entries);

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
