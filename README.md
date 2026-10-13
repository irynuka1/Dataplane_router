# Dataplane Router

A software router dataplane written in C. It receives raw Ethernet frames, forwards IPv4 packets using longest-prefix match, resolves next-hop MAC addresses with ARP, and generates ICMP replies and errors.

Built as a university networking assignment (Communication Protocols, UPB) on top of a provided link-layer API (`lib/`) and a Mininet-based checker.

## Features

| Area | Behaviour |
|------|-----------|
| **IPv4 forwarding** | Validates the header checksum, drops expired packets, decrements TTL and incrementally updates the checksum (RFC 1624). |
| **Routing (LPM)** | Static routing table loaded at startup, sorted once with `qsort`, then searched with binary search. |
| **ARP** | Answers ARP requests, sends requests for unknown next hops, and caches replies in a dynamic ARP table. |
| **Packet queue** | Packets waiting for ARP resolution are queued and flushed when the matching reply arrives. |
| **ICMP** | Echo Reply for packets addressed to the router, Time Exceeded (type 11) on TTL expiry, Destination Unreachable (type 3) when no route exists. |

## Project layout

```
.
├── router.c          # Router logic: forwarding, ARP, ICMP
├── include/
│   ├── protocols.h   # Ethernet, IP, ARP and ICMP header structs
│   ├── lib.h         # Link-layer API (recv/send, route table reader, checksum)
│   ├── queue.h       # Queue interface
│   └── list.h        # Linked list interface
├── lib/              # Provided support code (lib.c, queue.c, list.c)
├── checker/          # Mininet topology and automated tests
├── rtable0.txt       # Routing table for router 0
├── rtable1.txt       # Routing table for router 1
├── Makefile
└── create_archive.sh # Packs the submission archive
```

## How it works

```
recv_from_any_link
        │
   handle_packet ── EtherType ──┬─ 0x0800 (IPv4) → route_ip_packet
                                └─ 0x0806 (ARP)  → arp_req_handler / arp_rep_handler
```

**IPv4 path (`route_ip_packet`)**

1. If the packet is addressed to the router, answer with an ICMP Echo Reply.
2. Verify the IP checksum; drop the packet if it is corrupt.
3. If `TTL <= 1`, send ICMP *Time Exceeded*.
4. Look up the best route (`route_lookup`); if none exists, send ICMP *Destination Unreachable*.
5. Decrement TTL (`reduce_ttl`) and look up the next hop in the ARP table.
6. On a hit, rewrite the Ethernet addresses and forward. On a miss, queue the packet and broadcast an ARP request.

**ARP path**

- *Request:* turn the received frame into a reply carrying the interface MAC.
- *Reply:* store the IP→MAC mapping, then walk the queue and send every packet whose next hop matches; the rest stay queued.

### Key data structures

- **`routing_entries`** – array of `route_table_entry` (up to 100k), sorted by prefix and mask in descending order.
- **`arp_entries`** – array of `arp_table_entry` holding learned IP→MAC mappings.
- **`packet_queue`** – queue of heap blocks, each laid out as `[length | out interface | next hop | frame bytes]` (see `METADATA`).

## Build and run

```bash
make                                    # build ./router
./router <rtable> <iface0> <iface1> ... # e.g. ./router rtable0.txt rr-0-1 r-0 r-1
make clean
```

Shortcuts: `make run_router0` and `make run_router1`.

Routing table format (one route per line): `prefix next_hop mask interface`

```
192.127.86.0 192.127.86.2 255.255.255.0 0
```

## Testing

The checker builds a Mininet topology with two routers and several hosts, then runs forwarding, ARP, ICMP and LPM tests. It needs Mininet and root privileges:

```bash
./checker/checker.sh
```
