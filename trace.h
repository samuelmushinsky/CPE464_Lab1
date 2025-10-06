#ifndef TRACE_H
#define TRACE_H

#include <stdint.h>

// found a load of these structs online, they seem to be legit and working for 
// my needs. also copilot helped a bit to fill in some standarized things / comments

typedef struct ethernet_header
{
    uint8_t dest_mac[6]; // dest. mac address
    uint8_t src_mac[6];  // src. mac address
    uint16_t type;   // ethernet type
}__attribute__((__packed__)) ethernet_header_t;

typedef struct arp_header
{
    uint16_t hw_type;      // hardware type
    uint16_t proto_type;   // protocol type
    uint8_t hw_len;       // hardware address length
    uint8_t proto_len;   // protocol address length
    uint16_t opcode;     // operation code
    uint8_t sender_mac[6]; 
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
}__attribute__((__packed__)) arp_header_t;

typedef struct ip_header 
{
    uint8_t  version_ihl;     // version
    uint8_t  tos;             // type of service
    uint16_t total_length;    // total len
    uint16_t identification;  // identification
    uint16_t flags_offset;    // flags
    uint8_t  ttl;             
    uint8_t  protocol;        // protocol (1=ICMP,6=TCP,17=UDP)
    uint16_t checksum;        
    uint32_t src_ip;          // source ip
    uint32_t dst_ip;          // dest ip
} __attribute__((packed)) ip_header_t;

typedef struct icmp_header 
{
    uint8_t  type;          // msg type (8=request, 0=reply)
    uint8_t  code;          
    uint16_t checksum;      
    uint16_t identifier;    
    uint16_t sequence;      
} __attribute__((packed)) icmp_header_t;

typedef struct tcp_header 
{
    uint16_t src_port;      // src port
    uint16_t dst_port;      // dest port
    uint32_t seq_num;       // seq number
    uint32_t ack_num;       // ack number
    uint8_t  data_offset;   // data offset (upper 4 bits) + reserved bits
    uint8_t  flags;         
    uint16_t window;        
    uint16_t checksum;      
    uint16_t urgent_ptr;    
} __attribute__((packed)) tcp_header_t;

typedef struct udp_header 
{
    uint16_t src_port;      // src port
    uint16_t dst_port;      // dest port
    uint16_t length;        // datagram len
    uint16_t checksum;      
} __attribute__((packed)) udp_header_t;

#endif