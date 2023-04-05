//
// Created by yudonghyun on 23. 4. 4.
//
#define __FAVOR_BSD
#include "packet_manager.h"
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <memory>
#define GTP_E_MASK          0x04
#define GTP_S_MASK          0x02
#define GTP_PN_MASK         0x01
struct gtp_header {
    uint8_t flags;
    uint8_t message_type;
    uint16_t length;
    uint32_t TEID;
};


libpacket::Packet libpacket::packet_manager::make_packet(const struct pcap_pkthdr *pkthdr, const u_char *_packet)
{
    auto *ep = (struct ether_header *)_packet;  // get ethernet header
    _packet += sizeof(struct ether_header);  // get IP header
    unsigned short ether_type = ntohs(ep->ether_type);  // get protocol

    Packet packet(new simple_packet{});
    protocol::Protocol_info proto_info(new protocol::protocol_info{});

    /* set packet size */
    packet->bytes = pkthdr->caplen;

    /* set captured time */
    packet->time = std::make_shared<timeval>(pkthdr->ts);

    /* only process if this packet is ethernet type */
    if ((proto_info->is_ethernet = (ether_type == ETHERTYPE_IP)))
        _process_ip_packet(_packet, packet, proto_info);

    if(packet->is_GTP())
    {
        auto *ip_header = (struct ip *) _packet;
        _packet += ip_header->ip_hl * 4;  // udp pointer
        _packet += sizeof(struct udphdr);  // gtp pointer

        int offset = 8;
        auto *gtp_hdr = (gtp_header*)_packet;  // gtp header
        if (gtp_hdr->flags & (GTP_S_MASK|GTP_PN_MASK|GTP_E_MASK))
        {
            offset += 4;
            if(gtp_hdr->flags & GTP_E_MASK){

                uint8_t next_extension = 0;
                do {
                    uint8_t extension_length = (*(uint8_t *) (_packet + offset)) * 4;

                    offset += extension_length;
                    next_extension = *(uint8_t *) (_packet + offset - 1);
                } while (next_extension != 0);
            }
        }
        _packet += offset;
        _process_ip_packet(_packet, packet, proto_info);
    }

    /* set protocol info to packet */
    packet->protocol = proto_info;

    return packet;
}

void libpacket::packet_manager::_process_ip_packet(const u_char *_packet, libpacket::Packet &packet,
                                                                libpacket::protocol::Protocol_info &proto_info) {
    auto *ip_header = (struct ip *) _packet;

    /* set ip src & dst */
    packet->src = std::string(inet_ntoa(ip_header->ip_src));
    packet->dst = std::string(inet_ntoa(ip_header->ip_dst));

    /* set ip version */
    proto_info->ip_v = ip_header->ip_v;

    /* set protocol type */
    if (ip_header->ip_p == IPPROTO_ICMP)
        proto_info->type = protocol::ICMP;
    else if (ip_header->ip_p == IPPROTO_TCP)
    {
        proto_info->type = protocol::TCP;
        auto *tcph = (struct tcphdr *)(_packet + ip_header->ip_hl * 4);

        /* set port number */
        packet->src_port = ntohs(tcph->th_sport);
        packet->dst_port = ntohs(tcph->th_dport);
    }
    else if (ip_header->ip_p == IPPROTO_UDP)
    {
        proto_info->type = protocol::UDP;
        auto *ucph = (struct udphdr *)(_packet + ip_header->ip_hl * 4);

        /* set port number */
        packet->src_port = ntohs(ucph->uh_sport);
        packet->dst_port = ntohs(ucph->uh_dport);
    }
    else
        proto_info->type = protocol::NONE;
}
