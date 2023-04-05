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
    {
        auto *ip_header = (struct ip *) _packet;

        /* set ip src & dst */
        packet->src = std::string(inet_ntoa(ip_header->ip_src));
        packet->dst = std::string(inet_ntoa(ip_header->ip_dst));

        /* set ip version */
        proto_info->ip_v = ip_header->ip_v;

        /* set protocol type */
        if (ip_header->ip_p == IPPROTO_ICMP)
            proto_info->type = libpacket::protocol::ICMP;
        else if (ip_header->ip_p == IPPROTO_TCP)
        {
            proto_info->type = libpacket::protocol::TCP;
            auto *tcph = (struct tcphdr *)(_packet + ip_header->ip_hl * 4);

            /* set port number */
            packet->src_port = ntohs(tcph->th_sport);
            packet->dst_port = ntohs(tcph->th_dport);
        }
        else if (ip_header->ip_p == IPPROTO_UDP)
        {
            proto_info->type = libpacket::protocol::UDP;
            auto *ucph = (struct udphdr *)(_packet + ip_header->ip_hl * 4);

            /* set port number */
            packet->src_port = ntohs(ucph->uh_sport);
            packet->dst_port = ntohs(ucph->uh_dport);
        }
        else
            proto_info->type = libpacket::protocol::NONE;
    }

    /* set protocol info to packet */
    packet->protocol = proto_info;

    return packet;
}