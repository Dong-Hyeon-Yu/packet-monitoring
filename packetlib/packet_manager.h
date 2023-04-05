//
// Created by yudonghyun on 23. 4. 4.
//

#ifndef PCAP_PACKET_MANAGER_H
#define PCAP_PACKET_MANAGER_H

#include "packet.h"
#include <pcap.h>

namespace libpacket {

    class packet_manager {
    public:
        packet_manager()= default;

        static Packet make_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet);

        static void _process_ip_packet(const u_char *_packet, Packet &packet, protocol::Protocol_info &proto_info);
    };

}

#endif //PCAP_PACKET_MANAGER_H
