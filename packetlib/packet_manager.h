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

        static libpacket::Packet make_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet);
    };

}

#endif //PCAP_PACKET_MANAGER_H
