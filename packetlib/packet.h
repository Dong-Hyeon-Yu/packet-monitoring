//
// Created by yudonghyun on 23. 4. 4.
//

#ifndef PCAP_PACKET_H
#define PCAP_PACKET_H

#include <string>
#include <cstdint>
#include <memory>
#include <sys/time.h>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace libpacket {

//    const char* icmp_type[] = {
//        "ICMP_ECHOREPLY", "ICMP not defined (1)", "ICMP not defined (2) ", "ICMP_DEST_UNREACH",
//        "ICMP_SOURCE_QUENCH", "ICMP_REDIRECT", "ICMP not defined(6)", "ICMP not defined(7)", "ICMP_ECHO",
//        "ICMP not defined(9)", "ICMP not defined(10)", "ICMP_TIME_EXCEEDED", "ICMP_PARAMETERPROB",
//        "ICMP_TIMESTAMP", "ICMP_TIMESTAMPREPLY", "ICMP_INFO_REQUEST", "ICMP_INFO_REPLY", "ICMP_ADDRESS",
//        "ICMP_ADDRESSREPLY"
//    };

    namespace protocol {
        enum protocol_type {NONE, TCP, UDP, ICMP};

        std::string string_of(protocol_type _type);

        struct protocol_info {
            protocol_type type;
            std::uint8_t ip_v;
            bool is_ethernet;
        };
        typedef std::shared_ptr<protocol_info> Protocol_info;
    }

    typedef std::shared_ptr<const struct timeval> Timeval;

    struct simple_packet {
        std::uint32_t bytes;
        Timeval time;
        std::string src;
        std::string dst;
        std::uint16_t src_port;
        std::uint16_t dst_port;
        protocol::Protocol_info protocol;
    };

    typedef std::shared_ptr<simple_packet> Packet;

    struct statistician {
        std::uint16_t n_packets;
        std::uint32_t n_bytes;

        void eat(const Packet& packet) {
            n_packets += 1;
            n_bytes += packet->bytes;
        }

        [[nodiscard]]
        std::string analyze() const {
            std::stringstream ss;

            ss << "packets: " << std::setw(5) << n_packets << ", bytes: " << std::setw(9) << n_bytes;
            return ss.str();
        }
    };

    typedef std::shared_ptr<statistician> Statistician;
}


#endif //PCAP_PACKET_H
