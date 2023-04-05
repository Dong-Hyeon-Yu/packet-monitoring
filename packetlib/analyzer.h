//
// Created by yudonghyun on 23. 4. 5.
//

#ifndef PCAP_ANALYZER_H
#define PCAP_ANALYZER_H

#include "packet.h"
#include "template_singleton.h"
#include <map>

namespace libpacket {

    class analyzer;
    typedef analyzer* Analyzer;

    class analyzer : public template_singleton<analyzer> {
    public:
        analyzer()=default;

        ~analyzer() override;

        void yummy(const Packet& packet);
        void analyze();
        [[nodiscard]] bool check_too_much_ate() const;
        static void Gatcha(const Packet& packet);

    private:
        std::map<protocol::protocol_type, Statistician> citizen_of_;  // protocol
        std::map<std::string, Statistician> mailman_of_;  // dst
        std::map<std::uint16_t, Statistician> developer_of_;  // app (#port)

        uint16_t n_packets = 0;
        uint16_t n_drops = 0;
        uint32_t n_bytes = 0;
        const uint16_t capacity = 500;

        void _time_to_eat(const Packet& packet);
    };


}

#endif //PCAP_ANALYZER_H
