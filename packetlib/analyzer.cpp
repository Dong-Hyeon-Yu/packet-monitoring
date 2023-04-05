//
// Created by yudonghyun on 23. 4. 5.
//

#include <iomanip>
#include "analyzer.h"
#include "packet.h"

void libpacket::analyzer::yummy(const libpacket::Packet& packet) {

    if (!packet->protocol->is_ethernet) {
        n_drops += 1;
        return;
    }

    if (citizen_of_[packet->protocol->type] == nullptr)
        citizen_of_[packet->protocol->type] = std::make_shared<statistician>();
    if (mailman_of_[packet->dst] == nullptr)
        mailman_of_[packet->dst] = std::make_shared<statistician>();
    if (developer_of_[packet->dst_port] == nullptr)
        developer_of_[packet->dst_port] = std::make_shared<statistician>();


    citizen_of_[packet->protocol->type]->eat(packet);
    mailman_of_[packet->dst]->eat(packet);
    developer_of_[packet->dst_port]->eat(packet);
    _time_to_eat(packet);
}

void libpacket::analyzer::_time_to_eat(const libpacket::Packet &packet) {
    n_packets += 1;
    n_bytes += packet->bytes;
}

void libpacket::analyzer::Gatcha(const libpacket::Packet &packet) {
    using namespace libpacket;

    Analyzer analyst = analyzer::GetInstance();
    analyst->yummy(packet);
}

std::string libpacket::protocol::string_of(libpacket::protocol::protocol_type _type){
    if (_type == TCP) return "TCP";
    else if (_type == UDP) return "UDP";
    else if (_type == ICMP) return "ICMP";
    else return "NONE";
}

void libpacket::analyzer::analyze() {

    std::cout << "\n===================== SUMMARY ========================" << std::endl;

    std::cout << "::Protocols::\n";
    for (auto [protocol, citizen]: citizen_of_)
        std::cout << "  [" <<  libpacket::protocol::string_of(protocol) << "]\n      " << citizen->analyze() << std::endl;

    std::cout << "\n::IP addresses::\n";
    for (auto [dst, mailman]: mailman_of_)
        std::cout << "  [" <<  dst << "]\n      " << mailman->analyze() << std::endl;

    std::cout << "\n::Applications(#port)::\n";
    for (auto [port, developer]: developer_of_)
        std::cout << "  [" <<  port << "]\n      "  << developer->analyze() << std::endl;

    std::cout << "\n::Total::\n "
        << " packets: " << std::setw(5) << this->n_packets
        << ", drops: " << std::setw(5) << this->n_drops
        << ", bytes: " << std::setw(9) << this->n_bytes;

    std::cout << "\n===================== END ========================" << std::endl;
}


libpacket::analyzer::~analyzer() {
    analyze();
    citizen_of_.clear();
    mailman_of_.clear();
    developer_of_.clear();
}


