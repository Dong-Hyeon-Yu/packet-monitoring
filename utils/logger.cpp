//
// Created by user on 4/4/23.
//

#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <chrono>
#include <iomanip>
#include <arpa/inet.h>
#include "logger.h"

// Get current date/time, format is YYYY-MM-DD.HH:mm:ss
std::string utils::logger::currentDateTime() {
    time_t now = time(nullptr);
    struct tm tstruct{};
    char buf[80];

    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

    return buf;
}

std::string utils::logger::currentTime() {
    using namespace std::chrono;

    // get current time
    auto now = system_clock::now();

    // get number of milliseconds for the current second
    // (remainder after division into seconds)
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

    // convert to std::time_t in order to convert to std::tm (broken time)
    auto timer = system_clock::to_time_t(now);

    // convert to broken time
    std::tm bt = *std::localtime(&timer);

    std::ostringstream oss;

    oss << std::put_time(&bt, "%H:%M:%S"); // HH:MM:SS
    oss << '.' << std::setfill('0') << std::setw(6) << ms.count();

    return oss.str();
}

//template<typename T>
//void utils::logger::info(const T& object, const std::string& message) {
//    std::cout << "[info::" << typeid(object).name() << "] - [" << currentDateTime() << "] - " << message << std::endl;
//}
//
//template<typename T>
//void utils::logger::warn(const T& object, const std::string &message) {
//    std::cout << "[warn::" << typeid(object).name() << "] - [" << currentDateTime() << "] - " << message << std::endl;
//}
//
//template<typename T>
//void utils::logger::error(const T& object, const std::string &message) {
//    std::cout << "[error::" << typeid(object).name() << "] - [" << currentDateTime() << "] - " << message << std::endl;
//    exit(1);
//}

void utils::logger::_print_icmp_packet(struct ip *iph, unsigned length, const u_char *packet) {

    std::string message( reinterpret_cast<char const*>(packet), length );

    std::cout
        << currentTime()
        << " IP" << iph->ip_v << " "
        << utils::logger::_protocol(iph->ip_p) << " "
        << inet_ntoa(iph->ip_src) <<  " > " << inet_ntoa(iph->ip_dst)
        << ": " << message << ", length " << length
        << std::endl;
}

std::string utils::logger::_protocol(uint8_t protocol) {
    if (protocol == IPPROTO_TCP)
        return "TCP";
    else if (protocol == IPPROTO_UDP)
        return "UDP";
    else if (protocol== IPPROTO_ICMP)
        return "ICMP";
    else
        return " ";
}

void utils::logger::_print_segment(struct ip *iph, unsigned length, const u_char *packet) {

    auto *tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);

    std::cout
            << currentTime()
            << " IP" << iph->ip_v << " "
            << utils::logger::_protocol(iph->ip_p) << " "
            << inet_ntoa(iph->ip_src) <<  "." << tcph->th_sport << " > " << inet_ntoa(iph->ip_dst) << "." << tcph->th_dport
            << ", length " << length
            << std::endl;
}

void utils::logger::info(const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    auto *ep = (struct ether_header *)packet;  // get ethernet header
    packet += sizeof(struct ether_header);  // get IP header
    unsigned short ether_type = ntohs(ep->ether_type);  // get protocol
    if (ether_type == ETHERTYPE_IP)
    {

        auto *ip_header = (struct ip *) packet;
        if (ip_header->ip_p == IPPROTO_ICMP)
        {
            utils::logger::_print_icmp_packet(ip_header, pkthdr->len, packet);
        }
        else if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP)
        {
            utils::logger::_print_segment(ip_header, pkthdr->len, packet);
        }
    }
}

