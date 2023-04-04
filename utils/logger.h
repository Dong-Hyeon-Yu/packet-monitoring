//
// Created by user on 4/4/23.
//

#ifndef PCAP_LOGGER_H
#define PCAP_LOGGER_H

#include <string>
#include <pcap.h>
#include <iostream>

namespace utils {
    class logger {
    public:
        logger()= default;

        static std::string currentDateTime();
        static std::string currentTime();

        template<typename T>
        static void info(const T& object, const std::string& message) {
            std::cout << "[info::" << typeid(object).name() << "] - [" << currentDateTime() << "] - " << message << std::endl;
        }

        template<typename T>
        static void warn(const T& object, const std::string &message) {
            std::cout << "[warn::" << typeid(object).name() << "] - [" << currentDateTime() << "] - " << message << std::endl;
        }

        template<typename T>
        static void error(const T& object, const std::string &message) {
            std::cout << "[error::" << typeid(object).name() << "] - [" << currentDateTime() << "] - " << message << std::endl;
            exit(1);
        }

        static void info(const struct pcap_pkthdr *pkthdr, const u_char *packet);

    private:
        static void _print_icmp_packet(struct ip *iph, unsigned length, const u_char *packet);
        static void _print_segment(struct ip *iph, unsigned length, const u_char *packet);
        static std::string _protocol(uint8_t);
    };
}


#endif //PCAP_LOGGER_H
