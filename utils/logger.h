//
// Created by user on 4/4/23.
//

#ifndef PCAP_LOGGER_H
#define PCAP_LOGGER_H

#include <string>
#include <pcap.h>
#include <iostream>
#include "packet.h"

namespace utils {
    class logger {
    public:
        logger()= default;

        static std::string currentDateTime();

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

        static void info(const libpacket::Packet& packet);
    };
}


#endif //PCAP_LOGGER_H
