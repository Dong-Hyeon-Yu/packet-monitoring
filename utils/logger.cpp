//
// Created by user on 4/4/23.
//

#include <iostream>
#include <netinet/ip.h>
#include <chrono>
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

void utils::logger::info(const libpacket::Packet& packet) {

    std::cout << packet->to_string() << "\n" << std::flush;
}

