//
// Created by user on 4/5/23.
//

#include <chrono>
#include "packet.h"


std::string convert_to_time(const libpacket::Timeval& timeval) {
    using namespace std::chrono;

    // convert to broken time
    std::tm bt = *std::localtime(&timeval->tv_sec);

    std::ostringstream oss;

    oss << std::put_time(&bt, "%H:%M:%S"); // HH:MM:SS
    oss << '.' << std::setfill('0') << std::setw(6) << timeval->tv_usec;

    return oss.str();
}


std::string libpacket::simple_packet::to_string() {

    using namespace libpacket;

    std::ostringstream ss;
    ss << convert_to_time(this->time);

    if (this->protocol->is_ethernet) {
        ss << " IP" << std::to_string(this->protocol->ip_v) << " ";

        auto _type = this->protocol->type;

        if (_type == protocol::protocol_type::ICMP)
        {
            ss << "ICMP "
                << this->src <<  " > " << this->dst
                << ", length " << this->bytes;
        }
        else if (_type == protocol::protocol_type::TCP)
        {
            ss << "TCP "
                << this->src << "." << this->src_port << " > " << this->dst << "." << this->dst_port
                << ", length " << this->bytes;
        }
        else if (_type == protocol::protocol_type::UDP)
        {
            ss << "UDP "
                << this->src << "." << this->src_port << " > " << this->dst << "." << this->dst_port
                << ", length " << this->bytes;
        }
    }

    return ss.str();
}
