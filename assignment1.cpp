//
// Created by user on 4/3/23.
//

#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <sstream>
#include "utils/pcap_handler.h"
#include "utils/logger.h"

//const char* icmp_type[] = {
//        "ICMP_ECHOREPLY", "ICMP not defined (1)", "ICMP not defined (2) ", "ICMP_DEST_UNREACH",
//        "ICMP_SOURCE_QUENCH", "ICMP_REDIRECT", "ICMP not defined(6)", "ICMP not defined(7)", "ICMP_ECHO",
//        "ICMP not defined(9)", "ICMP not defined(10)", "ICMP_TIME_EXCEEDED", "ICMP_PARAMETERPROB",
//        "ICMP_TIMESTAMP", "ICMP_TIMESTAMPREPLY", "ICMP_INFO_REQUEST", "ICMP_INFO_REPLY", "ICMP_ADDRESS",
//        "ICMP_ADDRESSREPLY"
//};

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    utils::logger::info(pkthdr, packet);
}

int main(int argc, char **argv)
{
    auto *pcap = new utils::pcap_handler();


    pcap->find_all_devs();

    pcap->print_all_devs_info();

    // make filter
    std::stringstream filter;
    for(int i = 1; i<argc; i++)
        filter << " " << argv[i];

    pcap_t *pcd = pcap->set_filter(0, filter.str(), BUFSIZ, -1);

    pcap->gatcha(pcd, callback);
}