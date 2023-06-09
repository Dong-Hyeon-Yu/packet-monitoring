//
// Created by user on 4/3/23.
//

#include <csignal>
#include <setjmp.h>
#include <sstream>
#include "utils/pcap_handler.h"
#include "utils/logger.h"
#include "analyzer.h"
#include "packet_manager.h"

sig_atomic_t stopFlag = 0;
jmp_buf jmpbuf;

void handler(int)
{
    stopFlag = 1;
    longjmp(jmpbuf, 1);
}

void callback(u_char *, const struct pcap_pkthdr *pkthdr, const u_char *_packet)
{
    auto packet = libpacket::packet_manager::make_packet(pkthdr, _packet);
    utils::logger::info(packet);
    libpacket::analyzer::Gatcha(packet);
}

int main(int argc, char **argv)
{
    signal( SIGINT, &handler );

    auto *pcap = new utils::pcap_handler();

    pcap->find_all_devs();
    pcap->print_all_devs_info();

    // make filter
    std::stringstream filter;
    for(int i = 1; i<argc; i++)
        filter << " " << argv[i];

    pcap_t *pcd = pcap->set_filter(0, filter.str(), BUFSIZ, -1);

    setjmp(jmpbuf);
    if (!stopFlag) pcap->gatcha(pcd, callback);

    libpacket::analyzer::GetInstance()->analyze();

    /* save dump file */
    pcap_dumper_t *pd = pcap_dump_open(pcd, "capture.pcap");
    pcap_dump_close(pd);

}