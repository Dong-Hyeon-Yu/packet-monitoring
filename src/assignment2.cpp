//
// Created by yudonghyun on 23. 4. 5.
//

#include <sstream>
#include <csignal>
#include <setjmp.h>
#include "utils/pcap_handler.h"
#include "utils/logger.h"
#include "packetlib/packet_manager.h"
#include "packetlib/analyzer.h"

sig_atomic_t stopFlag = 0;
jmp_buf jmpbuf;

void handler(int)
{
    stopFlag = 1;
    longjmp(jmpbuf, 1);
}

void callback(u_char *, const struct pcap_pkthdr *pkthdr, const u_char *_packet)
{
    utils::logger::info(pkthdr, _packet);
    libpacket::analyzer::Gatcha(
            libpacket::packet_manager::make_packet(pkthdr, _packet));
}

int main(int argc, char **argv)
{
    signal( SIGINT, &handler );

    auto *pcap = new utils::pcap_handler();

    setjmp(jmpbuf);
    if (!stopFlag) pcap->gatcha(argv[1], callback);

    libpacket::analyzer::GetInstance()->analyze();
}