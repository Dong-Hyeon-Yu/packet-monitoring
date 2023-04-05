//
// Created by user on 4/4/23.
//

#include <iostream>
#include <sstream>
#include "pcap_handler.h"
#include "logger.h"

void utils::pcap_handler::find_all_devs() {
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_if_t *dev;

    pcap_findalldevs(&dev, err_buf);
    if (dev == nullptr)
        utils::logger::error(this, err_buf);

    do {
        // fetch additional information
        bpf_u_int32 netp, maskp;
        if (pcap_lookupnet(dev->name, &netp, &maskp, err_buf) < 0)
            utils::logger::warn(this, err_buf);

        struct in_addr net_addr{}, mask_addr{};
        net_addr.s_addr = netp;
        std::string net(inet_ntoa(net_addr));

        mask_addr.s_addr = maskp;
        std::string mask(inet_ntoa(mask_addr));

        this->devices.push_back(new device_info{dev, &netp, &maskp, net, mask});

    } while (dev->next != nullptr && (dev = dev->next));

    std::stringstream _msg;
    _msg << "find devices (total" << this->devices.size() << ").";
    utils::logger::info(this, _msg.str());
}

void utils::pcap_handler::print_all_devs_info() {
    int index = 0;
    for (auto dev_info: this->devices) {
        std::cout << "Device[" << index << "] : " << dev_info->device->name << "\n";
        std::cout << "Network : " << dev_info->network_str << "\n";
        std::cout << "Mask : " << dev_info->mask_str << "\n";
        std::cout << "=======================" << "\n" << std::endl;
        index += 1;
    }
}

pcap_t* utils::pcap_handler::get_pcd(
        const std::string& device_name,
        int buffer_size,
        int listening_duration_in_sec,
        bool promiscuous_mode
        ){
    char err_buf[PCAP_ERRBUF_SIZE];

    pcap_t *pcd = pcap_open_live(device_name.c_str(), buffer_size,  promiscuous_mode, listening_duration_in_sec, err_buf);
    if(pcd == nullptr)
        utils::logger::error(this, err_buf);

    return pcd;
}

pcap_t *utils::pcap_handler::get_pcd(
        int device_no,
        int buffer_size,
        int listening_duration_in_sec,
        bool promiscuous_mode
        ) {
    return utils::pcap_handler::get_pcd(
            this->devices[device_no]->device->name,
            buffer_size,
            listening_duration_in_sec,
            promiscuous_mode);
}


pcap_t *utils::pcap_handler::get_pcd_for_file(const std::string &file_name) {
    char err_buf[PCAP_ERRBUF_SIZE];

    pcap_t *pcd = pcap_open_offline(file_name.c_str(), err_buf);

    if (pcd == nullptr)
        utils::logger::error(this, err_buf);

    return pcd;
}

pcap_t * utils::pcap_handler::set_filter(
        const std::string& device_name,
        const std::string& filter,
        int buffer_size,
        int listening_duration_in_sec,
        bool promiscuous_mode
        ) {

    pcap_t *pcd = utils::pcap_handler::get_pcd(device_name, buffer_size, promiscuous_mode,
                                               listening_duration_in_sec);

    struct bpf_program fp{};
    if (pcap_compile(pcd, &fp, filter.c_str(), 0, *utils::pcap_handler::_find_by_name(device_name)->network) == -1)
        utils::logger::error(this, "pcap_compile error.");
    if (pcap_setfilter(pcd, &fp) == -1)
        utils::logger::error(this, "pcap_setfilter error.");

    return pcd;
}

pcap_t *utils::pcap_handler::set_filter(
        int device_no,
        const std::string& filter,
        int buffer_size,
        int listening_duration_in_sec,
        bool promiscuous_mode) {

    pcap_t *pcd = utils::pcap_handler::get_pcd(device_no, buffer_size, listening_duration_in_sec, promiscuous_mode);

    struct bpf_program fp{};
    if (pcap_compile(pcd, &fp, filter.c_str(), 0, *this->devices[device_no]->network) == -1)
        utils::logger::error(this, "pcap_compile error.");
    if (pcap_setfilter(pcd, &fp) == -1)
        utils::logger::error(this, "pcap_setfilter error.");

    return pcd;
}

void utils::pcap_handler::gatcha(pcap_t *pcd, pcap_callback callback) {
    pcap_loop(pcd, -1, callback, nullptr);
}

void utils::pcap_handler::gatcha(const std::string& file_name, pcap_callback callback) {

    pcap_t * pcd = utils::pcap_handler::get_pcd_for_file(file_name);

    int res;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    while((res = pcap_next_ex(pcd, &header, &pkt_data)) >= 0)
        callback(nullptr, header, pkt_data);

    if (res == -1){
        pcap_close(pcd);
        utils::logger::error(this, pcap_geterr(pcd));
    }

    pcap_close(pcd);
}

utils::device_info *utils::pcap_handler::_find_by_name(const std::string &device_name) {

    for (auto info:this->devices) {
        if (info->device->name == device_name)
            return info;
    }
    return nullptr;
}
