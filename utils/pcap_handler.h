//
// Created by user on 4/4/23.
//

#ifndef PCAP_PCAP_HANDLER_H
#define PCAP_PCAP_HANDLER_H

#include <pcap/pcap.h>
#include <vector>
#include <unordered_map>

namespace utils {

    typedef void (*pcap_callback)(u_char *, const struct pcap_pkthdr *, const u_char *);

    struct device_info {
        pcap_if_t *device;
        bpf_u_int32 *network;
        bpf_u_int32 *mask;
        std::string network_str;
        std::string mask_str;
    };

    class pcap_handler {
    public:
        pcap_handler() = default;

        void find_all_devs();
        void print_all_devs_info();

        pcap_t* set_filter(const std::string& device_name, const std::string& filter, int buffer_size, int listening_duration_in_sec, bool promiscuous_mode = false);
        pcap_t* set_filter(int device_no, const std::string& filter, int buffer_size, int listening_duration_in_sec, bool promiscuous_mode = false);
        void gatcha(pcap_t *pcd, pcap_callback callback);
        void gatcha(const std::string& file_name, pcap_callback callback);

    private:
        std::vector<device_info*> devices;
        std::unordered_map<pcap_t*, int> device_no_of;
        utils::device_info* _find_by_name(const std::string& device_name);

        pcap_t* get_pcd(const std::string& device_name, int buffer_size, int listening_duration_in_sec, bool promiscuous_mode = false);
        pcap_t* get_pcd(int device_no, int buffer_size, int listening_duration_in_sec, bool promiscuous_mode = false);
        pcap_t* get_pcd_for_file(const std::string& file_name);
    };
}

#endif //PCAP_PCAP_HANDLER_H
