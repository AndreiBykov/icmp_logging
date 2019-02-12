#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>

#include "bcc/BPF.h"

const std::string BPF_PROGRAM = R"(
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IPv6 0x86DD
#define ICMPv6 58
#define ECHO_REQ 128

int icmp6_filter(struct __sk_buff *skb) { 
	u8 *cursor = 0;	

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	
	if(ethernet->type != IPv6) {
	    	goto DROP;
	}

	struct ip6_t *ip6 = cursor_advance(cursor, sizeof(*ip6));
	if (ip6->next_header != ICMPv6) {
		goto DROP;
	}

	struct icmp6_t *icmp6 = cursor_advance(cursor, sizeof(*icmp6));
	if (icmp6->type != ECHO_REQ) {
		goto DROP;
	}

	KEEP:
		return -1;

	DROP:
		return 0;
})";

const int ETH_HLEN = 14;
const int IPV6_HLEN = 40;

int main(int argc, char* argv[]) {

    std::string interface;
    std::ofstream file;

    if (argc == 2) {
        interface = argv[1];
    } else if(argc == 3) {
        interface = argv[1];
        file.open(argv[2], std::ios::out | std::ios::app);
    } else {
        std::cout << "USAGE: sudo "<< argv[0] << " <if_name> [<filename>]" << std::endl;
        return -1;
    }

    std::cout << "interface = " << interface << std::endl;

    ebpf::BPF bpf;
    auto init_res = bpf.init(BPF_PROGRAM);

    if (init_res.code() != 0) {
        std::cerr << init_res.msg() << std::endl;
        return 1;
    }

    int prog_fd;
    auto load_res = bpf.load_func("icmp6_filter", BPF_PROG_TYPE_SOCKET_FILTER, prog_fd);

    if (load_res.code() != 0) {
        std::cerr << load_res.msg() << std::endl;
        return 1;
    }

    int sock = bpf_open_raw_sock(interface.c_str());

    if (bpf_attach_socket(sock, prog_fd) != 0){
        std::cerr << "Error creating socket" << std::endl;
        return 1;
    }

    std::cout << "Socket attached" << std::endl;

    unsigned char buf[2048];
    long size;
    int sequence_number;
    int echo_id;
    timeval current_time;
    char time_str[30];

    while (true) {
        size = read(sock, buf, 2048);
        if(size != -1) {
            sequence_number = buf[ETH_HLEN + IPV6_HLEN + 6] << 8 | buf[ETH_HLEN + IPV6_HLEN + 7];
            echo_id = buf[ETH_HLEN + IPV6_HLEN + 4] << 8 | buf[ETH_HLEN + IPV6_HLEN + 5];
            
            gettimeofday(&current_time, NULL);

            strftime(time_str, 30, "%Y-%m-%d %H:%M:%S", localtime(&current_time.tv_sec));

            std::cout << echo_id << ' ' << time_str << "." << current_time.tv_usec << " "
                      << sequence_number << std::endl;
            if (file) {
                file << echo_id << ' ' << time_str << "." << current_time.tv_usec << " "
                     << sequence_number << std::endl;
                file.flush();
            }
        }
    }
}
