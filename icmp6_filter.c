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
}
