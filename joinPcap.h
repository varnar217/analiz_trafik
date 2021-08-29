# include <pcap.h>

# ifndef _PKTSTRUCT_H_
# define _PKTSTRUCT_H_
# ifndef _MERGEPCAP_H_
# define _MERGEPCAP_H_
struct pktStruct {
	struct pcap_pkthdr pkt_header; // header object
	const u_char * pkt_data; // data object
	long time; // used to compare with each other
};

#endif
