/*#include <tins/tins.h>
#include <iostream>
#include <stddef.h>

using namespace Tins;

size_t counter(0);
// This is a handler used in Sniffer::sniff_loop
bool handler(const PDU& pkt) {
    // Lookup the UDP PDU
    const UDP &udp = pkt.rfind_pdu<UDP>();
    // We need source/destination port to be 53
    if (udp.sport() == 53 || udp.dport() == 53) {
        // Interpret it as DNS. This might throw, but Sniffer catches it
        DNS dns = pkt.rfind_pdu<RawPDU>().to<DNS>();
        // Just print out each query's domain name
        for (const auto &query : dns.queries()) {
            std::cout << query.dname() << std::endl;
        }
    }
    return true;
}
bool count_packets(const PDU &) {
    counter++;
    // Always keep looping. When the end of the file is found,
    // our callback will simply not be called again.
    return true;
}

int main() {
    FileSniffer sniffer("PCAPdroid_07_авг._23_17_23.pcap");
    sniffer.sniff_loop(count_packets);
    sniffer.sniff_loop(handler);
    std::cout << "There are " << counter << " packets in the pcap file\n";
}*/
/*
#include <tins/tins.h>
#include <iostream>
#include <stddef.h>

using namespace Tins;
bool doo(PDU &some_pdu) {
    // Search for it. If there is no IP PDU in the packet,
    // the loop goes on
    const IP &ip = some_pdu.rfind_pdu<IP>(); // non-const works as well
    std::cout << "Destination address: " << ip->dst_addr() << std::endl;
    // Just one packet please
    return false;
}



int main() {
    FileSniffer sniffer("PCAPdroid_07_авг._23_17_23.pcap");
    sniffer.sniff_loop(doo);
    //sniffer.sniff_loop(handler);
   // std::cout << "There are " << counter << " packets in the pcap file\n";
}
*/
/*
#include <vector>
#include <iostream>
#include <stddef.h>

#include <tins/tins.h>

using namespace Tins;

int main() {
    std::vector<Packet> vt;

    //Sniffer sniffer("eth0");
      FileSniffer sniffer("PCAPdroid_07_авг._23_17_23.pcap");
    while (vt.size() != 10) {
        // next_packet returns a PtrPacket, which can be implicitly converted to Packet.
        vt.push_back(sniffer.next_packet());
    }
    // Done, now let's check the packets
    for (const auto& packet : vt) {
        // Is there an IP PDU somewhere?
        if (packet.pdu()->find_pdu<IP>()) {
            // Just print timestamp's seconds and IP source address
            std::cout << "At: " << packet.timestamp().seconds()
                    << " - " << packet.pdu()->rfind_pdu<IP>().src_addr()
                    << std::endl;
        }
    }
}
*/
/*#include <iostream>
#include <tins/tins.h>
using namespace Tins;
using namespace std;
bool packetHandler(PDU &pdu)
{
    // Find the IP layer
    const IP &ip = pdu.rfind_pdu<IP>();
    std::cout << ip.src_addr() << " -> " << ip.dst_addr() << endl;
    return true;
}
int main() {
    FileSniffer sniffer("PCAPdroid_07_авг._23_17_23.pcap");
    sniffer.sniff_loop(packetHandler);
}*/

#include <iostream>
#include <tins/tins.h>
using namespace Tins;
using namespace std;
bool packetHandler(PDU &pdu)
{
    // Find the IP layer
    const IP &ip = pdu.rfind_pdu<IP>();
    //std::cout << ip.src_addr() << " -> " << ip.dst_addr() << endl;
     DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();
    for (const auto& query : dns.queries()) {
      cout << query.dname() << std::endl;
  }

    return true;
}
int main() {
    FileSniffer sniffer("PCAPdroid_07_авг._23_17_23.pcap");
    sniffer.sniff_loop(packetHandler);
}
/*
#include <tins/tins.h>
#include <iostream>
#include <stddef.h>

using namespace Tins;

size_t counter(0);

bool count_packets(const PDU &pdu)
{
	counter ++;
	const IP &ip = pdu.rfind_pdu<IP>(); // Find the IP layer
    const TCP &tcp = pdu.rfind_pdu<TCP>(); // Find the TCP layer
    const RadioTap &radio = pdu.rfind_pdu<RadioTap>(); // Find the RadioTap layer
    std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
              << ip.dst_addr() << ':' << tcp.dport() << std::endl;
	std::cout << radio.channel_freq() << std::endl;
	return true;
}

int main()
{
	FileSniffer sniffer("PCAPdroid_07_авг._23_17_23.pcap");
	sniffer.sniff_loop(count_packets);
	std::cout << "There are " << counter << " packets in the pcap file\n";
};*/
