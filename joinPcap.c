
//Read 2 .pcap files and merge them into 1 .pcap file with all the packets are sorted by time stamp
#include <string.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include "pktStruct.h" // in which I define a struct to save each packet's header and data
#include "joinPcap.h" // in which I define a struct to save each packet's header and data

using namespace std;
void sortPcap(pcap_t * spcap);

bool comparison(pktStruct a, pktStruct b);
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header,
		const u_char *pkt_data); // pcaket_handler
char errbuff[PCAP_ERRBUF_SIZE]; // errbuff is the error message when pcap_open_offline() method fails

/*************************************************************************************/
/* READ EACH ANOTATION OF THESE FOUR STRINGS AND VALUE THEM WITH THE VALUE BY YOUR OWN */
/*************************************************************************************/
string file1 = "100_seconds.pcap"; // declare the file location and the filename of file1(104)
string file2 = "DiscordVideoLTE.pcap"; // declare the file location and the filename of file2(53)
string tmpFile = "dont_timestep_sort.pcap"; // the file merged from file1 and file2 without sorting by timestamp
string sortedFile = "timestep_sort.pcap"; // the file already sorted by timestamp

int main() {

	pcap_t * pcap1 = pcap_open_offline(file1.c_str(), errbuff); // open the file1 and store data1
	pcap_t * pcap2 = pcap_open_offline(file2.c_str(), errbuff); // open the file2 and store data2

	struct pcap_pkthdr * header; // header object
	const u_char * data; // data object

	pcap_t * pd = pcap_open_dead(DLT_EN10MB, 262144); // dumper will use it as an argument
	pcap_dumper_t * dumper = pcap_dump_open(pd, /*"/home/xing/Desktop/tmp.pcap"*/
			tmpFile.c_str());

	pcap_loop(pcap2, 0, packet_handler, (unsigned char *) dumper);
	pcap_loop(pcap1, 0, packet_handler, (unsigned char *) dumper); // merged the two pcap files

	/* close */
	pcap_close(pcap1);
	pcap_close(pcap2);
	pcap_close(pd);
	pcap_dump_close(dumper);

//	string tmpFile = "/home/xing/Desktop/tmp.pcap";
	pcap_t * resultPcap = pcap_open_offline(tmpFile.c_str(), errbuff);
	sortPcap(resultPcap); // sort the merged pcap file

	return 0;

}

/**
 * Method Name: sortPcap()
 * Arguments  : pcap_t *
 * Return Type: void
 * Description: sort a .pcap file by time stamp then write all the packets to a new .pcap file
 */
void sortPcap(pcap_t * spcap) {

	struct pcap_pkthdr * header; // header object
	const u_char * data; // data object which is a pointer

	const u_char * data_copy; // data_copy

	vector<pktStruct> pktVector; // this vector contains each pktStruct
	pktStruct myStruct; // every myStruct instance stores a packet

	while (int returnValue = pcap_next_ex(spcap, &header, &data) >= 0) {

		// store each packet
		myStruct.pkt_header = *header;
		data_copy = (u_char *) malloc(myStruct.pkt_header.caplen); // malloc space for data_copy
		memcpy((void *) data_copy, (const void *) data, // copy data to data_copy
				myStruct.pkt_header.caplen);
		myStruct.pkt_data = data_copy;
		myStruct.time = header->ts.tv_sec * 1000000 + header->ts.tv_usec; // time is used to compare with each other
		/* print for test */
//		for (u_int i = 0; i < header->caplen; i++) {
		//	Start printing on the next after every 16 octets
//			if ((i % 16) == 0)
//				cout << endl;
//			//	Print each octet as hex (x), make sure there is always two characters (.2).
//			printf("%.2x ", myStruct.pkt_data[i]);
//			myStruct.pkt_data[i]=data[i];
//		}
//		/* another way to value the struct */
//		myStruct = {
//			header,
//			data,
//			time
//
//		};
		pktVector.push_back(myStruct);

		/* print for test */
//        cout<< "packetNo."<<":"<<structCount<<endl;
//		for (u_int i = 0; (i < header->caplen); i++) {
////				 Start printing on the next after every 16 octets
//			if ((i % 16) == 0)
//				cout << endl;
////				 Print each octet as hex (x), make sure there is always two characters (.2).
//			printf("%.2x ", myStruct.pkt_data[i]);
//
//		}
//		cout << myStruct.time << endl; // print for test
//		cout << myStruct.pkt_header->caplen << endl; //print for test
//		cout << myStruct.pkt_header->len << endl; // print for test
	}
	pcap_close(spcap);
	cout << "done store" << endl;
	/* reorder the vector by time */
	sort(pktVector.begin(), pktVector.end(), comparison);
	cout << "done sort" << endl;

	/* dump the ordered packets to the new file */
	pcap_t * finalPcap = pcap_open_dead(DLT_EN10MB, 262144); // dumper will use it
	pcap_dumper_t * tmpDump = pcap_dump_open(finalPcap,
	/*"/home/xing/Desktop/result.pcap"*/sortedFile.c_str()); // will be used to dump packets to the new file

	for (vector<pktStruct>::size_type ix = 0; ix < pktVector.size(); ix++) {
		pcap_dump((unsigned char *) tmpDump, &pktVector.at(ix).pkt_header,
				pktVector.at(ix).pkt_data);
		cout << ix << ":" << pktVector.at(ix).time << endl; // print for test

//		for (u_int i = 0; (i < header->caplen); i++) {
//			//				 Start printing on the next after every 16 octets
//			if ((i % 16) == 0)
//				cout << endl;
//			//				 Print each octet as hex (x), make sure there is always two characters (.2).
//			printf("%.2x ", pktVector.at(ix).pkt_data[i]);

		cout << pktVector.at(ix).pkt_header.caplen << endl; //print for test
		cout << pktVector.at(ix).pkt_header.len << endl; // print for test

	}

	pcap_dump_close(tmpDump);
	cout << "done dump" << endl; //print for test
	pcap_close(finalPcap);
	return;
}
/**
 * Method Name: comparison()
 * Arguments  : pktStruct, pktStruct
 * Return Type: bool
 * Description: callback method for sort() method
 */
bool comparison(pktStruct a, pktStruct b) {
	return a.time < b.time;
}

/**
 * Method Name: packet_handler()
 * Arguments  : u_char *, const struct pcap_pkthdr *, const u_char *
 * Return Type: void
 * Description: callback method for pcap_loop() method
 */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header,
		const u_char *pkt_data) {

	pcap_dump(dumpfile, header, pkt_data); // store a packet to the dump file
	return;
}
