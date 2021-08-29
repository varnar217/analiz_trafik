from nfstream import NFStreamer
import numpy as np
my_streamer = NFStreamer(source="dont_timp.pcap").to_pandas()[["src_ip",
                                                            "src_port",
                                                            "dst_ip",
                                                            "dst_port",
                                                            "protocol",
                                                            "bidirectional_packets",
                                                            "bidirectional_bytes",
                                                            "application_name"]] # or network interface)


my_streamer.to_csv('dont_timp.csv')


my_streamer = NFStreamer(source="timp.pcap").to_pandas()[["src_ip",
                                                            "src_port",
                                                            "dst_ip",
                                                            "dst_port",
                                                            "protocol",
                                                            "bidirectional_packets",
                                                            "bidirectional_bytes",
                                                            "application_name"]] # or network interface)


my_streamer.to_csv('timp.csv')
