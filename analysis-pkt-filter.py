from nfstream import NFStreamer
import numpy as np
my_streamer = NFStreamer(source="100_seconds.pcap").to_pandas()[["src_ip",
                                                            "src_port",
                                                            "dst_ip",
                                                            "dst_port",
                                                            "protocol",
                                                            "bidirectional_packets",
                                                            "bidirectional_bytes",
                                                            "application_name"]] # or network interface)


my_streamer.to_csv('100_sec.csv')


my_streamer = NFStreamer(source="DiscordVideoLTE.pcap").to_pandas()[["src_ip",
                                                            "src_port",
                                                            "dst_ip",
                                                            "dst_port",
                                                            "protocol",
                                                            "bidirectional_packets",
                                                            "bidirectional_bytes",
                                                            "application_name"]] # or network interface)


my_streamer.to_csv('DiscordVideoLTE.csv')

my_streamer = NFStreamer(source="out2.pcap").to_pandas()[["src_ip",
                                                            "src_port",
                                                            "dst_ip",
                                                            "dst_port",
                                                            "protocol",
                                                            "bidirectional_packets",
                                                            "bidirectional_bytes",
                                                            "application_name"]] # or network interface)


my_streamer.to_csv('out2.csv')
