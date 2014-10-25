make
#valgrind --leak-check=full  --show-leak-kinds=all ./wiretap --open wget.pcap
./wiretap --open wget.pcap
