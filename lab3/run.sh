make
#valgrind --leak-check=full  --show-leak-kinds=all ./bin/Wiretap --open wget.pcap
./bin/Wiretap --open ./sampletestfiles/wget.pcap
