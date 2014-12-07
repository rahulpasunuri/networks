make
#sudo nice ./bin/portScanner --ip 8.8.8.8 --prefix 127.90.101.1/30 --speedup 2 --scan FIN ACK --file ipAddresses.txt --verbose --ports 6000,6111-6115 
#sudo valgrind --leak-check=full  --show-leak-kinds=all nice ./bin/portScanner --ip 8.8.8.8 --prefix 127.90.101.1/30 --speedup 2 --scan FIN ACK --file ipAddresses.txt --verbose --ports 6000,6111-6115 
#sudo nice valgrind --leak-check=full  --show-leak-kinds=all ./bin/portScanner --ip 129.79.247.87 --speedup 5 --scan SYN --ports 22
sudo nice ./bin/portScanner --ip 129.79.247.87 --speedup 5 --scan SYN --ports 143
#sudo nice ./bin/portScanner --ip 129.79.247.87 --speedup 5 --scan NULL --ports 22
