make
sudo nice ./bin/portScanner --ip 8.8.8.8 --prefix 127.90.101.1/30 --speedup 2 --scan FIN ACK --file ipAddresses.txt --verbose --ports 6000,6111-6115 
#sudo valgrind --leak-check=full  --show-leak-kinds=all nice ./bin/portScanner --ip 8.8.8.8 --prefix 127.90.101.1/30 --speedup 2 --scan FIN ACK --file ipAddresses.txt --verbose --ports 6000,6111-6115 

