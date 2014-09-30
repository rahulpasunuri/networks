ODIR=object
SDIR=source
IDIR=include
BDIR=bin

all: $(ODIR)/HelperClass.o  $(ODIR)/Client.o $(ODIR)/FileObject.o $(ODIR)/Peer.o $(ODIR)/bt_setup.o
	g++ -Wall $(ODIR)/*.o -pthread -std=c++0x 	-o $(BDIR)/executable.out -lcrypto

$(ODIR)/HelperClass.o: $(IDIR)/HelperClass.h $(SDIR)/HelperClass.cpp
	g++ -Wall -c -o $(ODIR)/HelperClass.o $(SDIR)/HelperClass.cpp

$(ODIR)/FileObject.o: $(IDIR)/FileObject.h $(IDIR)/HelperClass.h $(SDIR)/FileObject.cpp
	g++ -Wall -c -o $(ODIR)/FileObject.o $(SDIR)/FileObject.cpp	
	
$(ODIR)/Client.o: $(IDIR)/Client.h $(IDIR)/HelperClass.h $(IDIR)/FileObject.h $(SDIR)/Client.cpp $(IDIR)/bt_lib.h
	g++ -Wall -c -o $(ODIR)/Client.o $(SDIR)/Client.cpp
	
				
$(ODIR)/Peer.o: $(IDIR)/HelperClass.h $(IDIR)/Client.h $(IDIR)/bt_lib.h $(IDIR)/FileObject.h $(IDIR)/Peer.h $(SDIR)/Peer.cpp
	g++ -Wall -c -pthread -std=c++0x -o $(ODIR)/Peer.o $(SDIR)/Peer.cpp				
												
$(ODIR)/bt_setup.o: $(IDIR)/HelperClass.h $(IDIR)/Client.h $(IDIR)/bt_lib.h $(IDIR)/FileObject.h $(IDIR)/Peer.h $(SDIR)/Peer.cpp $(IDIR)/bt_setup.h
	g++ -Wall -c -pthread -std=c++0x -lssl -o $(ODIR)/bt_setup.o $(SDIR)/bt_setup.cpp				

clear: 
	rm $(ODIR)/*.o -f
	rm $(BDIR)/* -f
