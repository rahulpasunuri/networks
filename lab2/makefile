ODIR=object
SDIR=source
IDIR=include
BDIR=bin

all: $(ODIR)/HelperClass.o $(ODIR)/FileObject.o $(ODIR)/Peer.o $(ODIR)/bt_setup.o $(ODIR)/Bencode.o
	g++ -Wall $(ODIR)/*.o -pthread -std=c++0x -o $(BDIR)/executable.out -lcrypto

$(ODIR)/HelperClass.o: $(IDIR)/HelperClass.h $(SDIR)/HelperClass.cpp
	g++ -Wall -c -o $(ODIR)/HelperClass.o $(SDIR)/HelperClass.cpp -lcrypto

$(ODIR)/FileObject.o: $(IDIR)/FileObject.h $(IDIR)/HelperClass.h $(SDIR)/FileObject.cpp
	g++ -Wall -c -o $(ODIR)/FileObject.o $(SDIR)/FileObject.cpp			
				
$(ODIR)/Peer.o: $(IDIR)/HelperClass.h $(IDIR)/bt_lib.h $(IDIR)/FileObject.h $(IDIR)/Peer.h $(SDIR)/Peer.cpp
	g++ -Wall -c -pthread -std=c++0x -o $(ODIR)/Peer.o $(SDIR)/Peer.cpp				

$(ODIR)/Bencode.o: $(IDIR)/Bencode.h $(SDIR)/Bencode.cpp
	g++ -Wall -c -o $(ODIR)/Bencode.o $(SDIR)/Bencode.cpp	-lcrypto			
												
$(ODIR)/bt_setup.o: $(IDIR)/HelperClass.h $(IDIR)/bt_lib.h $(IDIR)/FileObject.h $(IDIR)/Peer.h $(IDIR)/bt_setup.h $(IDIR)/Bencode.h $(SDIR)/bt_setup.cpp
	g++ -Wall -c -pthread -std=c++0x -o $(ODIR)/bt_setup.o $(SDIR)/bt_setup.cpp	-lcrypto

clear: 
	rm $(ODIR)/*.o -f
	rm $(BDIR)/* -f
