ODIR=object
SDIR=source
IDIR=include
BDIR=bin

all: $(ODIR)/HelperClass.o $(ODIR)/portScanner.o
	g++ -g -Wall  $(ODIR)/*.o -o $(BDIR)/portScanner
	
$(ODIR)/HelperClass.o: $(IDIR)/HelperClass.h $(SDIR)/HelperClass.cpp
	g++ -g -Wall -c -o $(ODIR)/HelperClass.o $(SDIR)/HelperClass.cpp -lcrypto	  
	
$(ODIR)/portScanner.o:  $(IDIR)/HelperClass.h $(SDIR)/portScanner.cpp
	g++ -g -Wall -c -o $(ODIR)/portScanner.o $(SDIR)/portScanner.cpp

clear:
	rm $(ODIR)/*.o -f
	rm $(BDIR)/* -f
