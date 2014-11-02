ODIR=object
SDIR=source
IDIR=include
BDIR=bin

all: $(ODIR)/HelperClass.o $(ODIR)/Core.o $(ODIR)/portScanner.o 
	g++ -g -Wall  $(ODIR)/*.o -o $(BDIR)/portScanner -lpcap
	
$(ODIR)/HelperClass.o: $(IDIR)/HelperClass.h $(SDIR)/HelperClass.cpp
	g++ -g -Wall -c -o $(ODIR)/HelperClass.o $(SDIR)/HelperClass.cpp  -lpcap

$(ODIR)/Core.o: $(IDIR)/HelperClass.h $(IDIR)/Core.h $(SDIR)/Core.cpp -lpcap
	g++ -g -Wall -c -o $(ODIR)/Core.o $(SDIR)/Core.cpp
	
$(ODIR)/portScanner.o:  $(IDIR)/HelperClass.h $(SDIR)/portScanner.cpp
	g++ -g -Wall -c -o $(ODIR)/portScanner.o $(SDIR)/portScanner.cpp -lpcap

clear:
	rm $(ODIR)/*.o -f
	rm $(BDIR)/* -f
