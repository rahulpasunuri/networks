ODIR=object
SDIR=source
IDIR=include
BDIR=bin



all: $(ODIR)/Wiretap.o
	g++ -g $(ODIR)/*.o -std=c++0x -o $(BDIR)/Wiretap -lpcap 
	
$(ODIR)/Wiretap.o: $(IDIR)/Wiretap.h $(SDIR)/Wiretap.cpp
	g++ -g -c -std=c++0x -o $(ODIR)/Wiretap.o $(SDIR)/Wiretap.cpp -lpcap
	
clear:
	rm -f $(ODIR)/*.o
	rm -f $(BDIR)/Wiretap
