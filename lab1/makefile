ODIR=object
SDIR=source
IDIR=include
BDIR=bin

all: $(ODIR)/HelperClass.o $(ODIR)/Server.o $(ODIR)/Client.o $(ODIR)/FileObject.o $(ODIR)/netcat_part.o
	g++ $(ODIR)/*.o	-o $(BDIR)/executable.out -lcrypto

$(ODIR)/HelperClass.o: $(IDIR)/HelperClass.h $(SDIR)/HelperClass.cpp
	g++ -c -o $(ODIR)/HelperClass.o $(SDIR)/HelperClass.cpp

$(ODIR)/FileObject.o: $(IDIR)/FileObject.h $(IDIR)/HelperClass.h $(SDIR)/FileObject.cpp
	g++ -c -o $(ODIR)/FileObject.o $(SDIR)/FileObject.cpp	
	
$(ODIR)/Client.o: $(IDIR)/Client.h $(IDIR)/HelperClass.h $(IDIR)/FileObject.h $(SDIR)/Client.cpp
	g++ -c -o $(ODIR)/Client.o $(SDIR)/Client.cpp
	
$(ODIR)/Server.o: $(IDIR)/Server.h $(IDIR)/HelperClass.h $(IDIR)/FileObject.h $(SDIR)/Server.cpp
	g++ -c -o $(ODIR)/Server.o $(SDIR)/Server.cpp
				
$(ODIR)/netcat_part.o: $(IDIR)/HelperClass.h $(IDIR)/Client.h $(IDIR)/Server.h $(IDIR)/FileObject.h $(SDIR)/netcat_part.cpp
	g++ -c -o $(ODIR)/netcat_part.o $(SDIR)/netcat_part.cpp				
				
clear: 
	rm $(ODIR)/*.o -f
	rm $(BDIR)/* -f
