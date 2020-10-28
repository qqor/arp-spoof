LDLIBS=-lpcap -lpthread

all: arp-spoof

arp-spoof: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

main.o: main.cpp
	g++ -Wall -c -o main.o main.cpp

clean:
	rm -f arp-spoof *.o