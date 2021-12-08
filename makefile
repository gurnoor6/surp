all: dns.o dns_parser.o
	g++ -o dns dns.o dns_parser.o -lpcap

dns.o: dns.cpp
	g++ -std=c++17 -c dns.cpp

dns_parser.o: dns_parser.cpp
	g++ -std=c++17 -c dns_parser.cpp

clean:
	rm -f dns dns.o dns_parser.o