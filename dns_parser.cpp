#include <pcap.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <algorithm>
using namespace std;

/* DNS name length cannot exceed 255 bytes */
#define DNS_NAME_LENGTH 256
#define A_QUERY 1
#define NS_QUERY 2
#define CNAME_QUERY 5
#define SOA_QUERY 6
#define WKS_QUERY 11
#define PTR_QUERY 12
#define MX_QUERY 15
#define TXT_QUERY 16
#define AAAA_QUERY 28
#define SRV_QUERY 33
#define OPT_QUERY 41
#define ANY_QUERY 255


/*DNS Structure - https://en.wikipedia.org/wiki/Domain_Name_System#Authoritative_name_server*/
/*DNS header*/
struct dns_header {
	u_int16_t id;	/* identification number */			
	u_int16_t flags;	/* flags */
	u_int16_t qdcount;	/* number of question entries */
	u_int16_t ancount;	/* number of answer entries */
	u_int16_t atcount;	/* number of authority entries */
	u_int16_t rrcount;	/* number of resource entries */
};

/*DNS response record*/
struct dns_response {
	u_int16_t dns_name_offset;
	u_int16_t type;
	u_int16_t dns_class;
	u_int16_t ttl1;
	u_int16_t ttl2;
	u_int16_t len;
};


// the string in response contains some non ascii printable characters
// so we need to convert them to ascii '.'
void make_printable(string &str){
	transform(str.begin(), str.end(), str.begin(), [](char c){
        return isprint(c) ? c : '.';
    });	
}

// process questions in dns payload
void process_queries(const u_char *payload, int &offset, int num_queries){
    for(int i = 0; i < num_queries; i++){
        char *query_name = (char *)(payload + offset);
        string dns_query_name = query_name;
		make_printable(dns_query_name);

        // 1 is due to null byte at end of string
        offset += dns_query_name.size() + 1;

        u_short query_type = ntohs(*(u_short *)(payload + offset));
        offset += sizeof(u_short);

        u_short query_class = ntohs(*(u_short *)(payload + offset));
        offset += sizeof(u_short);

        // final touch: dns_query_name has first character as '.', couldn't understand why
        dns_query_name = dns_query_name.substr(1, dns_query_name.size()-1);

        // cool works well
        cout << "query:\t" << dns_query_name << " " << query_type << " "  << query_class << endl;
    }
}

// process answers in dns payload
void process_responses(const u_char *payload, int &offset, int num_answers){
	for(int i = 0; i < num_answers; i++){
		struct dns_response *response = (struct dns_response *)(payload + offset);
		offset += sizeof(struct dns_response);

		response -> dns_name_offset = ntohs(response -> dns_name_offset);
		response -> type = ntohs(response -> type);
		response -> dns_class = ntohs(response -> dns_class);
		response -> ttl1 = ntohs(response -> ttl1);
		response -> ttl2 = ntohs(response -> ttl2);
		response -> len = ntohs(response -> len);

		if(response -> type == A_QUERY){
			struct in_addr response_addr = *(struct in_addr *)(payload + offset);
			string response_address = inet_ntoa(response_addr);
			cout << "response_addr: " << response_address << endl;
		}
		else if(response -> type == AAAA_QUERY){
			struct in6_addr response_addr = *(struct in6_addr *)(payload + offset);
			char buf[INET6_ADDRSTRLEN];
			string response_address = inet_ntop(AF_INET6, (void *)&response_addr, buf, INET6_ADDRSTRLEN);
			cout << "response_addr: " << response_address << endl;
		}
		else if(response -> type == CNAME_QUERY){
			char *cname;
			// pointer to string in packet
			if(response -> len == 2){
				uint16_t response_offset = ntohs(*(uint16_t *)(payload + offset));
				// first 2 bits are 1 by convention
				response_offset &= 0x3fff;
				cname = (char *)(payload + response_offset);
			}
			else{
				cname = (char *)(payload + offset);
			}

			string response_cname = cname;
			make_printable(response_cname);
			response_cname = response_cname.substr(1, response_cname.size()-1);
			cout << "response_cname: " << response_cname << endl;
		}
		else{
			// TODO deal with rest of queries
		}

		offset += response -> len;
	}
}

void parse_dns_payload(const u_char *payload){
    struct dns_header *header = (struct dns_header *)payload;
    int num_queries = ntohs(header -> qdcount);
    int num_answers = ntohs(header -> ancount);
    int offset = sizeof(struct dns_header);
	cout << "num_answers: " << num_answers << endl;
    process_queries(payload, offset, num_queries);
    process_responses(payload, offset, num_answers);
}
