#include<bits/stdc++.h>

using namespace std;

/*DNS response record*/
struct dns_response {
	u_int16_t dns_id;
	u_int16_t type;
	u_int32_t dns_class;
	// u_int16_t ttl1;
	// u_int16_t ttl2;
	u_int16_t len;
};

/*DNS response record*/
struct  __attribute__((packed)) dns_response1{
	u_int16_t dns_id;
	u_int16_t type;
	u_int16_t dns_class;
    u_int32_t ttl;
	u_int16_t len;
};



int main(){
    cout << sizeof(dns_response) << " " << sizeof(dns_response1) << endl;
}