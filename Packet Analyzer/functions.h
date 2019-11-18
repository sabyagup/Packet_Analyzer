/***************************Functions Header*******************************
***************************************************************************
******************* Author : Sabyasachi Gupta *****************************
******************* UIN    : 326005513        *****************************
******************* email  : sabyasachi.gupta@tamu.edu   ******************
***************************************************************************
***************************************************************************/

#ifndef FUNCTIONS_H
#define FUNCTIONS_H

void
process_sessions();

void
create_tuple(std::string tuple_key, const u_char *packet);

void
packet_capture(u_char *args, struct pcap_pkthdr *header, const u_char *packet);

void
print_app_banner(void);

void
print_app_usage(void);

void
print_my_payload(const unsigned char*);

#endif
