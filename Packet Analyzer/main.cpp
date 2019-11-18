/************************Main Program**************************************
***************************************************************************
******************* Author : Sabyasachi Gupta *****************************
******************* UIN    : 326005513        *****************************
******************* email  : sabyasachi.gupta@tamu.edu   ******************
***************************************************************************
***************************************************************************/

#include "libdef.h"
#include "functions.h"

/* Main Program */

int main(int argc, char **argv) {

	const unsigned char *packet;
	struct pcap_pkthdr header;

        char errbuf[PCAP_ERRBUF_SIZE];          /* error buffer */
        pcap_t *handle;                         /* packet capture handle */

        char filter_exp[] = "ip";               /* filter expression [3] */
        struct bpf_program fp;                  /* compiled filter program (expression) */

        print_app_banner();

	if ((argc > 2)||(argc == 1)){
                fprintf(stderr, "error: unrecognized command-line options\n\n");
                print_app_usage();
                exit(EXIT_FAILURE);
        }
	
	handle = pcap_open_offline(argv[1], errbuf);   //call pcap library function	

	if (handle == NULL) {
		fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
		return(2);
	}
	else {
		fprintf(stdout,"File %s opened successfully\n", argv[1]);
	}

	fprintf(stdout,"\n");

	while ((packet = pcap_next(handle, &header)) != NULL)
		packet_capture(NULL, &header, packet);

	process_sessions();
return 0;
}
