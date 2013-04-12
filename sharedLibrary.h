#ifndef SHARED_LIBRARY_H
#define SHARED_LIBRARY_H

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SIZE_ETHERNET 14
#define TRUE 1
#define CONNECTION_PORT 12000
#define PASSPHRASE "comp"

void systemFatal(const char *message);
void reportStatus(const char *message);
unsigned short csum(unsigned short*, int);
char *encrypt_data(char *input, char *key);
int bind_address(int port, int *socket);

struct AddrInfo
{
    char *DstHost;
    char *SrcHost;
    int dport;
    int sport;
};

#endif