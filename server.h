#ifndef SERVER_H
#define SERVER_H

#define _BSD_SOURCE

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pcap.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>

#include "sharedLibrary.h"

#define SNAP_LEN 1518

// Packet length
#define PCKT_LEN 8192

#define FILTER_BUFFER 1024
#define DEFAULT_DST_PORT	9000
#define DEFAULT_SRC_PORT	1234
#define DEFAULT_SRC_IP		"192.168.0.196"
#define OPTIONS 		"?h:d:s:p:c:"

void sendKnock(struct AddrInfo *addr);
void sendCommand(char *command);

#endif