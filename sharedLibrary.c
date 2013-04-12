#include "sharedLibrary.h"

/*
 -- FUNCTION: systemFatal
 --
 -- DATE: March 12, 2011
 --
 -- REVISIONS: (Date and Description)
 --
 -- DESIGNER: Aman Abdulla
 --
 -- PROGRAMMER: Luke Queenan
 --
 -- INTERFACE: static void systemFatal(const char* message);
 --
 -- RETURNS: void
 --
 -- NOTES:
 -- This function displays an error message and shuts down the program.
 */
void systemFatal(const char *message)
{
    perror(message);
    exit(EXIT_FAILURE);
}

char *encrypt_data(char *input, char *key)
{
    int i, x, y;
    
    x = strlen(input);
    y = strlen(key);
    
    for (i = 0; i < x; ++i)
    {
        input[i] ^= key[(i%y)];
    }
    return input;
}

int bind_address(int port, int *socket)
{
    struct sockaddr_in address;
    bzero((char *)&address, sizeof(struct sockaddr_in));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    
    return bind(*socket, (struct sockaddr *)&address, sizeof(address));
}
