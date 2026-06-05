// TODO: Better error handling, especially for memory allocation failures and socket errors

#include "assets.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

uint16_t build_query(const char *hostname, uint8_t **buf) {
    uint8_t *tmp = malloc(MAX_QUERY_SIZE);
    if (!tmp) {
        return 0;
    }

    dns_header header = {
        htons((rand() % 65536)), // ID
        htons(0x0100),           // Flags: standard query
        htons(1),                // QDCOUNT: 1 question
        htons(0),                // ANCOUNT: 0 answers
        htons(0),                // NSCOUNT: 0 authority records
        htons(0)                 // ARCOUNT: 0 additional records
    };
    memcpy(tmp, &header, sizeof(header));

    uint16_t index = HEADER_SIZE, i = 0;
    while (*hostname) {
        if (*hostname == '.') {
            tmp[index] = i;
            index += i + 1;
            i = 0;
        }

        else {
            tmp[index + i + 1] = *hostname;
            i++;
        }
        hostname++;
    }
    tmp[index] = i; // Length of the last label
    index += i + 1; // Total size of the domain name
    tmp[index] = 0; // Null-terminate the domain name
    uint16_t size = index + 1;

    dns_footer footer = {
        htons(0x0001), // QTYPE: A
        htons(0x0001)  // QCLASS: IN
    };
    memcpy(tmp + size, &footer, sizeof(footer));
    size += sizeof(footer);

    *buf = malloc(size);
    if (!*buf) {
        size = 0;
    } else {
        memcpy(*buf, tmp, size);
    }

    free(tmp);
    return size;
}

uint16_t send_query(uint8_t *query, uint16_t query_size, uint8_t **response) {
    if (!query || query_size < sizeof(dns_header) +
                                   5) { // Minimum size: header + 1 byte for domain + QTYPE + QCLASS
        return 0;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return 0;
    }

    struct sockaddr_in dest = {.sin_family = AF_INET, .sin_port = htons(53)};
    if (inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr) != 1) {
        close(fd);
        return 0;
    }

    struct timeval tv = {.tv_sec = 5, .tv_usec = 0}; // 5-second timeout
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        close(fd);
        return 0;
    }

    if (sendto(fd, query, query_size, 0, (struct sockaddr *)&dest, sizeof(dest)) == -1) {
        close(fd);
        return 0;
    }

    uint8_t *tmp = malloc(MAX_RESPONSE_SIZE);
    if (!tmp) {
        close(fd);
        return 0;
    }
    int response_size = recvfrom(fd, tmp, MAX_RESPONSE_SIZE, 0, NULL, NULL);
    if (response_size == -1) {
        free(tmp);
        close(fd);
        return 0;
    }

    *response = malloc(response_size);
    if (!*response) {
        free(tmp);
        close(fd);
        return 0;
    }
    memcpy(*response, tmp, response_size);

    free(tmp);
    close(fd);
    return response_size;
}

char *parse_response(uint8_t *response, uint16_t response_size) {
    if (!response ||
        response_size <
            sizeof(dns_header) + 5) { // Minimum size: header + 1 byte for domain + QTYPE + QCLASS
        return NULL;
    }
    dns_header header_big;
    memcpy(&header_big, response, sizeof(header_big));
    dns_header header = {ntohs(header_big.id),
                         ntohs(header_big.flags),
                         ntohs(header_big.qdcount),
                         ntohs(header_big.ancount),
                         ntohs(header_big.nscount),
                         ntohs(header_big.arcount)};
    if (header.ancount == 0) {
        return NULL; // No answers
    }

    int i = HEADER_SIZE; // Skip header
    if (!response[i]) {
        return NULL; // Empty domain name
    }
    int len = response[i++]; // Length of the first label
    char *tmp = malloc(MAX_QUERY_SIZE);
    if (!tmp) {
        return NULL;
    }

    while (response[i]) {
        if (len == 0) {
            len = response[i];
            tmp[i - HEADER_SIZE - 1] = '.';
        } else {
            tmp[i - HEADER_SIZE - 1] = response[i];
            len--;
        }
        i++;
    }
    tmp[i - HEADER_SIZE - 1] = '\0'; // Null-terminate the domain name

    char *name = malloc(i - HEADER_SIZE - 1 + 1); // +1 for null terminator
    if (!name) {
        free(tmp);
        return NULL;
    }
    memcpy(name, tmp, i - HEADER_SIZE - 1 + 1);
    free(tmp);

    dns_footer footer;
    memcpy(&footer, response + i + 1, sizeof(footer));
    if (ntohs(footer.type) != 0x0001 || ntohs(footer.addr_class) != 0x0001) {
        free(name);
        return NULL; // Not an A record or not IN class
    }

    i += 1 + sizeof(footer); // Move the index along

    return name;
}
