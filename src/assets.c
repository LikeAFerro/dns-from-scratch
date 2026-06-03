#include "assets.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

uint16_t build_query(const char *hostname, uint8_t **buf) {
    uint8_t *tmp = malloc(MAX_SIZE);
    if (!tmp) {
        return 0;
    }

    dns_header header = {
        htons((rand() % 65535)), // ID
        htons(0x0100),           // Flags: standard query
        htons(1),                // QDCOUNT: 1 question
        htons(0),                // ANCOUNT: 0 answers
        htons(0),                // NSCOUNT: 0 authority records
        htons(0)                 // ARCOUNT: 0 additional records
    };
    memcpy(tmp, &header, sizeof(header));

    uint16_t starting_index = 12, i = 0;
    while (*hostname) {
        if (*hostname == '.') {
            tmp[starting_index] = i;
            starting_index += i + 1;
            i = 0;
        }

        else {
            tmp[starting_index + i + 1] = *hostname;
            i++;
        }
        hostname++;
    }
    tmp[starting_index] = i; // Length of the last label
    starting_index += i + 1; // Total size of the domain name
    tmp[starting_index] = 0; // Null-terminate the domain name
    uint16_t size = starting_index + 1;

    uint16_t qfields[] = {
        htons(0x0001), // QTYPE: A
        htons(0x0001)  // QCLASS: IN
    };
    memcpy(tmp + size, qfields, sizeof(qfields));
    size += sizeof(qfields);

    *buf = malloc(size);
    if (!*buf) {
        size = 0;
    } else {
        memcpy(*buf, tmp, size);
    }
    free(tmp);

    return size;
}
