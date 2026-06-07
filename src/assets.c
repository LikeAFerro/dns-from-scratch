// TODO:
// IPv6 support is not implemented, and the code assumes that all answers will be of type A (IPv4).
// The code does not handle different types of answers (e.g., CNAME, MX, etc.).
// Testing unit should be updated.
// Doxygen comments should be added to all functions and data structures for better documentation.

#include "assets.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

dns_status build_query(const char *hostname, uint8_t **buf, uint16_t *query_size) {
    if (!hostname || !buf || !query_size || strlen(hostname) > MAX_HOSTNAME_LENGTH) {
        return DNS_QUERY_ERROR;
    }
    // Temporary buffer to build the query before allocating the final buffer of the exact size
    uint8_t *tmp = malloc(MAX_QUERY_SIZE);
    if (!tmp) {
        return DNS_MEMORY_ERROR;
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

    // Start parsing the hostname into the query buffer after the header
    uint16_t index = sizeof(dns_header), i = 0;
    while (*hostname) {
        // Prevent invalid characters and labels longer than 63 bytes
        if (*hostname == ' ' || *hostname == '\t' || *hostname == '\n' || *hostname == '\r' ||
            i >= 63) {
            free(tmp);
            return DNS_QUERY_ERROR;
        }

        // Handle label boundaries (dots)
        if (*hostname == '.') {
            if (i == 0) { // Prevent empty labels
                free(tmp);
                return DNS_QUERY_ERROR;
            }
            tmp[index] = i;
            index += i + 1;
            i = 0;
        }

        else {
            if (index + i + 1 >= MAX_QUERY_SIZE) { // Prevent buffer overflow
                free(tmp);
                return DNS_QUERY_ERROR;
            }
            tmp[index + i + 1] = *hostname;
            i++;
        }
        hostname++;
    }

    // Prevent buffer overflow for the null terminator and footer
    if (index + i + 1 + sizeof(dns_footer) >= MAX_QUERY_SIZE) {
        free(tmp);
        return DNS_QUERY_ERROR;
    }

    tmp[index] = i;   // Length of the last label
    index += i + 1;   // Total size of the domain name
    tmp[index++] = 0; // Null-terminate the domain name

    dns_footer footer = {
        htons(0x0001), // QTYPE: A
        htons(0x0001)  // QCLASS: IN
    };
    memcpy(tmp + index, &footer, sizeof(footer));
    *query_size = index + sizeof(footer);

    // Allocate the final buffer to the necessary size and copy the query data
    *buf = malloc(*query_size);
    if (!*buf) {
        free(tmp);
        return DNS_MEMORY_ERROR;
    } else {
        memcpy(*buf, tmp, *query_size);
    }

    free(tmp);
    return DNS_OK;
}

dns_status send_query(uint8_t *query, uint16_t query_size, uint8_t **response,
                      uint16_t *response_size) {
    if (!query || !response || !response_size || query_size < sizeof(dns_header) + 5 ||
        query_size > MAX_QUERY_SIZE) { // Minimum size: header + 1 byte for domain + QTYPE + QCLASS
        return DNS_INVALID_QUERY;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return DNS_SOCKET_ERROR;
    }

    struct sockaddr_in dest = {.sin_family = AF_INET, .sin_port = htons(53)};
    if (inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr) != 1) {
        close(fd);
        return DNS_INVALID_ADDRESS;
    }

    struct timeval tv = {.tv_sec = 5, .tv_usec = 0}; // 5-second timeout
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        close(fd);
        return DNS_SOCKET_ERROR;
    }

    if (sendto(fd, query, query_size, 0, (struct sockaddr *)&dest, sizeof(dest)) == -1) {
        close(fd);
        return DNS_SOCKET_ERROR;
    }

    // Temporary buffer to receive the response before allocating the final buffer of the exact size
    uint8_t *tmp = malloc(MAX_RESPONSE_SIZE);
    if (!tmp) {
        close(fd);
        return DNS_MEMORY_ERROR;
    }
    int size = recvfrom(fd, tmp, MAX_RESPONSE_SIZE, 0, NULL, NULL);
    if (size == -1) {
        free(tmp);
        close(fd);
        return DNS_TIMEOUT_ERROR;
    }
    *response_size = size;

    // Allocate the final buffer to the necessary size and copy the response data
    *response = malloc(*response_size);
    if (!*response) {
        free(tmp);
        close(fd);
        return DNS_MEMORY_ERROR;
    }
    memcpy(*response, tmp, *response_size);

    free(tmp);
    close(fd);
    return DNS_OK;
}

dns_status parse_response(uint8_t *response, uint16_t response_size, int *answer_count,
                          dns_answer **answers) {
    // Minimum size: header + 1 byte for domain + QTYPE + QCLASS
    if (!response || !answer_count || !answers || response_size < sizeof(dns_header) + 5) {
        return DNS_INVALID_ANSWER;
    }

    // Response starts with the query data, so we need to skip the header
    dns_header header;
    memcpy(&header, response, sizeof(header));
    *answer_count = ntohs(header.ancount);
    if (*answer_count == 0) {
        return DNS_NO_ANSWERS; // No answers in the response
    }

    // Skip the question section by moving the number of bytes specified by the labels in the query
    uint16_t index = sizeof(dns_header);
    while (*(response + index)) {
        index += *(response + index) + 1;
    }
    // Skip the null byte and footer
    index += 1 + sizeof(dns_footer);

    // Allocate memory for the answers based on the number of answers specified in the header
    *answers = malloc(*answer_count * sizeof(dns_answer));
    if (!*answers) {
        return DNS_MEMORY_ERROR;
    }

    // For each answer, parse the field and assign the values to the corresponding fields in the
    // dns_answer structure
    for (uint16_t i = 0; i < *answer_count; i++) {
        // Name pointer check and buffer overflow prevention.
        if ((*(response + index) & 0xC0) != 0xC0 || index + 10 > response_size) {
            free(*answers);
            *answers = NULL;
            return DNS_INVALID_ANSWER;
        } else {
            index += 2; // Skip the compressed name pointer
        }

        memcpy(&(*answers)[i].type, response + index, 2);
        (*answers)[i].type = ntohs((*answers)[i].type);
        index += 2; // Move past type
        memcpy(&(*answers)[i].addr_class, response + index, 2);
        (*answers)[i].addr_class = ntohs((*answers)[i].addr_class);
        index += 2; // Move past class
        memcpy(&(*answers)[i].ttl, response + index, 4);
        (*answers)[i].ttl = ntohl((*answers)[i].ttl);
        index += 4; // Move past TTL
        memcpy(&(*answers)[i].datalength, response + index, 2);
        (*answers)[i].datalength = ntohs((*answers)[i].datalength);
        index += 2;                    // Move past data length
        if ((*answers)[i].type == 1) { // Type A (IPv4)
            inet_ntop(AF_INET, response + index, (*answers)[i].address, ADDRESS_SIZE);
        }
        index += (*answers)[i].datalength; // Move past the address
    }

    return DNS_OK;
}
