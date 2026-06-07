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
    if (!hostname || strlen(hostname) > 255) {
        return DNS_QUERY_ERROR;
    }
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

    uint16_t index = sizeof(dns_header), i = 0;
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
        free(tmp);
        return DNS_MEMORY_ERROR;
    } else {
        memcpy(*buf, tmp, size);
    }

    free(tmp);
    *query_size = size;
    return DNS_OK;
}

dns_status send_query(uint8_t *query, uint16_t query_size, uint8_t **response,
                      uint16_t *response_size) {
    if (!query || query_size < sizeof(dns_header) + 5 ||
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
    if (!response ||
        response_size <
            sizeof(dns_header) + 5) { // Minimum size: header + 1 byte for domain + QTYPE + QCLASS
        return DNS_INVALID_ANSWER;
    }

    dns_header *header = (dns_header *)response;
    if (ntohs(header->ancount) == 0) {
        return DNS_NO_ANSWERS; // No answers in the response
    }

    uint16_t index = sizeof(dns_header);
    while (*(response + index)) {
        index += *(response + index) + 1; // Move to the next label
    }
    index += 1 + sizeof(dns_footer); // Skip the null byte and footer

    *answers = malloc(ntohs(header->ancount) * sizeof(dns_answer));
    if (!*answers) {
        return DNS_MEMORY_ERROR;
    }
    *answer_count = ntohs(header->ancount);

    for (uint16_t i = 0; i < *answer_count; i++) {
        if ((*(response + index) & 0xC0) == 0xC0) {
            index += 2; // Skip the compressed name pointer
        } else {
            free(*answers);
            *answers = NULL;
            return DNS_INVALID_ANSWER; // Unsupported name format in answer
        }

        (*answers)[i].type = ntohs(*(uint16_t *)(response + index));
        index += 2; // Move past type
        (*answers)[i].addr_class = ntohs(*(uint16_t *)(response + index));
        index += 2; // Move past class
        (*answers)[i].ttl = ntohl(*(uint32_t *)(response + index));
        index += 4; // Move past TTL
        (*answers)[i].datalength = ntohs(*(uint16_t *)(response + index));
        index += 2;                    // Move past data length
        if ((*answers)[i].type == 1) { // Type A (IPv4)
            inet_ntop(AF_INET, response + index, (*answers)[i].address, ADDRESS_SIZE);
        }
        index += (*answers)[i].datalength; // Move past the address and any padding
    }

    return DNS_OK;
}
