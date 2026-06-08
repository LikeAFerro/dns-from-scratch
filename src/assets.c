// TODO:
// IPv6 support is not implemented, and the code assumes that all answers will be of type A (IPv4).
// Make it so that the resolver is not hardcoded to use Google's public DNS server
// The code does not handle different types of answers (e.g., CNAME, MX, etc.).
// Testing unit should be updated.

#include "assets.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

dns_query query_default() {
    dns_query query = {
        .id = htons(rand() % 65536),
        .flags = htons(DNS_STANDARD_QUERY_FLAGS),
        .qdcount = htons(1),
        .ancount = htons(0),
        .nscount = htons(0),
        .arcount = htons(0),
        .query_name = NULL,
        .qtype = htons(DNS_QTYPE_A),
        .qclass = htons(1),
    };
    return query;
}

dns_config config_default() {
    dns_config config = {.dns_server = "8.8.8.8", .port = htons(53), .timeout = 5, .query_size = 0};
    return config;
}

dns_status build_query(const char *hostname, dns_query *query, dns_config *config) {
    if (!hostname || !query || !config || strlen(hostname) > MAX_HOSTNAME_LENGTH) {
        return DNS_QUERY_ERROR;
    }

    // Temporary buffer to build the query name before assigning it to the query structure
    uint8_t *buffer = malloc(MAX_QUERY_SIZE);

    // Iterate through the hostname and build the query buffer according to the DNS protocol format
    int label = 0, index = 1;
    while (*hostname) {
        // Prevent invalid characters and labels longer than 63 bytes
        if (*hostname == ' ' || *hostname == '\t' || *hostname == '\n' || *hostname == '\r' ||
            index >= 63) {
            free(buffer);
            return DNS_QUERY_ERROR;
        }

        // Handle label boundaries (dots)
        if (*hostname == '.') {
            if (label == 0) { // Prevent empty labels
                free(buffer);
                return DNS_QUERY_ERROR;
            }
            buffer[label] = index;
            label += index + 1;
            index = 0;
        }

        else {
            if (label + index + 1 >= MAX_QUERY_SIZE) { // Prevent buffer overflow
                free(buffer);
                return DNS_QUERY_ERROR;
            }
            buffer[label + index + 1] = *hostname;
            index++;
        }
        hostname++;
    }

    buffer[label] = index;                          // Length of the last label
    label += index + 1;                             // Total size of the domain name
    buffer[label] = 0;                              // Null-terminate the domain name
    config->query_size = label + FIXED_FIELDS_SIZE; // Total size of the query

    // Allocate memory for the query name in the query structure and copy the buffer
    query->query_name = malloc(label);
    if (!query->query_name) {
        free(buffer);
        return DNS_MEMORY_ERROR;
    }
    memcpy(query->query_name, buffer, label);

    free(buffer);
    return DNS_OK;
}

dns_status send_query(const dns_query *query, const dns_config *config, uint8_t **response,
                      uint16_t *response_size) {
    if (!query || !config || !response || !response_size ||
        config->query_size < FIXED_FIELDS_SIZE + 1 || config->query_size > MAX_QUERY_SIZE) {
        return DNS_INVALID_QUERY;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return DNS_SOCKET_ERROR;
    }

    struct sockaddr_in dest = {.sin_family = AF_INET, .sin_port = config->port};
    if (inet_pton(AF_INET, config->dns_server, &dest.sin_addr) != 1) {
        close(fd);
        return DNS_INVALID_ADDRESS;
    }

    struct timeval tv = {.tv_sec = config->timeout, .tv_usec = 0}; // 5-second timeout
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        close(fd);
        return DNS_SOCKET_ERROR;
    }

    if (sendto(fd, query, config->query_size, 0, (struct sockaddr *)&dest, sizeof(dest)) == -1) {
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

dns_status parse_response(dns_query *query, uint8_t *response, uint16_t response_size,
                          dns_answer **answers) {
    if (!query || !response || !answers || response_size < strlen((char *)query->query_name)) {
        return DNS_INVALID_ANSWER;
    }

    // Response starts with the query data, which we can skip
    memcpy(&query->id, response, query->query_size);
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
        if ((*(response + index) & DNS_NAME_POINTER) != DNS_NAME_POINTER ||
            index + 10 > response_size) {
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
        index += 2;                              // Move past data length
        if ((*answers)[i].type == DNS_QTYPE_A) { // Type A (IPv4)
            inet_ntop(AF_INET, response + index, (*answers)[i].address, INET6_ADDRSTRLEN);
        }
        index += (*answers)[i].datalength; // Move past the address
    }

    return DNS_OK;
}
