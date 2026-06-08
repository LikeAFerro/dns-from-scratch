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
#include <time.h>
#include <unistd.h>

dns_status initial_config(int argc, char *argv[], dns_config *config, dns_query *query) {
    if (!config || !query || argc < 2) {
        return DNS_ARGUMENT_ERROR;
    }

    // Set default values for the configuration
    strncpy(config->dns_server, DNS_DEFAULT_SERVER, sizeof(config->dns_server));
    config->port = DNS_DEFAULT_PORT;
    config->timeout = DNS_DEFAULT_TIMEOUT;

    // Seed the random number generator and initialize the query structure with default values
    srand(time(NULL));          // Seed the random number generator for query ID generation
    query->id = rand() % 65536; // Random query ID
    query->flags = DNS_STANDARD_QUERY_FLAGS; // Standard query with recursion desired
    query->qdcount = 1;                      // One question
    query->qtype = DNS_QTYPE_A;              // Default to A record (IPv4)
    query->qclass = 1;                       // IN class

    // Parse command-line options and arguments
    int opt;
    while ((opt = getopt(argc, argv, "h6")) != -1) {
        switch (opt) {
        case 'h':
            return DNS_HELP;
        case '6':
            query->qtype = DNS_QTYPE_AAAA;
            break;
        default:
            return DNS_OPTION_ERROR;
        }
    }
    if (optind >= argc || argc > optind + 1) {
        return DNS_ARGUMENT_ERROR;
    }
    if (strlen(argv[optind]) > DNS_MAX_HOSTNAME_LENGTH) {
        return DNS_HOSTNAME_ERROR;
    }
    strncpy(query->query_name, argv[optind], DNS_MAX_HOSTNAME_LENGTH);

    return DNS_OK;
}

dns_status serialize_query(const dns_query *query, dns_buffer *serialized_query) {
    if (!query || !serialized_query || strlen(query->query_name) == 0 || query->qtype == 0 ||
        query->qclass == 0 || query->qdcount == 0) {
        return DNS_QUERY_ERROR;
    }

    serialized_query->size = 0;
    serialized_query->data = NULL;
    // Temporary buffer to build the query name before assigning it to the query structure
    uint8_t *buffer = malloc(DNS_MAX_QUERY_SIZE);
    if (!buffer) {
        return DNS_MEMORY_ERROR;
    }

    uint16_t header[] = {
        htons(query->id), htons(query->flags), htons(query->qdcount), htons(0), htons(0), htons(0)};
    memcpy(buffer, header, DNS_HEADER_SIZE); // Copy the fixed header fields
    serialized_query->size += DNS_HEADER_SIZE;

    // Iterate through the hostname and build the query buffer
    int index = 0, label = 0;
    const char *hostname = query->query_name;
    while (*hostname) {
        // Prevent invalid characters and labels longer than 63 bytes
        if (*hostname == ' ' || *hostname == '\t' || *hostname == '\n' || *hostname == '\r' ||
            index >= 63) {
            free(buffer);
            return DNS_HOSTNAME_ERROR;
        }

        // Handle label boundaries (dots)
        if (*hostname == '.') {
            if (index == 0) { // Prevent empty labels
                free(buffer);
                return DNS_HOSTNAME_ERROR;
            }
            buffer[serialized_query->size + label] = index;
            label += index + 1; // Move to the next label position
            index = 0;          // Reset index for the next label
        }

        else {
            index++;
            if (label + index >= DNS_MAX_QUERY_SIZE) { // Prevent buffer overflow
                free(buffer);
                return DNS_HOSTNAME_ERROR;
            }
            buffer[serialized_query->size + label + index] = *hostname;
        }
        hostname++;
    }

    buffer[serialized_query->size + label] = index; // Length of the last label
    label += index + 1;                             // Total size of the domain name
    buffer[serialized_query->size + label] = 0;     // Null-terminate the domain name
    serialized_query->size += label + 1;            // Total size of the query

    uint16_t qtype_qclass[] = {htons(query->qtype), htons(query->qclass)};
    memcpy(buffer + serialized_query->size, qtype_qclass, sizeof(qtype_qclass));
    serialized_query->size += sizeof(qtype_qclass);

    // Allocate memory for the query name in the query structure and copy the buffer
    serialized_query->data = malloc(serialized_query->size);
    if (!serialized_query->data) {
        free(buffer);
        return DNS_MEMORY_ERROR;
    }
    memcpy(serialized_query->data, buffer, serialized_query->size);

    free(buffer);
    return DNS_OK;
}

dns_status send_query(const dns_buffer *query, const dns_config *config, dns_buffer *response) {
    if (!query || !config || !response || query->size < DNS_FIXED_FIELDS_SIZE + 1 ||
        query->size > DNS_MAX_QUERY_SIZE) {
        return DNS_QUERY_ERROR;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return DNS_SOCKET_ERROR;
    }

    struct sockaddr_in dest = {.sin_family = AF_INET, .sin_port = htons(config->port)};
    if (inet_pton(AF_INET, config->dns_server, &dest.sin_addr) != 1) {
        close(fd);
        return DNS_ADDRESS_ERROR;
    }

    struct timeval tv = {.tv_sec = config->timeout, .tv_usec = 0}; // 5-second timeout
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        close(fd);
        return DNS_SOCKET_ERROR;
    }

    if (sendto(fd, query->data, query->size, 0, (struct sockaddr *)&dest, sizeof(dest)) == -1) {
        close(fd);
        return DNS_SOCKET_ERROR;
    }

    // Temporary buffer to receive the response before allocating the final buffer of the exact
    // size
    uint8_t *tmp = malloc(DNS_MAX_RESPONSE_SIZE);
    if (!tmp) {
        close(fd);
        return DNS_MEMORY_ERROR;
    }
    int size = recvfrom(fd, tmp, DNS_MAX_RESPONSE_SIZE, 0, NULL, NULL);
    if (size == -1) {
        free(tmp);
        close(fd);
        return DNS_ANSWER_ERROR;
    }
    response->size = size;

    // Allocate the final buffer to the necessary size and copy the response data
    response->data = malloc(response->size);
    if (!response->data) {
        free(tmp);
        close(fd);
        return DNS_MEMORY_ERROR;
    }
    memcpy(response->data, tmp, response->size);

    free(tmp);
    close(fd);
    return DNS_OK;
}

dns_status parse_response(const dns_buffer *response, dns_answer **answers,
                          uint16_t *answer_count) {
    if (!response || !answers || !answer_count || response->size < DNS_FIXED_FIELDS_SIZE) {
        return DNS_ANSWER_ERROR;
    }

    uint16_t header[DNS_HEADER_SIZE / 2]; // DNS header is 12 bytes, so we need 6 uint16_t fields
    memcpy(header, response->data, DNS_HEADER_SIZE);
    *answer_count = ntohs(header[3]); // The number of answers is in the 4th field of the header

    // Skip the question section by moving the number of bytes specified by the labels in the
    // query
    uint16_t index = DNS_HEADER_SIZE; // Start after the header
    while (*(response->data + index)) {
        index += *(response->data + index) + 1;
    }
    // Skip the null byte and footer
    index += 1 + sizeof(uint16_t) * 2; // Move past the null byte and QTYPE/QCLASS fields

    // Allocate memory for the answers based on the number of answers specified in the header
    *answers = malloc(*answer_count * sizeof(dns_answer));
    if (!*answers) {
        return DNS_MEMORY_ERROR;
    }

    // For each answer, parse the field and assign the values to the corresponding fields in the
    // dns_answer structure
    for (uint16_t i = 0; i < *answer_count; i++) {
        // Name pointer check and buffer overflow prevention.
        if ((*(response->data + index) & DNS_NAME_POINTER) != DNS_NAME_POINTER ||
            index + 10 > response->size) {
            free(*answers);
            *answers = NULL;
            return DNS_ANSWER_ERROR;
        } else {
            index += 2; // Skip the compressed name pointer
        }

        memcpy(&(*answers)[i].type, response->data + index, 2);
        (*answers)[i].type = ntohs((*answers)[i].type);
        index += 2; // Move past type
        memcpy(&(*answers)[i].addr_class, response->data + index, 2);
        (*answers)[i].addr_class = ntohs((*answers)[i].addr_class);
        index += 2; // Move past class
        memcpy(&(*answers)[i].ttl, response->data + index, 4);
        (*answers)[i].ttl = ntohl((*answers)[i].ttl);
        index += 4; // Move past TTL
        memcpy(&(*answers)[i].datalength, response->data + index, 2);
        (*answers)[i].datalength = ntohs((*answers)[i].datalength);
        index += 2;                              // Move past data length
        if ((*answers)[i].type == DNS_QTYPE_A) { // Type A (IPv4)
            inet_ntop(AF_INET, response->data + index, (*answers)[i].address, INET6_ADDRSTRLEN);
        }
        index += (*answers)[i].datalength; // Move past the address
    }

    return DNS_OK;
}
