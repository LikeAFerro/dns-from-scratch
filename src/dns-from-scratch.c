#include "assets.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    // Initial configuration and argument parsing
    dns_query query;
    dns_config config;
    dns_buffer serialized_query = {NULL, 0}, serialized_response = {NULL, 0};
    dns_status status = initial_config(argc, argv, &config, &query);
    if (status != DNS_OK) {
        switch (status) {
        case DNS_HELP:
            printf("Usage: %s [options] <hostname>\n", argv[0]);
            printf("Options:\n");
            printf("  -h        Show this help message\n");
            printf("  -6        Query for AAAA records (IPv6)\n");
            printf("  -R <addr> Specify custom DNS server address\n");
            exit(0);
        case DNS_ARGUMENT_ERROR:
            fprintf(stderr, "Invalid arguments provided\n");
            break;
        case DNS_HOSTNAME_ERROR:
            fprintf(stderr, "Invalid hostname provided\n");
            break;
        case DNS_OPTION_ERROR:
            fprintf(stderr, "Invalid option provided\n");
            break;
        default:
            fprintf(stderr, "Unknown error occurred during initial configuration\n");
        }
        exit(1);
    }

    // Serialization into a byte array according to the DNS protocol format
    status = serialize_query(&query, &serialized_query);
    if (status != DNS_OK) {
        if (status == DNS_MEMORY_ERROR) {
            fprintf(stderr, "Memory allocation failed\n");
        } else if (status == DNS_HOSTNAME_ERROR) {
            fprintf(stderr, "Invalid hostname provided\n");
        } else if (status == DNS_QUERY_ERROR) {
            fprintf(stderr, "Invalid query parameters\n");
        } else {
            fprintf(stderr, "Unknown error occurred during query serialization\n");
        }
        free(serialized_query.data);
        exit(1);
    }

    // Send the query and receive the response
    status = send_query(&serialized_query, &config, &serialized_response);
    if (status != DNS_OK) {
        switch (status) {
        case DNS_SOCKET_ERROR:
            fprintf(stderr, "Socket error occurred\n");
            break;
        case DNS_MEMORY_ERROR:
            fprintf(stderr, "Memory allocation failed\n");
            break;
        case DNS_ADDRESS_ERROR:
            fprintf(stderr, "Invalid DNS server address\n");
            break;
        default:
            fprintf(stderr, "Unknown error occurred\n");
        }
        free(serialized_query.data);
        free(serialized_response.data);
        exit(1);
    }

    dns_answer *answers = NULL;
    uint16_t answer_count = 0;
    status = parse_response(&serialized_response, &answers, &answer_count);
    if (status != DNS_OK) {
        switch (status) {
        case DNS_ANSWER_ERROR:
            fprintf(stderr, "Invalid answer format in response\n");
            break;
        case DNS_MEMORY_ERROR:
            fprintf(stderr, "Memory allocation failed\n");
            break;
        default:
            fprintf(stderr, "Unknown error occurred\n");
        }
        free(serialized_query.data);
        free(serialized_response.data);
        free(answers);
        exit(1);
    }

    printf("Answers received: %d\n", answer_count);
    for (int i = 0; i < answer_count; i++) {
        printf("Type: %u, Class: %u, TTL: %u, Data Length: %u, Address: %s\n",
               answers[i].type,
               answers[i].addr_class,
               answers[i].ttl,
               answers[i].datalength,
               answers[i].address);
    }

    free(serialized_query.data);
    free(serialized_response.data);
    free(answers);
    return 0;
}
