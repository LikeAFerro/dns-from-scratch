#include "assets.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    // Validate command-line arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <domain>\n", argv[0]);
        exit(1);
    }

    // Initialize the DNS query structure with default values
    dns_query query = query_default();
    dns_config config = config_default();

    // Check for optional flags
    while (getopt(argc, argv, "h6") != -1) {
        switch (optopt) {
        case 'h':
            printf("Usage: dns-from-scratch <domain>\n");
            printf("Example: dns-from-scratch example.com\n");
            printf("Domain name is required. Options:\n");
            printf("  -h: Show this help message\n");
            printf("  -6: Query for IPv6 addresses\n");
            exit(0);
        case '6':
            query.qtype = htons(DNS_QTYPE_AAAA);
            break;
        default:
            fprintf(stderr, "Unknown option: -%c\n", optopt);
            exit(1);
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "Expected domain name after options\n");
        exit(1);
    }
    char user_query[MAX_HOSTNAME_LENGTH];
    snprintf(user_query, sizeof(user_query), "%s", argv[optind]);

    srand(time(NULL));

    dns_status status = build_query(user_query, &query, &config);
    if (status != DNS_OK) {
        if (status == DNS_QUERY_ERROR) {
            fprintf(stderr, "Invalid hostname\n");
        }
        if (status == DNS_MEMORY_ERROR) {
            fprintf(stderr, "Memory allocation failed\n");
        } else {
            fprintf(stderr, "Unknown error occurred\n");
        }
        free(query.query_name);
        exit(1);
    }

    uint8_t *response = NULL;
    uint16_t response_size;
    status = send_query(&query, &config, &response, &response_size);
    if (status != DNS_OK) {
        switch (status) {
        case DNS_SOCKET_ERROR:
            fprintf(stderr, "Socket error occurred\n");
            break;
        case DNS_MEMORY_ERROR:
            fprintf(stderr, "Memory allocation failed\n");
            break;
        case DNS_TIMEOUT_ERROR:
            fprintf(stderr, "Request timed out\n");
            break;
        case DNS_INVALID_QUERY:
            fprintf(stderr, "Invalid query format\n");
            break;
        case DNS_INVALID_ADDRESS:
            fprintf(stderr, "Invalid DNS server address\n");
            break;
        default:
            fprintf(stderr, "Unknown error occurred\n");
        }
        free(query.query_name);
        free(response);
        exit(1);
    }

    dns_answer *answers = NULL;
    status = parse_response(&query, response, response_size, &answers);
    if (status != DNS_OK) {
        switch (status) {
        case DNS_INVALID_ANSWER:
            fprintf(stderr, "Invalid answer format in response\n");
            break;
        case DNS_NO_ANSWERS:
            fprintf(stderr, "No answers found in response\n");
            break;
        case DNS_MEMORY_ERROR:
            fprintf(stderr, "Memory allocation failed\n");
            break;
        default:
            fprintf(stderr, "Unknown error occurred\n");
        }
        free(query.query_name);
        free(response);
        free(answers);
        exit(1);
    }

    printf("Answers received: %d\n", query.ancount);
    for (int i = 0; i < query.ancount; i++) {
        printf("Type: %u, Class: %u, TTL: %u, Data Length: %u, Address: %s\n",
               answers[i].type,
               answers[i].addr_class,
               answers[i].ttl,
               answers[i].datalength,
               answers[i].address);
    }

    free(query.query_name);
    free(response);
    free(answers);
    return 0;
}
