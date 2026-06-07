#include "assets.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[]) {
    // Validate command-line arguments
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <domain>\n", argv[0]);
        exit(1);
    }

    srand(time(NULL));

    uint8_t *query = NULL;
    uint16_t query_size;
    dns_status status = build_query(argv[1], &query, &query_size);
    if (status != DNS_OK) {
        if (status == DNS_MEMORY_ERROR) {
            fprintf(stderr, "Memory allocation failed\n");
        } else if (status == DNS_QUERY_ERROR) {
            fprintf(stderr, "Invalid hostname\n");
        } else {
            fprintf(stderr, "Unknown error occurred\n");
        }
        exit(1);
    }

    // -------------------------------- Debug: Print the raw query bytes
    // printf("%d bytes:\n", query_size);
    // for (uint16_t i = 0; i < query_size; i++) {
    //     printf("%02x ", query[i]);
    // }
    // printf("\n");
    // -------------------------------- End debug

    uint8_t *response = NULL;
    uint16_t response_size;
    status = send_query(query, query_size, &response, &response_size);
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
        free(query);
        free(response);
        exit(1);
    }

    // -------------------------------- Debug: Print the raw response bytes
    // printf("Received response:\n");
    // for (uint16_t i = 0; i < response_size; i++) {
    //    printf("%02x ", response[i]);
    //}
    // printf("\n");
    // -------------------------------- End debug

    int answer_count = 0;
    dns_answer *answers = NULL;
    status = parse_response(response, response_size, &answer_count, &answers);
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
        free(query);
        free(response);
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

    free(query);
    free(response);
    free(answers);
    return 0;
}
