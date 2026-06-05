#include "assets.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <domain>\n", argv[0]);
        exit(1);
    }

    srand(time(NULL));

    uint8_t *query = NULL;
    uint16_t size;
    if (!(size = build_query(argv[1], &query))) {
        fprintf(stderr, "Failed to build query\n");
        exit(1);
    }

    printf("%d bytes:\n", size);

    for (uint16_t i = 0; i < size; i++) {
        printf("%02x ", query[i]);
    }
    printf("\n");

    uint8_t *response = NULL;
    uint16_t response_size = send_query(query, size, &response);
    if (!response || response_size == 0) {
        fprintf(stderr, "No response received\n");
        free(query);
        exit(1);
    }

    printf("Received response:\n");
    for (uint16_t i = 0; i < response_size; i++) {
        printf("%02x ", response[i]);
    }
    printf("\n");

    dns_answer *answers = parse_response(response, response_size);
    if (!answers) {
        fprintf(stderr, "Failed to parse response\n");
        free(query);
        free(response);
        exit(1);
    }

    printf("Answer:\n");
    printf("Type: %u, Class: %u, TTL: %u, Data Length: %u, Address: %s\n",
           answers[0].type,
           answers[0].addr_class,
           answers[0].ttl,
           answers[0].datalength,
           answers[0].address);

    free(query);
    free(response);
    free(answers);
    return 0;
}
