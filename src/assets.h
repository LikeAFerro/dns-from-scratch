#ifndef ASSETS_H
#define ASSETS_H

#include <stdint.h>

#define MAX_QUERY_SIZE 271
#define MAX_RESPONSE_SIZE 512

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header;

uint16_t build_query(const char *hostname, uint8_t **buf);
uint16_t send_query(uint8_t *query, uint16_t query_size, uint8_t **response);

#endif // ASSETS_H
