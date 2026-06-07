#ifndef ASSETS_H
#define ASSETS_H

#include <stdint.h>

#define MAX_QUERY_SIZE 271
#define MAX_RESPONSE_SIZE 512
#define ADDRESS_SIZE 16

typedef enum {
    DNS_OK = 0,
    DNS_QUERY_ERROR,
    DNS_MEMORY_ERROR,
    DNS_SOCKET_ERROR,
    DNS_INVALID_QUERY,
    DNS_INVALID_ADDRESS,
    DNS_TIMEOUT_ERROR,
    DNS_NO_ANSWERS,
    DNS_INVALID_ANSWER
} dns_status;

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header;

typedef struct {
    uint16_t type;
    uint16_t addr_class;
} dns_footer;

typedef struct {
    uint16_t type;
    uint16_t addr_class;
    uint32_t ttl;
    uint16_t datalength;
    char address[ADDRESS_SIZE]; // IPv4 address
} dns_answer;

dns_status build_query(const char *hostname, uint8_t **buf, uint16_t *query_size);
dns_status send_query(uint8_t *query, uint16_t query_size, uint8_t **response,
                      uint16_t *response_size);
dns_status parse_response(uint8_t *response, uint16_t response_size, int *answer_count,
                          dns_answer **answers);

#endif // ASSETS_H
