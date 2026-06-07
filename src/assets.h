#ifndef ASSETS_H
#define ASSETS_H

#include <stdint.h>

#define MAX_HOSTNAME_LENGTH 253
#define MAX_QUERY_SIZE 271
#define MAX_RESPONSE_SIZE 512
#define ADDRESS_SIZE 16

/** @brief Status codes for DNS operations */
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

/** @brief DNS header structure */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header;

/** @brief DNS footer structure */
typedef struct {
    uint16_t type;
    uint16_t addr_class;
} dns_footer;

/** @brief DNS answer structure */
typedef struct {
    uint16_t type;
    uint16_t addr_class;
    uint32_t ttl;
    uint16_t datalength;
    char address[ADDRESS_SIZE]; // IPv4 address
} dns_answer;

/** @brief Build a DNS query for a given hostname
 * @param hostname The domain name to query
 * @param buf Output buffer for the query
 * @param query_size Output variable for the size of the query
 * @return DNS status code indicating success or type of error
 */
dns_status build_query(const char *hostname, uint8_t **buf, uint16_t *query_size);

/** @brief Send a DNS query and receive a response
 * @param query The DNS query to send
 * @param query_size The size of the DNS query
 * @param response Output buffer for the DNS response
 * @param response_size Output variable for the size of the DNS response
 * @return DNS status code indicating success or type of error
 */
dns_status send_query(uint8_t *query, uint16_t query_size, uint8_t **response,
                      uint16_t *response_size);
/** @brief Parse a DNS response
 * @param response The DNS response to parse
 * @param response_size The size of the DNS response
 * @param answer_count Output variable for the number of answers parsed
 * @param answers Output variable for the array of parsed answers
 * @return DNS status code indicating success or type of error
 */
dns_status parse_response(uint8_t *response, uint16_t response_size, int *answer_count,
                          dns_answer **answers);

#endif // ASSETS_H
