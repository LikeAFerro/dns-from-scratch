#ifndef ASSETS_H
#define ASSETS_H

#include <netinet/in.h>
#include <stdint.h>

#define DNS_DEFAULT_SERVER "8.8.8.8"
#define DNS_DEFAULT_PORT 53
#define DNS_DEFAULT_TIMEOUT 5
#define DNS_HEADER_SIZE 12
#define DNS_FIXED_FIELDS_SIZE 16
#define DNS_MAX_HOSTNAME_LENGTH 253
#define DNS_MAX_QUERY_SIZE 271
#define DNS_MAX_RESPONSE_SIZE 512
#define DNS_QTYPE_A 0X0001
#define DNS_QTYPE_AAAA 0X001C
#define DNS_STANDARD_QUERY_FLAGS 0x0100
#define DNS_NAME_POINTER 0xC0

/** @brief Status codes for DNS operations */
typedef enum {
    DNS_OK = 0,
    DNS_HELP,
    DNS_QUERY_ERROR,
    DNS_HOSTNAME_ERROR,
    DNS_OPTION_ERROR,
    DNS_ARGUMENT_ERROR,
    DNS_MEMORY_ERROR,
    DNS_SOCKET_ERROR,
    DNS_ADDRESS_ERROR,
    DNS_ANSWER_ERROR
} dns_status;

typedef struct {
    char dns_server[INET6_ADDRSTRLEN]; // DNS server address (IPv4 for now)
    uint16_t port;                     // DNS server port
    uint16_t timeout;                  // Query timeout
} dns_config;

/** @brief Unserialized DNS query structure */
typedef struct {
    uint16_t id;                                  // Query ID
    uint16_t flags;                               // Query flags
    uint16_t qdcount;                             // Number of questions
    char query_name[DNS_MAX_HOSTNAME_LENGTH + 1]; // Domain name to query
    uint16_t qtype;                               // Query type (e.g., A, AAAA)
    uint16_t qclass;                              // Query class (usually 1 for IN)
} dns_query;

/** @brief Unserialized DNS answer structure */
typedef struct {
    uint16_t type;                  // Answer type (e.g., A, AAAA)
    uint16_t addr_class;            // Answer class (usually 1 for IN)
    uint32_t ttl;                   // Time to live for the answer
    uint16_t datalength;            // Length of the answer data
    char address[INET6_ADDRSTRLEN]; // Buffer to hold the string representation of the IP address
} dns_answer;

typedef struct {
    uint8_t *data; // Pointer to the serialized query data
    uint16_t size; // Size of the serialized query data
} dns_buffer;

/** @brief Parse the arguments to initialize DNS configuration and query structures
 * @param argc Argument count
 * @param argv Argument values
 * @param config Output DNS configuration structure
 * @param query Output DNS query structure
 * @return DNS status code indicating success or type of error
 */
dns_status initial_config(int argc, char *argv[], dns_config *config, dns_query *query);

/** @brief Serialize a DNS query structure into a byte array
 * @param query The DNS query structure to serialize
 * @param serialized_query Output buffer for the serialized query
 * @return DNS status code indicating success or type of error
 */
dns_status serialize_query(const dns_query *query, dns_buffer *serialized_query);

/** @brief Send a DNS query and receive a response
 * @param query The DNS query to send
 * @param config DNS configuration structure
 * @param response Output buffer for the DNS response
 * @return DNS status code indicating success or type of error
 */
dns_status send_query(const dns_buffer *query, const dns_config *config, dns_buffer *response);

/** @brief Parse a DNS response
 * @param response The DNS response to parse
 * @param answers Output variable for the array of parsed answers
 * @param answer_count Output variable for the number of parsed answers
 * @return DNS status code indicating success or type of error
 */
dns_status parse_response(const dns_buffer *response, dns_answer **answers, uint16_t *answer_count);

#endif // ASSETS_H
