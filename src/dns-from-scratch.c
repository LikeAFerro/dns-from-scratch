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

    uint8_t *buf = NULL;
    uint16_t size;
    if (!(size = build_query(argv[1], &buf))) {
        fprintf(stderr, "Failed to build query\n");
        exit(1);
    }

    printf("%d bytes:\n", size);

    for (uint16_t i = 0; i < size; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");

    free(buf);
    return 0;
}
