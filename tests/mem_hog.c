/* Include headers for malloc, memset, sleep, and output. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    /* Allocate 300 MB of memory and verify malloc succeeded. */
    size_t size = 300UL * 1024UL * 1024UL;
    unsigned char *buf = malloc(size);
    if (buf == NULL) {
        fprintf(stderr, "Error: malloc failed for 300 MB\n");
        return 1;
    }

    /* Touch every page with memset so the kernel allocates real physical RSS pages. */
    memset(buf, 0x42, size);
    printf("mem_hog holding 300 MB for 30s...\n");
    fflush(stdout);
    sleep(30);

    free(buf);
    return 0;
}
