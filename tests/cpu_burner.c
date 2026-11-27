/* Include headers for clock_gettime and output. */
#include <stdio.h>
#include <time.h>

int main(void) {
    struct timespec start;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Spin in a CPU-bound loop for about 20 seconds to trigger high-CPU detection. */
    volatile unsigned long long counter = 0;
    while (1) {
        for (int i = 0; i < 1000000; i++) {
            counter++;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - start.tv_sec) >= 20) {
            break;
        }
    }

    printf("cpu_burner finished after 20s (counter=%llu)\n", counter);
    return 0;
}
