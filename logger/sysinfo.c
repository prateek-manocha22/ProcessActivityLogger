/* Include headers needed for sysconf, file reading, and string matching. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sysinfo.h"

long get_ticks_per_sec(void) {
    /* Query the kernel tick rate and fall back to 100 Hz if unavailable. */
    long ticks = sysconf(_SC_CLK_TCK);
    if (ticks <= 0) {
        return 100;
    }
    return ticks;
}

time_t get_boot_time(void) {
    /* Cache the boot time after the first read because it stays constant until reboot. */
    static time_t cached_btime = 0;
    if (cached_btime > 0) {
        return cached_btime;
    }

    /* Open /proc/stat and scan for the "btime" line holding the boot timestamp. */
    FILE *fp = fopen("/proc/stat", "r");
    if (fp == NULL) {
        return 0;
    }

    char line[512];
    unsigned long long btime = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "btime %llu", &btime) == 1) {
            cached_btime = (time_t)btime;
            break;
        }
    }

    fclose(fp);
    return cached_btime;
}

time_t ticks_to_epoch(unsigned long long t) {
    /* Add the process start offset in seconds to the system boot timestamp. */
    long tps = get_ticks_per_sec();
    time_t boot = get_boot_time();
    return boot + (time_t)(t / (unsigned long long)tps);
}

unsigned long get_total_mem_kb(void) {
    /* Open /proc/meminfo and search for the MemTotal line in kilobytes. */
    FILE *fp = fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        return 0;
    }

    char line[256];
    unsigned long mem_kb = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "MemTotal: %lu", &mem_kb) == 1) {
            break;
        }
    }

    fclose(fp);
    return mem_kb;
}
