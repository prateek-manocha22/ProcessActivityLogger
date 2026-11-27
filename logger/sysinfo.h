/* Prevent duplicate inclusion of system info helpers. */
#ifndef SYSINFO_H
#define SYSINFO_H

#include <time.h>

/* Return the kernel clock ticks per second using sysconf(_SC_CLK_TCK). */
long get_ticks_per_sec(void);

/* Return the system boot time in Unix epoch seconds from /proc/stat. */
time_t get_boot_time(void);

/* Convert a process start time in clock ticks into a Unix epoch timestamp. */
time_t ticks_to_epoch(unsigned long long t);

/* Return total installed physical RAM in kilobytes from /proc/meminfo. */
unsigned long get_total_mem_kb(void);

#endif
