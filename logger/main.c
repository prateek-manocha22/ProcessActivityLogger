/* Include standard input/output functions so we can print the process table. */
#include <stdio.h>

/* Include our snapshot header so we can use the Process struct and take_snapshot(). */
#include "snapshot.h"

int main(void) {
    /* Allocate the process list statically so a large MAX_PROCS array does not overflow the stack. */
    static Process list[MAX_PROCS];

    /* Print a startup message so the user knows the logger has begun running. */
    if (printf("Process Activity Logger starting\n\n") < 0) {
        return 1;
    }

    /* Collect a live snapshot of all processes currently visible in /proc. */
    int count = take_snapshot(list, MAX_PROCS);

    /* Print the column headers aligned neatly for easy reading. */
    printf("%-8s %-8s %-6s %s\n", "PID", "PPID", "STATE", "NAME");

    /* Loop through every captured process and print one row per process. */
    for (int i = 0; i < count; i++) {
        printf("%-8d %-8d %-6c %s\n",
               list[i].pid,
               list[i].ppid,
               list[i].state,
               list[i].name);
    }

    /* Print the final summary line showing how many processes were found. */
    printf("\nFound %d processes\n", count);

    /* Return 0 to tell the operating system that the program finished without errors. */
    return 0;
}
