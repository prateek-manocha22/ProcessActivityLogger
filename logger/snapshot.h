/* Prevent duplicate inclusion of snapshot declarations. */
#ifndef SNAPSHOT_H
#define SNAPSHOT_H

/* Store the key metrics collected for one running Linux process. */
typedef struct {
    int pid;
    int ppid;
    char name[64];
    char state;
    char user[32];
    int priority;
    int nice;
    int threads;
    unsigned long long start_ticks;
    unsigned long long cpu_ticks;
    unsigned long rss_kb;
} Process;

/* Cap the maximum number of processes held in one snapshot array. */
#define MAX_PROCS 4096

/* Read details for one PID from /proc; returns 0 on success, -1 on failure. */
int read_process(int pid, Process *out);

/* Scan /proc for all running processes into list up to max; returns count. */
int take_snapshot(Process list[], int max);

#endif
