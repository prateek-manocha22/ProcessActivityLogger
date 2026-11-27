/* Header guard prevents this file from being included more than once. */
#ifndef SNAPSHOT_H
#define SNAPSHOT_H

/* Group all important information about one running process into a single struct. */
typedef struct {
    int pid;
    int ppid;
    char name[256];
    char state;                      /* R, S, D, Z, T ... */
    unsigned long long start_ticks;  /* field 22 of /proc/<pid>/stat */
} Process;

/* Limit how many processes we store at once so memory usage stays predictable. */
#define MAX_PROCS 4096

/* Read one process's details from /proc/<pid>/stat; returns 0 on success, -1 on failure. */
int read_process(int pid, Process *out);     /* 0 = ok, -1 = failed */

/* Scan /proc for all running processes and fill list up to max; returns how many were found. */
int take_snapshot(Process list[], int max);  /* returns how many were found */

#endif
