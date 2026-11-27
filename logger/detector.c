/* Include standard definitions along with detector and sysinfo headers. */
#include <stddef.h>

#include "detector.h"
#include "sysinfo.h"

/* Find a process in list by its unique (pid, start_ticks) identity. */
static int find_process(const Process *list, int n, int pid, unsigned long long start_ticks) {
    if (list == NULL || n <= 0) {
        return -1;
    }

    for (int i = 0; i < n; i++) {
        if (list[i].pid == pid && list[i].start_ticks == start_ticks) {
            return i;
        }
    }

    return -1;
}

int detect_events(const Process *old_list, int old_n, const Process *new_list,
                  int new_n, Event *events, int max_events) {
    if (events == NULL || max_events <= 0) {
        return 0;
    }
    if ((old_n > 0 && old_list == NULL) || (new_n > 0 && new_list == NULL)) {
        return 0;
    }

    int count = 0;

    /* Scan new processes to detect newly started ones and state transitions. */
    for (int i = 0; i < new_n && count < max_events; i++) {
        int old_idx = find_process(old_list, old_n, new_list[i].pid, new_list[i].start_ticks);
        if (old_idx < 0) {
            events[count].type = EV_STARTED;
            events[count].proc = new_list[i];
            events[count].old_state = '-';
            count++;
        } else if (old_list[old_idx].state != new_list[i].state) {
            events[count].type = EV_STATE_CHANGED;
            events[count].proc = new_list[i];
            events[count].old_state = old_list[old_idx].state;
            count++;
        }
    }

    /* Scan old processes to detect any that disappeared in the new snapshot. */
    for (int i = 0; i < old_n && count < max_events; i++) {
        int new_idx = find_process(new_list, new_n, old_list[i].pid, old_list[i].start_ticks);
        if (new_idx < 0) {
            events[count].type = EV_TERMINATED;
            events[count].proc = old_list[i];
            events[count].old_state = '-';
            count++;
        }
    }

    return count;
}

void compute_cpu_percent(const Process *old_list, int old_n,
                         const Process *new_list, int new_n,
                         double elapsed_sec, double *cpu_out) {
    if (new_list == NULL || cpu_out == NULL || new_n <= 0) {
        return;
    }

    long ticks_per_sec = get_ticks_per_sec();

    /* Compute CPU % per new process using tick delta divided by total ticks in the interval. */
    for (int i = 0; i < new_n; i++) {
        if (old_list == NULL || old_n <= 0 || elapsed_sec <= 0.0) {
            cpu_out[i] = 0.0;
            continue;
        }

        int old_idx = find_process(old_list, old_n, new_list[i].pid, new_list[i].start_ticks);
        if (old_idx < 0 || new_list[i].cpu_ticks < old_list[old_idx].cpu_ticks) {
            cpu_out[i] = 0.0;
            continue;
        }

        unsigned long long delta_ticks = new_list[i].cpu_ticks - old_list[old_idx].cpu_ticks;
        cpu_out[i] = ((double)delta_ticks / ((double)ticks_per_sec * elapsed_sec)) * 100.0;
    }
}
