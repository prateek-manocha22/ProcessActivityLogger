/* Prevent duplicate inclusion of process event detection declarations. */
#ifndef DETECTOR_H
#define DETECTOR_H

#include "snapshot.h"

/* Identify the three lifecycle changes detected between two snapshots. */
typedef enum { EV_STARTED, EV_TERMINATED, EV_STATE_CHANGED } EventType;

/* Represent one detected process lifecycle event. */
typedef struct {
    EventType type;
    Process proc;
    char old_state;
} Event;

/* Cap the maximum number of events reported in a single cycle. */
#define MAX_EVENTS 8192

/* Compare old_list and new_list to emit STARTED, TERMINATED, and STATE_CHANGED events. */
int detect_events(const Process *old_list, int old_n, const Process *new_list,
                  int new_n, Event *events, int max_events);

/* Calculate CPU percentage for each process in new_list over elapsed_sec. */
void compute_cpu_percent(const Process *old_list, int old_n,
                         const Process *new_list, int new_n,
                         double elapsed_sec, double *cpu_out);

#endif
