/* Prevent duplicate inclusion of alert evaluation declarations. */
#ifndef ALERTS_H
#define ALERTS_H

#include "detector.h"
#include "snapshot.h"

/* Hold thresholds and watched process names configured by the user. */
typedef struct {
    double cpu_limit;
    unsigned long mem_limit_mb;
    int burst_limit;
    char watch[8][64];
    int watch_count;
} AlertConfig;

/* Inspect events and live metrics and record triggered alerts to alerts.csv. */
void check_alerts(const Event *events, int n_events, const Process *list,
                  const double *cpu, int n, const AlertConfig *cfg);

#endif
