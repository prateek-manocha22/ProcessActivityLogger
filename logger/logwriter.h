/* Prevent duplicate inclusion of CSV logging declarations. */
#ifndef LOGWRITER_H
#define LOGWRITER_H

#include <time.h>

#include "detector.h"
#include "snapshot.h"

/* Append one lifecycle event row to logs/events.csv. */
void log_event(const Event *e, time_t now);

/* Atomically write the current process snapshot to logs/live.csv. */
void write_live(const Process *list, const double *cpu, int n);

/* Append one alert row to logs/alerts.csv. */
void log_alert(const char *severity, const char *message);

#endif
