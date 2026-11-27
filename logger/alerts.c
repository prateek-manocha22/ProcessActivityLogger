/* Include headers for formatting, string matching, and alert logging. */
#include <stdio.h>
#include <string.h>

#include "alerts.h"
#include "logwriter.h"

#define MAX_ALERT_KEYS 256

/* Track a process identity already alerted for sustained resource usage. */
typedef struct {
    int active;
    int pid;
    unsigned long long start_ticks;
} AlertKey;

/* Check whether a (pid, start_ticks) pair is already present in a key table. */
static int has_alert_key(const AlertKey keys[], int pid, unsigned long long start_ticks) {
    for (int i = 0; i < MAX_ALERT_KEYS; i++) {
        if (keys[i].active && keys[i].pid == pid && keys[i].start_ticks == start_ticks) {
            return 1;
        }
    }
    return 0;
}

/* Add a (pid, start_ticks) pair into the first free slot of a key table. */
static void add_alert_key(AlertKey keys[], int pid, unsigned long long start_ticks) {
    if (has_alert_key(keys, pid, start_ticks)) {
        return;
    }
    for (int i = 0; i < MAX_ALERT_KEYS; i++) {
        if (!keys[i].active) {
            keys[i].active = 1;
            keys[i].pid = pid;
            keys[i].start_ticks = start_ticks;
            return;
        }
    }
}

/* Remove a (pid, start_ticks) pair once usage drops below the threshold. */
static void remove_alert_key(AlertKey keys[], int pid, unsigned long long start_ticks) {
    for (int i = 0; i < MAX_ALERT_KEYS; i++) {
        if (keys[i].active && keys[i].pid == pid && keys[i].start_ticks == start_ticks) {
            keys[i].active = 0;
            return;
        }
    }
}

/* Forget keys belonging to processes that are no longer running so slots stay free. */
static void prune_dead_keys(AlertKey keys[], const Process *list, int n) {
    for (int i = 0; i < MAX_ALERT_KEYS; i++) {
        if (!keys[i].active) {
            continue;
        }
        int still_alive = 0;
        for (int j = 0; j < n; j++) {
            if (list[j].pid == keys[i].pid && list[j].start_ticks == keys[i].start_ticks) {
                still_alive = 1;
                break;
            }
        }
        if (!still_alive) {
            keys[i].active = 0;
        }
    }
}

/* Check whether a process name matches any watched name in cfg->watch. */
static int is_watched_name(const char *name, const AlertConfig *cfg) {
    if (name == NULL || cfg == NULL) {
        return 0;
    }

    int limit = cfg->watch_count;
    if (limit > 8) {
        limit = 8;
    }

    for (int i = 0; i < limit; i++) {
        if (strcmp(name, cfg->watch[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void check_alerts(const Event *events, int n_events, const Process *list,
                  const double *cpu, int n, const AlertConfig *cfg) {
    static AlertKey cpu_keys[MAX_ALERT_KEYS];
    static AlertKey mem_keys[MAX_ALERT_KEYS];

    if (cfg == NULL) {
        return;
    }

    int started_count = 0;
    char msg[256];

    /* Check lifecycle events for zombies, fork bursts, and watched processes. */
    if (events != NULL && n_events > 0) {
        for (int i = 0; i < n_events; i++) {
            const Event *e = &events[i];

            if (e->type == EV_STARTED) {
                started_count++;
            }

            if ((e->type == EV_STARTED || e->type == EV_STATE_CHANGED) && e->proc.state == 'Z') {
                snprintf(msg, sizeof(msg),
                         "Zombie process detected: name=%s pid=%d parent=%d",
                         e->proc.name, e->proc.pid, e->proc.ppid);
                log_alert("WARNING", msg);
            }

            if ((e->type == EV_STARTED || e->type == EV_TERMINATED) &&
                is_watched_name(e->proc.name, cfg)) {
                const char *action = (e->type == EV_STARTED) ? "started" : "terminated";
                snprintf(msg, sizeof(msg),
                         "Watched process %s: name=%s pid=%d",
                         action, e->proc.name, e->proc.pid);
                log_alert("INFO", msg);
            }
        }

        if (cfg->burst_limit > 0 && started_count >= cfg->burst_limit) {
            snprintf(msg, sizeof(msg),
                     "Possible fork storm: %d processes started in one cycle",
                     started_count);
            log_alert("CRITICAL", msg);
        }
    }

    /* Check live CPU and memory usage, deduplicating repeated alerts per process. */
    if (list != NULL && cpu != NULL && n > 0) {
        prune_dead_keys(cpu_keys, list, n);
        prune_dead_keys(mem_keys, list, n);

        for (int i = 0; i < n; i++) {
            const Process *p = &list[i];

            if (cpu[i] >= cfg->cpu_limit) {
                if (!has_alert_key(cpu_keys, p->pid, p->start_ticks)) {
                    snprintf(msg, sizeof(msg),
                             "High CPU usage: name=%s pid=%d cpu=%.1f%% (limit=%.1f%%)",
                             p->name, p->pid, cpu[i], cfg->cpu_limit);
                    log_alert("WARNING", msg);
                    add_alert_key(cpu_keys, p->pid, p->start_ticks);
                }
            } else {
                remove_alert_key(cpu_keys, p->pid, p->start_ticks);
            }

            unsigned long rss_mb = p->rss_kb / 1024UL;
            if (rss_mb >= cfg->mem_limit_mb) {
                if (!has_alert_key(mem_keys, p->pid, p->start_ticks)) {
                    snprintf(msg, sizeof(msg),
                             "High memory usage: name=%s pid=%d rss=%luMB (limit=%luMB)",
                             p->name, p->pid, rss_mb, cfg->mem_limit_mb);
                    log_alert("WARNING", msg);
                    add_alert_key(mem_keys, p->pid, p->start_ticks);
                }
            } else {
                remove_alert_key(mem_keys, p->pid, p->start_ticks);
            }
        }
    }
}
