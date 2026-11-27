/* Include headers for CLI options, signals, timing, memory, and logger modules. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "alerts.h"
#include "detector.h"
#include "logwriter.h"
#include "snapshot.h"

/* Flag set by SIGINT or SIGTERM so the main loop can shut down cleanly. */
static volatile sig_atomic_t stop_requested = 0;

/* Signal handler that only records the stop request asynchronously. */
static void handle_signal(int sig) {
    (void)sig;
    stop_requested = 1;
}

/* Print command-line options and defaults for the user. */
static void print_usage(const char *prog) {
    printf("Usage: %s [-i seconds] [-c cpu_limit] [-m mem_mb] [-b burst] [-w name] [-h]\n", prog);
    printf("  -i seconds    Polling interval in seconds (default: 2)\n");
    printf("  -c cpu_limit  CPU%% alert threshold (default: 80)\n");
    printf("  -m mem_mb     Memory RSS alert threshold in MB (default: 500)\n");
    printf("  -b burst      New processes per cycle burst limit (default: 30)\n");
    printf("  -w name       Watch process name (repeatable, up to 8)\n");
    printf("  -h            Show this help message\n");
}

/* Format current local wall-clock time as HH:MM:SS for terminal status lines. */
static void format_hms(time_t t, char *buf, size_t size) {
    struct tm tm_info;
    if (localtime_r(&t, &tm_info) == NULL || strftime(buf, size, "%H:%M:%S", &tm_info) == 0) {
        snprintf(buf, size, "00:00:00");
    }
}

int main(int argc, char *argv[]) {
    /* Initialize default polling interval and alert configuration values. */
    int interval = 2;
    AlertConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.cpu_limit = 80.0;
    cfg.mem_limit_mb = 500;
    cfg.burst_limit = 30;

    /* Parse command-line flags with getopt. */
    int opt;
    while ((opt = getopt(argc, argv, "i:c:m:b:w:h")) != -1) {
        switch (opt) {
            case 'i':
                interval = atoi(optarg);
                if (interval < 1) {
                    fprintf(stderr, "Error: -i interval must be at least 1 second\n");
                    return 1;
                }
                break;
            case 'c':
                cfg.cpu_limit = atof(optarg);
                if (cfg.cpu_limit <= 0.0) {
                    fprintf(stderr, "Error: -c cpu_limit must be positive\n");
                    return 1;
                }
                break;
            case 'm': {
                long mem_val = atol(optarg);
                if (mem_val <= 0) {
                    fprintf(stderr, "Error: -m mem_limit_mb must be positive\n");
                    return 1;
                }
                cfg.mem_limit_mb = (unsigned long)mem_val;
                break;
            }
            case 'b':
                cfg.burst_limit = atoi(optarg);
                if (cfg.burst_limit <= 0) {
                    fprintf(stderr, "Error: -b burst_limit must be positive\n");
                    return 1;
                }
                break;
            case 'w':
                if (cfg.watch_count >= 8) {
                    fprintf(stderr, "Error: at most 8 -w watched names are allowed\n");
                    return 1;
                }
                snprintf(cfg.watch[cfg.watch_count], sizeof(cfg.watch[0]), "%s", optarg);
                cfg.watch_count++;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Install SIGINT and SIGTERM handlers without SA_RESTART so sleep wakes up promptly. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Allocate snapshot, CPU, and event buffers on the heap to avoid stack overflow. */
    Process *old_list = malloc(sizeof(Process) * MAX_PROCS);
    Process *new_list = malloc(sizeof(Process) * MAX_PROCS);
    Event *events = malloc(sizeof(Event) * MAX_EVENTS);
    double *cpu_out = malloc(sizeof(double) * MAX_PROCS);
    if (old_list == NULL || new_list == NULL || events == NULL || cpu_out == NULL) {
        fprintf(stderr, "Error: failed to allocate memory for process buffers\n");
        free(old_list);
        free(new_list);
        free(events);
        free(cpu_out);
        return 1;
    }

    /* Capture the initial baseline snapshot and write initial live.csv. */
    int old_n = take_snapshot(old_list, MAX_PROCS);
    memset(cpu_out, 0, sizeof(double) * (size_t)MAX_PROCS);
    write_live(old_list, cpu_out, old_n);

    struct timespec prev_ts;
    clock_gettime(CLOCK_MONOTONIC, &prev_ts);

    unsigned long total_events = 0;

    /* Run the monitoring loop until SIGINT or SIGTERM sets stop_requested. */
    while (!stop_requested) {
        sleep((unsigned int)interval);
        if (stop_requested) {
            break;
        }

        /* Take a new snapshot and measure real elapsed monotonic seconds. */
        int new_n = take_snapshot(new_list, MAX_PROCS);
        struct timespec curr_ts;
        clock_gettime(CLOCK_MONOTONIC, &curr_ts);

        double elapsed_sec = (double)(curr_ts.tv_sec - prev_ts.tv_sec) +
                             (double)(curr_ts.tv_nsec - prev_ts.tv_nsec) / 1e9;
        if (elapsed_sec <= 0.0) {
            elapsed_sec = 0.001;
        }
        prev_ts = curr_ts;

        /* Compute CPU %, detect events, write CSV logs, and evaluate alert rules. */
        compute_cpu_percent(old_list, old_n, new_list, new_n, elapsed_sec, cpu_out);
        int ev_n = detect_events(old_list, old_n, new_list, new_n, events, MAX_EVENTS);

        time_t now = time(NULL);
        int started = 0;
        int terminated = 0;
        int changed = 0;

        for (int i = 0; i < ev_n; i++) {
            log_event(&events[i], now);
            if (events[i].type == EV_STARTED) {
                started++;
            } else if (events[i].type == EV_TERMINATED) {
                terminated++;
            } else if (events[i].type == EV_STATE_CHANGED) {
                changed++;
            }
        }
        total_events += (unsigned long)ev_n;

        check_alerts(events, ev_n, new_list, cpu_out, new_n, &cfg);
        write_live(new_list, cpu_out, new_n);

        /* Swap buffers so the current snapshot becomes the previous one for the next cycle. */
        Process *tmp = old_list;
        old_list = new_list;
        new_list = tmp;
        old_n = new_n;

        char hms[16];
        format_hms(now, hms, sizeof(hms));
        printf("[%s] processes=%d started=%d terminated=%d changed=%d\n",
               hms, new_n, started, terminated, changed);
        fflush(stdout);
    }

    /* Report clean shutdown summary and release all heap allocations. */
    printf("\nStopped. Total events logged: %lu\n", total_events);

    free(old_list);
    free(new_list);
    free(events);
    free(cpu_out);
    return 0;
}
