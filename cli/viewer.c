/* Include standard headers for file I/O, sorting, memory allocation, and string splitting. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Represent one parsed event row from logs/events.csv. */
typedef struct {
    char timestamp[32];
    char event[20];
    int pid;
    int ppid;
    char name[64];
    char state[8];
    char old_state[8];
    char user[32];
    int threads;
    unsigned long rss_kb;
    long lifetime_sec;
} EventRow;

/* Represent one parsed alert row from logs/alerts.csv. */
typedef struct {
    char timestamp[32];
    char severity[16];
    char message[256];
} AlertRow;

/* Represent one parsed live snapshot row from logs/live.csv. */
typedef struct {
    int pid;
    int ppid;
    char name[64];
    char user[32];
    char state[8];
    double cpu_percent;
    unsigned long rss_kb;
    int threads;
    int priority;
    int nice;
    char start_time[32];
} LiveRow;

/* Track the chosen sort column for the live subcommand. */
typedef enum { SORT_CPU, SORT_MEM, SORT_PID } LiveSort;

/* Print usage instructions for all viewer subcommands and flags. */
static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s events [--last N] [--event TYPE] [--name TEXT] [--pid N]\n", prog);
    printf("  %s alerts [--last N] [--severity LEVEL]\n", prog);
    printf("  %s live   [--sort cpu|mem|pid] [--top N]\n", prog);
}

/* Split a mutable CSV line on commas using strsep while keeping empty fields. */
static int split_csv_line(char *line, char *fields[], int max_fields) {
    if (line == NULL || fields == NULL || max_fields <= 0) {
        return 0;
    }

    /* Strip trailing newline and carriage return characters first. */
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }

    int count = 0;
    char *cursor = line;
    while (count < max_fields) {
        char *token = strsep(&cursor, ",");
        if (token == NULL) {
            break;
        }
        fields[count++] = token;
    }

    return count;
}

/* Open a CSV file or print a friendly message telling the user to start the logger. */
static FILE *open_csv_or_warn(const char *path) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        printf("Could not open %s. Please start the logger first (./build/logger).\n", path);
    }
    return fp;
}

/* Handle the "viewer events" subcommand with filtering and --last tailing. */
static int cmd_events(int argc, char *argv[]) {
    int last_n = 20;
    const char *filter_event = NULL;
    const char *filter_name = NULL;
    int filter_pid = -1;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--last") == 0 && i + 1 < argc) {
            last_n = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--event") == 0 && i + 1 < argc) {
            filter_event = argv[++i];
        } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            filter_name = argv[++i];
        } else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            filter_pid = atoi(argv[++i]);
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (last_n <= 0) {
        last_n = 20;
    }

    FILE *fp = open_csv_or_warn("logs/events.csv");
    if (fp == NULL) {
        return 0;
    }

    /* Read matching event rows into a dynamically growing array via realloc. */
    EventRow *rows = NULL;
    int count = 0;
    int cap = 0;
    char line[1024];
    int line_num = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line_num++ == 0) {
            continue;
        }

        char *fields[11];
        if (split_csv_line(line, fields, 11) < 11) {
            continue;
        }

        EventRow row;
        snprintf(row.timestamp, sizeof(row.timestamp), "%s", fields[0]);
        snprintf(row.event, sizeof(row.event), "%s", fields[1]);
        row.pid = atoi(fields[2]);
        row.ppid = atoi(fields[3]);
        snprintf(row.name, sizeof(row.name), "%s", fields[4]);
        snprintf(row.state, sizeof(row.state), "%s", fields[5]);
        snprintf(row.old_state, sizeof(row.old_state), "%s", fields[6]);
        snprintf(row.user, sizeof(row.user), "%s", fields[7]);
        row.threads = atoi(fields[8]);
        row.rss_kb = strtoul(fields[9], NULL, 10);
        row.lifetime_sec = strtol(fields[10], NULL, 10);

        if (filter_event != NULL && strcmp(row.event, filter_event) != 0) {
            continue;
        }
        if (filter_name != NULL && strstr(row.name, filter_name) == NULL) {
            continue;
        }
        if (filter_pid >= 0 && row.pid != filter_pid) {
            continue;
        }

        if (count == cap) {
            int new_cap = (cap == 0) ? 64 : cap * 2;
            EventRow *tmp = realloc(rows, sizeof(EventRow) * (size_t)new_cap);
            if (tmp == NULL) {
                fprintf(stderr, "Error: out of memory reading events\n");
                free(rows);
                fclose(fp);
                return 1;
            }
            rows = tmp;
            cap = new_cap;
        }
        rows[count++] = row;
    }
    fclose(fp);

    int start = (count > last_n) ? (count - last_n) : 0;
    printf("%-19s %-14s %-7s %-7s %-20s %-5s %-4s %-12s %-7s %-9s %s\n",
           "TIMESTAMP", "EVENT", "PID", "PPID", "NAME", "STATE", "OLD", "USER", "THREADS", "RSS_KB", "LIFE(s)");
    for (int i = start; i < count; i++) {
        printf("%-19s %-14s %-7d %-7d %-20s %-5s %-4s %-12s %-7d %-9lu %ld\n",
               rows[i].timestamp, rows[i].event, rows[i].pid, rows[i].ppid,
               rows[i].name, rows[i].state, rows[i].old_state, rows[i].user,
               rows[i].threads, rows[i].rss_kb, rows[i].lifetime_sec);
    }

    free(rows);
    return 0;
}

/* Handle the "viewer alerts" subcommand with severity filtering and --last tailing. */
static int cmd_alerts(int argc, char *argv[]) {
    int last_n = 20;
    const char *filter_sev = NULL;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--last") == 0 && i + 1 < argc) {
            last_n = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--severity") == 0 && i + 1 < argc) {
            filter_sev = argv[++i];
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (last_n <= 0) {
        last_n = 20;
    }

    FILE *fp = open_csv_or_warn("logs/alerts.csv");
    if (fp == NULL) {
        return 0;
    }

    AlertRow *rows = NULL;
    int count = 0;
    int cap = 0;
    char line[1024];
    int line_num = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line_num++ == 0) {
            continue;
        }

        char *fields[3];
        if (split_csv_line(line, fields, 3) < 3) {
            continue;
        }

        AlertRow row;
        snprintf(row.timestamp, sizeof(row.timestamp), "%s", fields[0]);
        snprintf(row.severity, sizeof(row.severity), "%s", fields[1]);
        snprintf(row.message, sizeof(row.message), "%s", fields[2]);

        if (filter_sev != NULL && strcmp(row.severity, filter_sev) != 0) {
            continue;
        }

        if (count == cap) {
            int new_cap = (cap == 0) ? 64 : cap * 2;
            AlertRow *tmp = realloc(rows, sizeof(AlertRow) * (size_t)new_cap);
            if (tmp == NULL) {
                fprintf(stderr, "Error: out of memory reading alerts\n");
                free(rows);
                fclose(fp);
                return 1;
            }
            rows = tmp;
            cap = new_cap;
        }
        rows[count++] = row;
    }
    fclose(fp);

    int start = (count > last_n) ? (count - last_n) : 0;
    printf("%-19s %-10s %s\n", "TIMESTAMP", "SEVERITY", "MESSAGE");
    for (int i = start; i < count; i++) {
        printf("%-19s %-10s %s\n", rows[i].timestamp, rows[i].severity, rows[i].message);
    }

    free(rows);
    return 0;
}

/* Comparator for qsort ordering live rows by CPU % descending. */
static int cmp_live_cpu(const void *a, const void *b) {
    const LiveRow *ra = (const LiveRow *)a;
    const LiveRow *rb = (const LiveRow *)b;
    if (rb->cpu_percent > ra->cpu_percent) return 1;
    if (rb->cpu_percent < ra->cpu_percent) return -1;
    return ra->pid - rb->pid;
}

/* Comparator for qsort ordering live rows by resident memory descending. */
static int cmp_live_mem(const void *a, const void *b) {
    const LiveRow *ra = (const LiveRow *)a;
    const LiveRow *rb = (const LiveRow *)b;
    if (rb->rss_kb > ra->rss_kb) return 1;
    if (rb->rss_kb < ra->rss_kb) return -1;
    return ra->pid - rb->pid;
}

/* Comparator for qsort ordering live rows by PID ascending. */
static int cmp_live_pid(const void *a, const void *b) {
    const LiveRow *ra = (const LiveRow *)a;
    const LiveRow *rb = (const LiveRow *)b;
    return (ra->pid > rb->pid) - (ra->pid < rb->pid);
}

/* Handle the "viewer live" subcommand with sorting and --top limiting. */
static int cmd_live(int argc, char *argv[]) {
    LiveSort sort_by = SORT_CPU;
    int top_n = 15;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--sort") == 0 && i + 1 < argc) {
            const char *mode = argv[++i];
            if (strcmp(mode, "cpu") == 0) {
                sort_by = SORT_CPU;
            } else if (strcmp(mode, "mem") == 0) {
                sort_by = SORT_MEM;
            } else if (strcmp(mode, "pid") == 0) {
                sort_by = SORT_PID;
            } else {
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--top") == 0 && i + 1 < argc) {
            top_n = atoi(argv[++i]);
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (top_n <= 0) {
        top_n = 15;
    }

    FILE *fp = open_csv_or_warn("logs/live.csv");
    if (fp == NULL) {
        return 0;
    }

    LiveRow *rows = NULL;
    int count = 0;
    int cap = 0;
    char line[1024];
    int line_num = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line_num++ == 0) {
            continue;
        }

        char *fields[11];
        if (split_csv_line(line, fields, 11) < 11) {
            continue;
        }

        LiveRow row;
        row.pid = atoi(fields[0]);
        row.ppid = atoi(fields[1]);
        snprintf(row.name, sizeof(row.name), "%s", fields[2]);
        snprintf(row.user, sizeof(row.user), "%s", fields[3]);
        snprintf(row.state, sizeof(row.state), "%s", fields[4]);
        row.cpu_percent = atof(fields[5]);
        row.rss_kb = strtoul(fields[6], NULL, 10);
        row.threads = atoi(fields[7]);
        row.priority = atoi(fields[8]);
        row.nice = atoi(fields[9]);
        snprintf(row.start_time, sizeof(row.start_time), "%s", fields[10]);

        if (count == cap) {
            int new_cap = (cap == 0) ? 128 : cap * 2;
            LiveRow *tmp = realloc(rows, sizeof(LiveRow) * (size_t)new_cap);
            if (tmp == NULL) {
                fprintf(stderr, "Error: out of memory reading live.csv\n");
                free(rows);
                fclose(fp);
                return 1;
            }
            rows = tmp;
            cap = new_cap;
        }
        rows[count++] = row;
    }
    fclose(fp);

    /* Sort all parsed live processes according to the user's chosen metric. */
    if (count > 1) {
        if (sort_by == SORT_CPU) {
            qsort(rows, (size_t)count, sizeof(LiveRow), cmp_live_cpu);
        } else if (sort_by == SORT_MEM) {
            qsort(rows, (size_t)count, sizeof(LiveRow), cmp_live_mem);
        } else {
            qsort(rows, (size_t)count, sizeof(LiveRow), cmp_live_pid);
        }
    }

    int limit = (count < top_n) ? count : top_n;
    printf("%-7s %-7s %-20s %-12s %-5s %-6s %-9s %-7s %-4s %-5s %s\n",
           "PID", "PPID", "NAME", "USER", "STATE", "CPU%", "RSS_KB", "THREADS", "PRI", "NICE", "START_TIME");
    for (int i = 0; i < limit; i++) {
        printf("%-7d %-7d %-20s %-12s %-5s %-6.1f %-9lu %-7d %-4d %-5d %s\n",
               rows[i].pid, rows[i].ppid, rows[i].name, rows[i].user,
               rows[i].state, rows[i].cpu_percent, rows[i].rss_kb,
               rows[i].threads, rows[i].priority, rows[i].nice, rows[i].start_time);
    }

    free(rows);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return (argc < 2) ? 1 : 0;
    }

    if (strcmp(argv[1], "events") == 0) {
        return cmd_events(argc, argv);
    }
    if (strcmp(argv[1], "alerts") == 0) {
        return cmd_alerts(argc, argv);
    }
    if (strcmp(argv[1], "live") == 0) {
        return cmd_live(argc, argv);
    }

    print_usage(argv[0]);
    return 1;
}
