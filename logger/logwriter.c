/* Include headers for file I/O, errno, mkdir, time formatting, and project types. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "logwriter.h"
#include "sysinfo.h"

/* Ensure the logs directory exists before opening any CSV output file. */
static int ensure_logs_dir(void) {
    if (mkdir("logs", 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

/* Copy src into dst while replacing CSV-breaking or control characters with '_'. */
static void sanitize_csv(const char *src, char *dst, size_t dst_size) {
    if (dst == NULL || dst_size == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    size_t i = 0;
    for (; src[i] != '\0' && i + 1 < dst_size; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == ',' || c == '"' || c == '\\' || c < 32 || c == 127) {
            dst[i] = '_';
        } else {
            dst[i] = (char)c;
        }
    }
    dst[i] = '\0';
}

/* Format a Unix timestamp as "YYYY-MM-DD HH:MM:SS" in local time. */
static void format_local_time(time_t t, char *buf, size_t size) {
    if (buf == NULL || size == 0) {
        return;
    }

    struct tm tm_info;
    if (localtime_r(&t, &tm_info) == NULL) {
        snprintf(buf, size, "1970-01-01 00:00:00");
        return;
    }

    if (strftime(buf, size, "%Y-%m-%d %H:%M:%S", &tm_info) == 0) {
        snprintf(buf, size, "1970-01-01 00:00:00");
    }
}

/* Check whether a CSV file needs its header written (missing or zero bytes). */
static int needs_csv_header(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return 1;
    }
    return st.st_size == 0;
}

/* Map an EventType enum value to its CSV label string. */
static const char *event_type_name(EventType type) {
    switch (type) {
        case EV_STARTED:
            return "STARTED";
        case EV_TERMINATED:
            return "TERMINATED";
        case EV_STATE_CHANGED:
            return "STATE_CHANGED";
        default:
            return "UNKNOWN";
    }
}

void log_event(const Event *e, time_t now) {
    if (e == NULL || ensure_logs_dir() != 0) {
        return;
    }

    const char *path = "logs/events.csv";
    int write_header = needs_csv_header(path);

    /* Open events.csv in append mode so existing history is preserved. */
    FILE *fp = fopen(path, "a");
    if (fp == NULL) {
        return;
    }

    if (write_header) {
        fprintf(fp, "timestamp,event,pid,ppid,name,state,old_state,user,threads,rss_kb,lifetime_sec\n");
    }

    char ts[32];
    char safe_name[64];
    char safe_user[32];
    format_local_time(now, ts, sizeof(ts));
    sanitize_csv(e->proc.name, safe_name, sizeof(safe_name));
    sanitize_csv(e->proc.user, safe_user, sizeof(safe_user));

    /* Only STATE_CHANGED has a meaningful previous state; others record '-'. */
    char old_state = (e->type == EV_STATE_CHANGED) ? e->old_state : '-';
    char cur_state = (e->proc.state != '\0') ? e->proc.state : '?';

    /* Compute total lifetime in seconds only when a process has terminated. */
    long lifetime_sec = 0;
    if (e->type == EV_TERMINATED) {
        time_t start_epoch = ticks_to_epoch(e->proc.start_ticks);
        if (now > start_epoch) {
            lifetime_sec = (long)(now - start_epoch);
        }
    }

    fprintf(
        fp,
        "%s,%s,%d,%d,%s,%c,%c,%s,%d,%lu,%ld\n",
        ts,
        event_type_name(e->type),
        e->proc.pid,
        e->proc.ppid,
        safe_name,
        cur_state,
        old_state,
        safe_user,
        e->proc.threads,
        e->proc.rss_kb,
        lifetime_sec
    );

    fclose(fp);
}

void write_live(const Process *list, const double *cpu, int n) {
    if (n < 0 || (n > 0 && (list == NULL || cpu == NULL)) || ensure_logs_dir() != 0) {
        return;
    }

    const char *tmp_path = "logs/live.csv.tmp";
    const char *live_path = "logs/live.csv";

    /* Write the full snapshot to a temporary file first to avoid partial reads. */
    FILE *fp = fopen(tmp_path, "w");
    if (fp == NULL) {
        return;
    }

    fprintf(fp, "pid,ppid,name,user,state,cpu_percent,rss_kb,threads,priority,nice,start_time\n");

    for (int i = 0; i < n; i++) {
        char safe_name[64];
        char safe_user[32];
        char start_ts[32];

        sanitize_csv(list[i].name, safe_name, sizeof(safe_name));
        sanitize_csv(list[i].user, safe_user, sizeof(safe_user));
        format_local_time(ticks_to_epoch(list[i].start_ticks), start_ts, sizeof(start_ts));

        char cur_state = (list[i].state != '\0') ? list[i].state : '?';

        fprintf(
            fp,
            "%d,%d,%s,%s,%c,%.1f,%lu,%d,%d,%d,%s\n",
            list[i].pid,
            list[i].ppid,
            safe_name,
            safe_user,
            cur_state,
            cpu[i],
            list[i].rss_kb,
            list[i].threads,
            list[i].priority,
            list[i].nice,
            start_ts
        );
    }

    /* Close and atomically rename the temporary file onto logs/live.csv. */
    if (fclose(fp) == 0) {
        rename(tmp_path, live_path);
    }
}

void log_alert(const char *severity, const char *message) {
    if (severity == NULL || message == NULL || ensure_logs_dir() != 0) {
        return;
    }

    const char *path = "logs/alerts.csv";
    int write_header = needs_csv_header(path);

    FILE *fp = fopen(path, "a");
    if (fp == NULL) {
        return;
    }

    if (write_header) {
        fprintf(fp, "timestamp,severity,message\n");
    }

    char ts[32];
    char safe_sev[32];
    char safe_msg[512];
    format_local_time(time(NULL), ts, sizeof(ts));
    sanitize_csv(severity, safe_sev, sizeof(safe_sev));
    sanitize_csv(message, safe_msg, sizeof(safe_msg));

    fprintf(fp, "%s,%s,%s\n", ts, safe_sev, safe_msg);
    fclose(fp);
}
