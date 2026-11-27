/* Include standard headers for I/O, conversion, strings, directories, and limits. */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "snapshot.h"

/* Check whether a directory entry name contains only ASCII digits. */
static int is_all_digits(const char *text) {
    if (text == NULL || text[0] == '\0') {
        return 0;
    }

    for (int i = 0; text[i] != '\0'; i++) {
        if (!isdigit((unsigned char)text[i])) {
            return 0;
        }
    }

    return 1;
}

/* Read and parse /proc/<pid>/stat for identity, state, CPU, and scheduling fields. */
static int read_stat_file(int pid, Process *out) {
    char path[64];
    int path_len = snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
        return -1;
    }

    /* Open the stat file; return -1 if the process exited before we could read it. */
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    char line[4096];
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    /* Locate the first '(' and last ')' because process names may contain spaces or ')'. */
    char *open_paren = strchr(line, '(');
    char *close_paren = strrchr(line, ')');
    if (open_paren == NULL || close_paren == NULL || close_paren <= open_paren) {
        return -1;
    }

    /* Parse the PID at the start of the line to confirm the file format. */
    int parsed_pid = 0;
    if (sscanf(line, "%d", &parsed_pid) != 1) {
        return -1;
    }
    out->pid = parsed_pid;

    /* Copy the process name safely inside the fixed-size name buffer. */
    size_t name_len = (size_t)(close_paren - (open_paren + 1));
    if (name_len >= sizeof(out->name)) {
        name_len = sizeof(out->name) - 1;
    }
    memcpy(out->name, open_paren + 1, name_len);
    out->name[name_len] = '\0';

    /* Parse fields 3, 4, 14, 15, 18, 19, 20, and 22 after the last ')'. */
    char state = '?';
    int ppid = 0;
    unsigned long long utime = 0;
    unsigned long long stime = 0;
    int priority = 0;
    int nice_val = 0;
    int threads = 0;
    unsigned long long start_ticks = 0;

    int matched = sscanf(
        close_paren + 1,
        " %c %d %*d %*d %*d %*d %*d %*d %*d %*d %*d %llu %llu %*d %*d %d %d %d %*d %llu",
        &state,
        &ppid,
        &utime,
        &stime,
        &priority,
        &nice_val,
        &threads,
        &start_ticks
    );
    if (matched != 8) {
        return -1;
    }

    out->state = state;
    out->ppid = ppid;
    out->cpu_ticks = utime + stime;
    out->priority = priority;
    out->nice = nice_val;
    out->threads = threads;
    out->start_ticks = start_ticks;

    return 0;
}

/* Read /proc/<pid>/statm to calculate resident memory usage in kilobytes. */
static int read_statm_file(int pid, Process *out) {
    char path[64];
    int path_len = snprintf(path, sizeof(path), "/proc/%d/statm", pid);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
        return -1;
    }

    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    char line[256];
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    /* Extract the second number (resident pages) and convert pages to kilobytes. */
    unsigned long resident_pages = 0;
    if (sscanf(line, "%*d %lu", &resident_pages) != 1) {
        return -1;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return -1;
    }

    out->rss_kb = (unsigned long)(((unsigned long long)resident_pages * (unsigned long long)page_size) / 1024ULL);
    return 0;
}

/* Look up the owning username from the /proc/<pid> directory UID. */
static int read_owner(int pid, Process *out) {
    char dir_path[64];
    int path_len = snprintf(dir_path, sizeof(dir_path), "/proc/%d", pid);
    if (path_len < 0 || (size_t)path_len >= sizeof(dir_path)) {
        return -1;
    }

    struct stat st;
    if (stat(dir_path, &st) != 0) {
        return -1;
    }

    /* Resolve UID to username, falling back to numeric UID text if lookup fails. */
    struct passwd *pw = getpwuid(st.st_uid);
    if (pw != NULL && pw->pw_name != NULL) {
        snprintf(out->user, sizeof(out->user), "%s", pw->pw_name);
    } else {
        snprintf(out->user, sizeof(out->user), "%lu", (unsigned long)st.st_uid);
    }

    return 0;
}

int read_process(int pid, Process *out) {
    if (pid <= 0 || out == NULL) {
        return -1;
    }

    /* Zero-initialize the struct before filling it so no stale data remains on partial failure. */
    Process temp;
    memset(&temp, 0, sizeof(temp));

    /* Collect stat, statm, and owner info; fail cleanly if the process disappears mid-read. */
    if (read_stat_file(pid, &temp) != 0) {
        return -1;
    }
    if (read_statm_file(pid, &temp) != 0) {
        return -1;
    }
    if (read_owner(pid, &temp) != 0) {
        return -1;
    }

    *out = temp;
    return 0;
}

int take_snapshot(Process list[], int max) {
    if (list == NULL || max <= 0) {
        return 0;
    }

    /* Open /proc so we can iterate over every numeric PID directory. */
    DIR *proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        return 0;
    }

    int count = 0;
    struct dirent *entry;

    while ((entry = readdir(proc_dir)) != NULL) {
        if (count >= max) {
            break;
        }
        if (!is_all_digits(entry->d_name)) {
            continue;
        }

        /* Convert directory name to an integer PID while guarding against overflow. */
        errno = 0;
        char *endptr = NULL;
        long pid_val = strtol(entry->d_name, &endptr, 10);
        if (errno != 0 || endptr == entry->d_name || *endptr != '\0' || pid_val <= 0 || pid_val > INT_MAX) {
            continue;
        }

        if (read_process((int)pid_val, &list[count]) == 0) {
            count++;
        }
    }

    closedir(proc_dir);
    return count;
}
