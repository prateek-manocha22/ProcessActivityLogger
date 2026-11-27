/* Include standard I/O functions for snprintf, fopen, fgets, fclose, and sscanf. */
#include <stdio.h>
/* Include standard library functions for strtol to safely convert text to numbers. */
#include <stdlib.h>
/* Include string functions like strchr, strrchr, and memcpy to parse the stat line. */
#include <string.h>
/* Include character classification functions like isdigit to check folder names. */
#include <ctype.h>
/* Include directory functions like opendir, readdir, and closedir to browse /proc. */
#include <dirent.h>
/* Include errno and limits so we can safely validate converted PID numbers. */
#include <errno.h>
#include <limits.h>

/* Include our own header so the compiler verifies our function signatures match. */
#include "snapshot.h"

/* Helper function to check if a folder name contains only digits (0-9). */
static int is_all_digits(const char *text) {
    /* Reject NULL or empty strings because they cannot be valid process IDs. */
    if (text == NULL || text[0] == '\0') {
        return 0;
    }

    /* Check each character one by one until the end of the string. */
    for (int i = 0; text[i] != '\0'; i++) {
        /* Cast to unsigned char before calling isdigit to avoid undefined behavior on signed chars. */
        if (!isdigit((unsigned char)text[i])) {
            /* Return 0 (false) immediately if any non-digit character is found. */
            return 0;
        }
    }

    /* Every character was a digit, so return 1 (true). */
    return 1;
}

int read_process(int pid, Process *out) {
    /* Stop early if the PID is invalid or the caller gave us a NULL output pointer. */
    if (pid <= 0 || out == NULL) {
        return -1;
    }

    /* Build the file path "/proc/<pid>/stat" safely without overflowing the buffer. */
    char path[64];
    int path_len = snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
        return -1;
    }

    /* Open the stat file for reading; it may return NULL if the process already exited. */
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    /* Read the single summary line from /proc/<pid>/stat into a temporary buffer. */
    char line[4096];
    if (fgets(line, sizeof(line), fp) == NULL) {
        /* Always close the file before returning so we never leak file descriptors. */
        fclose(fp);
        return -1;
    }

    /* Close the file right away since we already copied the line into memory. */
    fclose(fp);

    /* Find the first '(' which marks the start of the process name. */
    char *open_paren = strchr(line, '(');
    /* Find the LAST ')' because a process name itself is allowed to contain spaces or ')'. */
    char *close_paren = strrchr(line, ')');
    if (open_paren == NULL || close_paren == NULL || close_paren <= open_paren) {
        return -1;
    }

    /* Read the PID at the very beginning of the line to confirm the format is valid. */
    int parsed_pid = 0;
    if (sscanf(line, "%d", &parsed_pid) != 1) {
        return -1;
    }
    out->pid = parsed_pid;

    /* Calculate how many characters are between '(' and ')' for the process name. */
    size_t name_len = (size_t)(close_paren - (open_paren + 1));
    /* Cap the length so it always fits inside out->name with room for the '\0' terminator. */
    if (name_len >= sizeof(out->name)) {
        name_len = sizeof(out->name) - 1;
    }
    /* Copy the process name bytes and add the terminating null byte at the end. */
    memcpy(out->name, open_paren + 1, name_len);
    out->name[name_len] = '\0';

    /* Parse the fields after the last ')': state (field 3), ppid (field 4), skip 5..21, read field 22. */
    char state = '?';
    int ppid = 0;
    unsigned long long start_ticks = 0;
    int matched = sscanf(
        close_paren + 1,
        " %c %d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %llu",
        &state,
        &ppid,
        &start_ticks
    );
    /* Make sure all three requested fields (state, ppid, start_ticks) were read successfully. */
    if (matched != 3) {
        return -1;
    }

    /* Store the parsed values into the caller's Process struct now that everything succeeded. */
    out->state = state;
    out->ppid = ppid;
    out->start_ticks = start_ticks;

    /* Return 0 to tell the caller that reading this process succeeded. */
    return 0;
}

int take_snapshot(Process list[], int max) {
    /* Return 0 right away if the caller gave us an invalid array or non-positive limit. */
    if (list == NULL || max <= 0) {
        return 0;
    }

    /* Open the /proc virtual directory where Linux exposes one numbered folder per process. */
    DIR *proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        return 0;
    }

    /* Track how many valid processes we have saved into list so far. */
    int count = 0;
    struct dirent *entry;

    /* Read one directory entry at a time until there are no more entries in /proc. */
    while ((entry = readdir(proc_dir)) != NULL) {
        /* Stop scanning once the caller's array is full so we never write past the end. */
        if (count >= max) {
            break;
        }

        /* Skip non-process entries like "cpuinfo" or "." by keeping only all-digit names. */
        if (!is_all_digits(entry->d_name)) {
            continue;
        }

        /* Convert the folder name text into an integer PID while checking for overflow. */
        errno = 0;
        char *endptr = NULL;
        long pid_val = strtol(entry->d_name, &endptr, 10);
        if (errno != 0 || endptr == entry->d_name || *endptr != '\0' || pid_val <= 0 || pid_val > INT_MAX) {
            continue;
        }

        /* Try reading this process's stat file; skip it silently if it exited mid-scan. */
        if (read_process((int)pid_val, &list[count]) == 0) {
            count++;
        }
    }

    /* Close the /proc directory handle when finished to free OS resources. */
    closedir(proc_dir);

    /* Return the total number of processes successfully stored in list. */
    return count;
}
