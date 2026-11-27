/* Include headers for fork, sleep, and standard output. */
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    /* Fork a child process that exits immediately so it becomes a zombie. */
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /* Exit at once without being waited on by the parent. */
        _exit(0);
    }

    /* Sleep for 60 seconds without calling wait() so the zombie stays visible in /proc. */
    printf("Parent %d created zombie child %d; sleeping 60s...\n", (int)getpid(), (int)pid);
    fflush(stdout);
    sleep(60);
    return 0;
}
