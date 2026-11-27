/* Include headers for fork, execlp, wait, and output. */
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int count = 40;
    int spawned = 0;

    /* Rapidly spawn 40 short-lived sleep children to simulate a fork burst. */
    for (int i = 0; i < count; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            break;
        }
        if (pid == 0) {
            execlp("sleep", "sleep", "6", NULL);
            _exit(1);
        }
        spawned++;
    }

    /* Wait for every spawned child to exit so no zombies are left behind. */
    for (int i = 0; i < spawned; i++) {
        wait(NULL);
    }

    printf("burst_spawner finished (%d children)\n", spawned);
    return 0;
}
