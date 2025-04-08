#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

int main() {
    pid_t child_pid = fork();

    if (child_pid == 0) {
        // Child process (Tracee)
        printf("Child: I am being traced!\n");
        ptrace(PTRACE_TRACEME, 0, NULL, NULL); // Allow parent to trace me
        raise(SIGSTOP); // Stop itself to let the parent attach
        printf("Child: Continuing execution!\n");
    } else {
        // Parent process (Tracer)
        int status;
        waitpid(child_pid, &status, 0); // Wait for child to stop itself

        printf("Parent: Reading child's memory...\n");
        long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)main, NULL);
        printf("Parent: Read data from child's memory: %lx\n", data);

        ptrace(PTRACE_CONT, child_pid, NULL, NULL); // Continue child execution
        waitpid(child_pid, &status, 0); // Wait for child to finish
        printf("Parent: Child finished execution.\n");
    }
    return 0;
}
