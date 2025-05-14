#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h> // For timestamps

// Array of common system call names
const char* syscall_names[] = {
    "read", "write", "open", "close", "stat", "fstat", "lstat", "poll",
    "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
    "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select",
    "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat",
    "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer",
    "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom",
    "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername",
    "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve",
    "exit", "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget",
    "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate",
    "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir",
    "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown",
    "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo",
    "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid",
    "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid",
    "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid",
    "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending",
    "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime",
    "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs",
    "getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler",
    "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min",
    "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup",
    "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex",
    "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2",
    "swapon", "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm",
    "create_module", "init_module", "delete_module", "get_kernel_syms", "query_module",
    "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security"
};

#define MAX_SYSCALLS 330

// Function to get the current timestamp
char* get_timestamp() {
    static char timestamp[20];
    time_t raw_time;
    struct tm *time_info;

    time(&raw_time);
    time_info = localtime(&raw_time);

    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", time_info);
    return timestamp;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <target_program>\n", argv[0]);
        return 1;
    }

    // Open a log file
    FILE *log_file = fopen("syscall_log.txt", "w");
    if (!log_file) {
        perror("Failed to open log file");
        return 1;
    }

    pid_t child_pid = fork();

    if (child_pid < 0) {
        perror("fork failed");
        fclose(log_file);
        return 1;
    }

    if (child_pid == 0) {
        // Child process: Allow tracing and execute the target program
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(argv[1], argv[1], (char *)NULL);
        perror("execl failed"); // If execl fails
        fclose(log_file);
        return 1;
    } else {
        // Parent process: Trace the child
        struct user_regs_struct regs;
        int status;

        waitpid(child_pid, &status, 0); // Wait for the child to stop
        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);

        while (1) {
            waitpid(child_pid, &status, 0);
            if (WIFEXITED(status)) break; // Exit loop if the child exits

            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

            long syscall_num = regs.orig_rax;
            char *timestamp = get_timestamp();

            if (syscall_num >= 0 && syscall_num < MAX_SYSCALLS) {
                printf("[%s] Traced system call: %s\n", timestamp, syscall_names[syscall_num]);
                fprintf(log_file, "[%s] Traced system call: %s\n", timestamp, syscall_names[syscall_num]);
            } else {
                printf("[%s] Traced unknown system call: %ld\n", timestamp, syscall_num);
                fprintf(log_file, "[%s] Traced unknown system call: %ld\n", timestamp, syscall_num);
            }

            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL); // Continue tracing
        }

        ptrace(PTRACE_DETACH, child_pid, NULL, NULL); // Detach from the child
        fclose(log_file); // Close the log file
    }

    return 0;
}
