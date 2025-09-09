#include <libc/unistd.h>

void yield() {
    _SYSCALL0_NO_RET(SYS_PROC_YIELD);
}

int64_t fork() {
    return _SYSCALL0(SYS_PROC_FORK);
}

void exit(int64_t status) {
    _SYSCALL1_NO_RET(SYS_PROC_EXIT, status);
}

int64_t execve(const char* pathname, char** argv, char** envp) {
    return _SYSCALL3(SYS_EXEC, pathname, argv, envp);
}

int64_t getpid() {
    return _SYSCALL0(SYS_PROC_PID);
}

int64_t write(uint64_t fd, const char* buf, size_t count) {
    return _SYSCALL3(SYS_WRITE, fd, buf, count);
}

int64_t open(const char* path, uint16_t flags) {
    return _SYSCALL2(SYS_OPEN, path, flags);
}

int64_t read(uint64_t fd, void* buf, size_t count) {
    return _SYSCALL3(SYS_READ, fd, buf, count);
}

int64_t close(uint64_t fd) {
    return _SYSCALL1(SYS_CLOSE, fd);
}

int64_t brk(void* addr) {
    return _SYSCALL1(SYS_BRK, addr);
}

// TODO: The types idtype_t, id_t, and siginfo_t should be properly defined in a header.
int64_t waitid(uint64_t idtype, uint64_t id, void* infop, int options) {
    // TODO: Need to define SYS_WAITID in unistd.h and implement the _SYSCALL4 macro.
    return _SYSCALL4(SYS_WAITID, idtype, id, infop, options);
}

// TODO: The type pid_t should be properly defined in a header.
int64_t waitpid(int64_t pid, int *wstatus, int options) {
    // TODO: These constants should be defined in a header (e.g., <sys/wait.h>)
    #define WEXITED 4

    uint64_t idtype;
    uint64_t id;

    if (pid < -1) {
        idtype = P_PGID;
        id = -pid;
    } else if (pid == -1) {
        idtype = P_ALL;
        id = 0;
    } else if (pid == 0) {
        idtype = P_PGID;
        id = 0;
    } else { // pid > 0
        idtype = P_PID;
        id = pid;
    }

    // TODO: This is a placeholder. A proper implementation needs a siginfo_t struct
    //       to get the real exit status and pid of the child.
    int temp_status[16]; // Temporary buffer to act as a placeholder for siginfo_t

    int64_t result = waitid(idtype, id, &temp_status, options | WEXITED);

    if (result < 0) {
        return -1; // Error
    }

    if (wstatus != NULL) {
        // TODO: Extract the real status from the info struct once implemented.
        *wstatus = temp_status[0];
    }

    // TODO: Return the actual pid from the info struct once implemented.
    return temp_status[1];
}

void* sbrk(int64_t increment) {
    static void* program_break = NULL;

    if (program_break == NULL) {
        // Initialize program_break by calling brk(0) to get the current break
        program_break = (void*)brk(0);
        if ((int64_t)program_break == -1) {
            return (void*)-1; // brk(0) failed
        }
    }

    void* old_program_break = program_break;
    void* new_program_break = (void*)((uint64_t)program_break + increment);

    if (brk(new_program_break) == -1) {
        return (void*)-1; // brk failed
    }

    program_break = new_program_break;
    return old_program_break;
}