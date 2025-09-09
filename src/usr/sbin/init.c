#include <libc/unistd.h>
#include <libc/stdio.h>                                                                                                                                                                                                                          │
#include <libc/string.h>
#include <libc/stdlib.h>

#include <stdarg.h>

static uint64_t counter = 0;
static int64_t serio_fd;

// A mux_printf that writes to both the console (stdout) and the serial port
void mux_printf(const char* format, ...) {
    va_list args;

    // Print to standard output (the console)
    va_start(args, format);
    vdprintf(STDOUT_FILENO, format, args);
    va_end(args);

    // Print to the serial port
    va_start(args, format);
    vdprintf(serio_fd, format, args);
    va_end(args);
}

static void test_write() {
    mux_printf("Starting init...\n");
}


static int64_t test_fork() {
    int64_t fork_pid = fork();
    if(fork_pid == 0) {
        mux_printf("I am the child!\n");
    } else {
        mux_printf("I am the parent!\n");
    }
    return fork_pid;
}

static void test_read() {
    // Lets try to read some bytes from a file...
    uint64_t linker_fd = open("/init/user.lds", 1);
    char buf[533];
    int64_t bytes_read = read(linker_fd, buf, 532);
    buf[bytes_read] = '\0';
    mux_printf("I read the following number of bytes: %d\n", bytes_read);

    if(bytes_read == 532) {
        mux_printf("I read 532 bytes! yay!\n");
        mux_printf("Those UTF-8 bytes yield:\n%s\n", buf);

        char ascii_buf[533];
        utf8_to_ascii_safe(ascii_buf, buf, 533);
        mux_printf("Those ASCII bytes yield:\n%s\n", ascii_buf);
    }
}

static void test_brk() {
    // Testing
    mux_printf("  Lets test brk() while we're here...\n");
    int64_t status = brk((void*)0x802000);
    if(status == 0) {
        mux_printf("  We set our brk to 0x802000\n");
        mux_printf("  But wait! I wanna see what our break is...\n");
        int64_t current_brk_val = (int64_t)brk(0);
        if(current_brk_val > 0) {
            mux_printf("  Current break is: 0x%x\n", current_brk_val);
            mux_printf("  Requesting addition of 0x100000\n");
            void* sbrk_ret = sbrk(0x100000);
            if ((int64_t)sbrk_ret != -1) {
                int64_t new_brk_val = (int64_t)brk(0);
                if(new_brk_val > 0) {
                    mux_printf("  New break is: 0x%x\n", new_brk_val);
                }
            } else {
                mux_printf("  sbrk failed!\n");
            }
        }
    } else {
        mux_printf("  brk(0x802000) failed!\n");
    }
}

void test_fork_bomb() {
    #define MAX_FORKS 500
    mux_printf("--- Starting Fork Bomb Test ---\n");

    for (int i = 0; i < MAX_FORKS; i++) {
        int64_t child_pid = fork();
        if (child_pid < 0) {
            mux_printf("Fork failed! Halting test.\n");
            break;
        }

        if(child_pid == 0) {
            mux_printf("I am a child, my PID is: %d\n", getpid());
            continue;
        } else {
            mux_printf("I am a parent, waiting on child: %d\n", child_pid);
            waitpid(child_pid, NULL, 0);
            mux_printf("I am exiting as parent: %d\n", getpid());
            exit(0);
        }
    }

    // This code is only reached by the final child in the chain
    mux_printf("--- Fork Bomb Test Finished ---\n");
}

void test_concurrent_forks() {
    #define NUM_CHILDREN 5
    mux_printf("--- Starting Concurrent Fork Test ---\n");

    uint64_t children_pids[NUM_CHILDREN];

    // --- Parent Process: Creation Phase ---
    for (int i = 0; i < NUM_CHILDREN; i++) {
        int64_t child_pid = fork();

        if (child_pid < 0) {
            mux_printf("Fork failed! Halting test.\n");
            return;
        }

        if (child_pid == 0) {
            // --- Child Process Logic ---
            uint64_t child_self_pid = getpid();
            mux_printf("  -> Child process started, PID: %d\n", child_self_pid);

            for (int j = 0; j < 3; j++) {
                mux_printf("    -> Child %d is yielding.\n", child_self_pid);
                yield();
            }

            mux_printf("  -> Child process finished, PID: %d\n", child_self_pid);
            exit(child_self_pid);
        } else {
            // --- Parent Process ---
            children_pids[i] = child_pid;
        }
    }

    // --- Parent Process: Reaping Phase ---
    mux_printf("--- Parent finished creating children. Now waiting... ---\n");

    for (int i = 0; i < NUM_CHILDREN; i++) {
        uint64_t child_to_reap = children_pids[i];
        mux_printf("  -> Parent waiting for child PID: %d\n", child_to_reap);
        waitpid(child_to_reap, NULL, 0);
        mux_printf("  -> Parent reaped child PID: %d\n", child_to_reap);
    }

    mux_printf("--- Concurrent Fork Test Finished ---\n");
}

static void child_process_logic(uint64_t pid) {
    for(;;) {
        counter++;

        if(counter % 500 == 0) {
            yield();
            mux_printf("I just did a yield!\n");
            // test_brk();
        }

        if(counter > 1000) {
            mux_printf("Time for me to exit!\n");
            mux_printf("%d\n", pid);

            int64_t status = close(serio_fd);
            if(!status) {
                mux_printf("I just closed a file descriptor for serial! I shouldn\'t see this on serial!\n");
            }

            exit(pid);
        }
    }
}

static void reaping_loop() {
    mux_printf("Entering main init loop to reap orphans...\n");
    for (;;) {
        waitpid(-1, NULL, WNOHANG);
        yield();
    }
}

int main(int argc, char** argv, char** envp) {
    serio_fd = open("/dev/serial01", 1); // TODO: Define read, write, exec flags
    
    // Log the variables passed into main after opening serial
    mux_printf("argc: %d\n", argc);
    mux_printf("argv: %p\n", argv);
    if (argv != NULL) {
        for (int i = 0; i < argc; i++) {
            mux_printf("argv[%d]: %s\n", i, argv[i]);
        }
    }
    mux_printf("envp: %p\n", envp);
    if (envp != NULL) {
        for (int i = 0; envp[i] != NULL; i++) {
            mux_printf("envp[%d]: %s\n", i, envp[i]);
        }
    }
    
    test_write();
    //test_fork_bomb();
    //test_concurrent_forks();
    int64_t fork_pid = test_fork();
    // test_read();

    uint64_t pid = getpid();
    if(fork_pid == 0) {
        mux_printf("I am the child so I am going to do more work...\n");
        child_process_logic(pid);
    } else {
        waitpid(fork_pid, NULL, P_PID);
        mux_printf("Parent (init) has reaped the test child process.\n");
        mux_printf("%d\n", pid);
        exit(pid);
    }
}
