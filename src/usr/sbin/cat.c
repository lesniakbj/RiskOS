#include <libc/stdio.h>
#include <libc/unistd.h>

typedef struct file_stats {
    uint64_t device_id;
    uint64_t inode;
    uint32_t mode;
    uint32_t num_links;
    uint64_t size_bytes;
    uint64_t num_blocks;
    uint64_t access_time;
    uint64_t modified_time;
    uint64_t create_time;
} file_stats_t;

uint64_t serio_fd;

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

int main(int argc, char** argv, char** envp) {
    serio_fd = open("/dev/serial01", 1);
    mux_printf("We made it to cat!\n");
    for(int i = 0; i < argc; i++) {
        mux_printf("%s\n", argv[i]);
    }
    for (int i = 0; envp[i] != NULL; i++) {
        mux_printf("%s\n", envp[i]);
    }

    // Test file stat
    file_stats_t st;
    int64_t res = stat("/init/sbin/cat", &st);
    if(res == 0) {
        mux_printf("File stats successfully retrieved:\n");
        mux_printf("  Device ID: %llu\n", st.device_id);
        mux_printf("  Inode: %llu\n", st.inode);
        mux_printf("  Mode: %u\n", st.mode);
        mux_printf("  Num Links: %u\n", st.num_links);
        mux_printf("  Size (bytes): %llu\n", st.size_bytes);
        mux_printf("  Num Blocks: %llu\n", st.num_blocks);
        mux_printf("  Access Time: %llu\n", st.access_time);
        mux_printf("  Modified Time: %llu\n", st.modified_time);
        mux_printf("  Create Time: %llu\n", st.create_time);
    } else {
        mux_printf("Error getting file stats\n");
    }

    exit(0);
}