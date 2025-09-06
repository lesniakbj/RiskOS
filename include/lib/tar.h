#ifndef LIB_TAR_H
#define LIB_TAR_H

#include <stdint.h>

#define TAR_NORMAL_FILE '0'
#define TAR_HARD_LINK   '1'
#define TAR_SYM_LINK    '2'
#define TAR_CHAR_DEV    '3'
#define TAR_BLOCK_DEV   '4'
#define TAR_DIRECTORY   '5'
#define TAR_NAMED_PIPE  '6'

typedef struct tar_header {
    char filename[100];
    char mode[8];
    char owner_id[8];
    char group_id[8];
    char filesize[12];
    char last_modified[12];
    char checksum[8];
    char type;
    char linked_name[100];
    char magic[6];
    char ver[2];
    char owner_name[32];
    char group_name[32];
    char dev_major[8];
    char dev_minor[8];
    char filename_prefix[155];
    char padding[12];
} __attribute__((packed)) tar_header_t;

typedef struct tar_header_list {
    tar_header_t header;
    struct tar_header_list* next;
} tar_header_list_t;

int64_t tar_list(uint8_t *archive_start, tar_header_list_t **out);
int64_t tar_lookup(uint8_t *archive_start, const char *filename, uint8_t **out);

#endif