#include <kernel/heap.h>
#include <kernel/log.h>
#include <lib/tar.h>
#include <libc/string.h>
#include <lib/octal.h>

// Return a list of all of the tar headers in the archive
int64_t tar_list(uint8_t *archive_start, tar_header_list_t **out) {
    tar_header_t* header = (tar_header_t *)archive_start;
    tar_header_list_t* list = NULL;
    int64_t count = 0;
    *out = NULL;

    // Iterate through the archive as long as we find valid UStar headers
    while(memcmp(header->magic, "ustar", 5) == 0) {
        tar_header_list_t* list_item;
        SAFE_ALLOC(list_item, tar_header_list_t*, "TAR: Failed to allocated memory for tar header item at: 0x%llx", (uint64_t)list_item, return -1);

        memcpy(&list_item->header, header, sizeof(tar_header_t));
        list_item->next = list;
        list = list_item;
        count++;

        // First, calculate how many 512-byte blocks the file content occupies.
        uint64_t filesize = octal_to_int(header->filesize, sizeof(header->filesize));
        uint64_t size_in_blocks = (filesize + 511) / 512;

        // The next header is located after the current header AND the content blocks.
        header = (tar_header_t *)((uint8_t *)header + (size_in_blocks + 1) * 512);
        if (header->filename[0] == '\0') {
            break;
        }
    }

    *out = list;
    return count;
}

// Lookup a file in a TAR archive, file contents are in the pointer 'out' and
// the filesize is returned by the function. If 0 filesize found, check 'out' is NULL
int64_t tar_lookup(uint8_t *archive_start, const char *filename, uint8_t **out) {
    tar_header_t *header = (tar_header_t *)archive_start;

    // Iterate through the archive as long as we find valid UStar headers
    while(memcmp(header->magic, "ustar", 5) == 0) {
        uint64_t filesize = octal_to_int(header->filesize, sizeof(header->filesize));

        // Check if the filename is the one we're looking for
        if (strcmp(header->filename, filename) == 0) {
            // File found. Set `out` to the start of the content
            *out = (uint8_t *)(header + 1);
            return filesize;
        }
        // Not a match, so skip to the next header.
        // First, calculate how many 512-byte blocks the file content occupies.
        uint64_t size_in_blocks = (filesize + 511) / 512;

        // The next header is located after the current header AND the content blocks.
        header = (tar_header_t *)((uint8_t *)header + (size_in_blocks + 1) * 512);
        if (header->filename[0] == '\0') {
            break;
        }
    }

    *out = NULL;
    return 0;
}
