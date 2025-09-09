#ifndef LIB_ELF_H
#define LIB_ELF_H

#include <stdint.h>
#include <kernel/proc.h>
#include <drivers/fs/vfs.h>

#define ELF_TYPE_NONE      0
#define ELF_TYPE_REL       1
#define ELF_TYPE_EXEC      2
#define ELF_TYPE_DYN       3
#define ELF_TYPE_CORE      4

typedef struct elf_header {
    unsigned char   ident[16];
    uint16_t        file_type;
    uint16_t        machine_arch;
    uint32_t        elf_version;
    uint64_t        entry_point_addr;
    uint64_t        prog_header_offset;
    uint64_t        section_header_offset;
    uint32_t        arch_flags;
    uint16_t        elf_header_size;
    uint16_t        program_header_size;
    uint16_t        num_program_entries;
    uint16_t        section_header_size;
    uint16_t        num_section_entries;
    uint16_t        section_name_strings_section;
} __attribute__((packed)) elf_header_t;

typedef struct elf_section_header {
    uint32_t    section_name_idx;
    uint32_t    section_type;
    uint64_t    section_flags;
    uint64_t    addr_in_img;
    uint64_t    offset_in_file;
    uint64_t    section_size;
    uint32_t	related_section_idx;
    uint32_t	section_info;
    uint64_t	byte_alignment;
    uint64_t	size_entries;
} __attribute__((packed)) elf_section_header_t;

typedef struct elf_program_header {
	uint32_t	entry_type;		/* Entry type. */
	uint32_t	access_flags;	/* Access permission flags. */
	uint64_t	file_offest;	/* File offset of contents. */
	uint64_t	virtual_addr;	/* Virtual address in memory image. */
	uint64_t	physical_addr; 	/* Physical address (not used). */
	uint64_t	file_size;	    /* Size of contents in file. */
	uint64_t	mem_used;	    /* Size of contents in memory. */
	uint64_t	byte_alignment;	/* Alignment in memory and file. */
} __attribute__((packed)) elf_program_header_t;

process_t* elf_load_process(void* file_ptr);
process_t* elf_load_process_with_args(void* file_ptr, int argc, char** argv, char** envp);
void elf_load_process_vfs(vfs_node_t* file);
void elf_load_process_vfs_args(vfs_node_t* file, int argc, char** argv, char** envp);
#endif