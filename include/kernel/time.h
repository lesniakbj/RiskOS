#ifndef KERNEL_TIME_H
#define KERNEL_TIME_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <kernel/limine.h>

void system_time_init(struct limine_date_at_boot_response* time_resp);
void timestamp_to_string(uint64_t timestamp, char* buffer);

uint64_t system_get_ticks();

#endif