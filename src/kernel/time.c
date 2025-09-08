#include <kernel/time.h>
#include <kernel/log.h>

// Seconds counter, updated by the RTC interrupt
volatile uint64_t system_ticks = 0;
volatile uint64_t g_unix_seconds = 0;
static bool system_time_initialized = false;

uint64_t system_get_ticks() {
    return system_ticks;
}

// Reverses a string 'str' of length 'len'
static void k_str_reverse(char *str, int len) {
    int i = 0, j = len - 1;
    char temp;
    while (i < j) {
        temp = str[i];
        str[i] = str[j];
        str[j] = temp;
        i++;
        j--;
    }
}

// Converts a uint64_t to a string in the given buffer.
// Returns the number of characters written (excluding null terminator).
static int k_u64_to_str(uint64_t n, char* buf) {
    int i = 0;
    if (n == 0) {
        buf[i++] = '0';
        buf[i] = '\0';
        return 1;
    }

    while (n > 0) {
        buf[i++] = (n % 10) + '0';
        n /= 10;
    }

    k_str_reverse(buf, i);
    buf[i] = '\0';
    return i;
}

void system_time_init(struct limine_date_at_boot_response* time_resp) {
    if (time_resp != NULL) {
        LOG_INFO("RTC Unix Timestamp: %llu", time_resp->timestamp);

        char rtc_buf[20];
        timestamp_to_string(time_resp->timestamp, rtc_buf);
        LOG_INFO("Formatted RTC: %s", rtc_buf);
    } else {
        LOG_WARN("RTC boot date and time request not honored");
    }

    g_unix_seconds = time_resp->timestamp;
    system_time_initialized = true;
    LOG_INFO("System timer initialized...");
}

void timestamp_to_string(uint64_t timestamp, char* buffer) {
    const int days_in_month[] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    #define is_leap(y) ((y) % 4 == 0 && ((y) % 100 != 0 || (y) % 400 == 0))

    uint64_t seconds_in_day = 24 * 3600;
    uint64_t days_since_epoch = timestamp / seconds_in_day;
    uint64_t seconds_today = timestamp % seconds_in_day;

    int year = 1970;
    while (days_since_epoch >= (is_leap(year) ? 366 : 365)) {
        days_since_epoch -= (is_leap(year) ? 366 : 365);
        year++;
    }

    int month = 1;
    while (days_since_epoch >= ((uint64_t)days_in_month[month] + (month == 2 && is_leap(year)))) {
        days_since_epoch -= (days_in_month[month] + (month == 2 && is_leap(year)));
        month++;
    }

    int day = days_since_epoch + 1;
    int hour = seconds_today / 3600;
    int minute = (seconds_today % 3600) / 60;
    int second = seconds_today % 60;

    char* p = buffer;
    int len;

    // Year (YYYY)
    if (year < 1000) *p++ = '0';
    if (year < 100) *p++ = '0';
    if (year < 10) *p++ = '0';
    len = k_u64_to_str(year, p);
    p += len;
    *p++ = '-';

    // Month (MM)
    if (month < 10) *p++ = '0';
    len = k_u64_to_str(month, p);
    p += len;
    *p++ = '-';

    // Day (DD)
    if (day < 10) *p++ = '0';
    len = k_u64_to_str(day, p);
    p += len;
    *p++ = ' ';

    // Hour (HH)
    if (hour < 10) *p++ = '0';
    len = k_u64_to_str(hour, p);
    p += len;
    *p++ = ':';

    // Minute (MM)
    if (minute < 10) *p++ = '0';
    len = k_u64_to_str(minute, p);
    p += len;
    *p++ = ':';

    // Second (SS)
    if (second < 10) *p++ = '0';
    len = k_u64_to_str(second, p);
    p += len;

    *p = '\0';
}