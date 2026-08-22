#include <stddef.h>
#include <string.h>

static int file_open;
static unsigned file_offset;
static int exit_status = -1;
static char console[16];
static unsigned console_len;
static const char hello[] = "hello";

int fk_open(const char *path) {
    if (path == NULL || strcmp(path, "/hello") != 0 || file_open) return -1;
    file_open = 1;
    file_offset = 0;
    return 3;
}

int fk_read(int fd, char *buffer, unsigned length) {
    if (fd != 3 || !file_open || buffer == NULL) return -1;
    unsigned remaining = 5 - file_offset;
    unsigned count = length < remaining ? length : remaining;
    memcpy(buffer, hello + file_offset, count);
    file_offset += count;
    return (int)count;
}

int fk_write(int fd, const char *buffer, unsigned length) {
    if (fd != 1 || buffer == NULL || length > sizeof(console)) return -1;
    memcpy(console, buffer, length);
    console_len = length;
    return (int)length;
}

int fk_close(int fd) {
    if (fd != 3 || !file_open) return -1;
    file_open = 0;
    return 0;
}

void fk_exit(int status) { exit_status = status; }

int fk_observed_exit(void) { return exit_status; }
unsigned fk_console_length(void) { return console_len; }
