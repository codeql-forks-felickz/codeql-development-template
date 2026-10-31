typedef unsigned long size_t;
void *memcpy(void *destination, const void *source, size_t count);
void *memset(void *destination, int value, size_t count);
int printf(const char *format, ...);

void bad_copy_without_terminator(void) {
    char source[150], destination[100];
    memset(source, 'A', 149);
    source[149] = '\0';
    memcpy(destination, source, 99);
    printf("%s", destination); // $ Alert
}

void good_copy_with_terminator(void) {
    char source[150], destination[100];
    memset(source, 'A', 149);
    source[149] = '\0';
    memcpy(destination, source, 99);
    destination[99] = '\0';
    printf("%s", destination);
}

void good_zero_initialized_destination(void) {
    char source[150], destination[100] = { 0 };
    memset(source, 'A', 149);
    source[149] = '\0';
    memcpy(destination, source, 99);
    printf("%s", destination);
}