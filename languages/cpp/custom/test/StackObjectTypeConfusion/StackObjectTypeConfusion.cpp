void printIntLine(int value);

void bad_void_pointer_type_confusion(void) {
    char charBuffer = 'a';
    void *data = 0;
    data = &charBuffer;
    printIntLine(*((int *)data)); // $ Alert
}

void good_matching_pointer_type(void) {
    int intBuffer = 8;
    void *data = 0;
    data = &intBuffer;
    printIntLine(*((int *)data));
}