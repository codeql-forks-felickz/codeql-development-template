void printIntLine(int value);

void bad_void_pointer_type_confusion(void) {
    void *data = 0;
    {
        char charBuffer = 'a';
        data = &charBuffer;
    }
    printIntLine(*((int *)data)); // $ Alert
}

void good_matching_pointer_type(void) {
    void *data = 0;
    {
        int intBuffer = 8;
        data = &intBuffer;
    }
    printIntLine(*((int *)data));
}