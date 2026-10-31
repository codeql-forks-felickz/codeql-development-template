typedef unsigned long size_t;
void *malloc(size_t size);
void free(void *ptr);

struct Lock {
    int mutex;
};

int pthread_mutex_init(int *mutex, void *attributes);
typedef struct Lock *LockHandle;

int bad_lock_create(LockHandle *lock) {
    LockHandle my_lock = (LockHandle)malloc(sizeof(*my_lock));
    if (pthread_mutex_init(&my_lock->mutex, 0) != 0) {
        free(lock); // $ Alert
        return 0;
    }
    *lock = my_lock;
    return 1;
}

void good_free_owned_allocation(void) {
    LockHandle lock = (LockHandle)malloc(sizeof(*lock));
    free(lock);
}

void good_free_output_value(LockHandle *lock) {
    free(*lock);
}