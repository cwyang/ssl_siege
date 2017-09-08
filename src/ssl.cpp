#include <cassert>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <pthread.h>

static pthread_mutex_t *lock_cs;
static void thread_locking_callback(int mode, int n, const char *file, int line)
{
    if ((mode & CRYPTO_LOCK) != 0) {
        pthread_mutex_lock(lock_cs + n);
    } else if ((mode & CRYPTO_UNLOCK) != 0) {
        pthread_mutex_unlock(lock_cs + n);
    } else {
        assert(!"unexpected mode");
    }
}
void thread_setup(void)
{
    int i;

    lock_cs = (pthread_mutex_t *) 
        OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&lock_cs[i], NULL);
    }

    CRYPTO_set_locking_callback((void (*)(int, int, const char *, int))
                                thread_locking_callback);
}
void openssl_startup(void)
{
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    SSL_load_error_strings();
}
