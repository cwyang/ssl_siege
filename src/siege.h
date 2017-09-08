/*
 * SSL siege with renegotiation attack
 * 8 September 2017
 * Chul-Woong Yang (cwyang)
 *
 */
extern void thread_setup(void);
extern void openssl_startup(void);

static inline unsigned long timediff_us(struct timeval *tm1, struct timeval *tm2) 
{
    return ((tm2->tv_sec - tm1->tv_sec) * 1000000) + (tm2->tv_usec - tm1->tv_usec);
}

static inline unsigned long timediff_ms(struct timeval *tm1, struct timeval *tm2) 
{
    return timediff_us(tm1, tm2) / 1000;
}
