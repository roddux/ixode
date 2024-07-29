# Overview
N_GSM is a tty line discipline. We can autoload this in Ubuntu, because the `dev.tty.ldisc_autoload` sysctl is enabled, the n_gsm module isn't blacklisted -- it should be! -- and in kernels prior to 6.6 any user can open the n_gsm discipline without privileges.


# Technical details
Okay, so a `gsm` object has a bunch of `dlci` objects associated with it. We allocate a `struct gsm_mux` by associating a line discipline with a TTY object, through the `TIOCSETD` ioctl. This ends up calling through to `gsmld_open`, through the `open` function pointer on the `tty_ldisc_packet` operations:
```c
static struct tty_ldisc_ops tty_ldisc_packet = {
    // ...
    .name            = "n_gsm",
    .open            = gsmld_open,  // <-- this bad boi
    .close           = gsmld_close,
    // ...
    .ioctl           = gsmld_ioctl,
    // ...
};
```

This allocates us a `struct gsm_mux`:
```c
static int gsmld_open(struct tty_struct *tty) {
    // ...
    
    gsm = gsm_alloc_mux();
    if (gsm == NULL)
        return -ENOMEM;

    // ...
}
```

Now, when we call line discipline-related IOCTLs on our tty file descriptor, we route through to `gsmld_ioctl`. One of these ioctl calls is `GSMIOC_SETCONF_DLCI`:
```c
static int gsmld_ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg) {
    // ...

    switch (cmd) {
    // ...
    case GSMIOC_SETCONF_DLCI:
        // blah blah, copy argument data
        if (copy_from_user(&dc, (void __user *)arg, sizeof(dc)))
            return -EFAULT;

        // bounds check
        if (dc.channel == 0 || dc.channel >= NUM_DLCI)
            return -EINVAL;

        // note: to this point, no locks have been taken

        // check if the dlci at this index is initialized already
        addr = array_index_nospec(dc.channel, NUM_DLCI);        
        dlci = gsm->dlci[addr];

        // if not, allocate it using gsm_dlci_alloc
        if (!dlci) {
            dlci = gsm_dlci_alloc(gsm, addr);
            if (!dlci)
                return -ENOMEM;
        }

        // configure the new dlci, based on given config
        return gsm_dlci_config(dlci, &dc, 0);
    // ...
    }
}
```

In the definition of `gsm_dlci_alloc`..:
```c
static struct gsm_dlci *gsm_dlci_alloc(struct gsm_mux *gsm, int addr) {
    // allocate the new dlci object
    struct gsm_dlci *dlci = kzalloc(sizeof(struct gsm_dlci), GFP_ATOMIC);
    if (dlci == NULL)
        return NULL;

    // dlci setup ...

    timer_setup(&dlci->t1, gsm_dlci_t1, 0); // dlci->t1 work queue setup with gsm_dlci_t1 function

    // more dlci setup ...

    // register this new object into the parent's gsm.dlci[] array at index addr
    gsm->dlci[addr] = dlci;
    return dlci;
}
```


## The bug
Did you catch it? :)

If we race two calls to `GSMIOC_SETCONF_DLCI`, both may see `gsm->dlci[addr]` as uninitialized, and both will attempt to setup a new dlci and register it. Both will succeed, but this means the parent gsm object will only have a reference to _one_ of the objects, because the other will be overwritten.

So! Using this, when we teardown the gsm object, it will try and destroy all child dlci objects. This is called whenever we either change the line discipline for our tty file descriptor, or if we close it outright. We get here through the `close` function pointer in the above `tty_ldisc_ops` struct:
```c
static void gsmld_close(struct tty_struct *tty) {
    // ...
    gsm_cleanup_mux(gsm, false);
    // ...
}
```

In `gsm_cleanup_mux`:
```c
    for (i = NUM_DLCI - 1; i >= 0; i--)
        if (gsm->dlci[i])
            gsm_dlci_release(gsm->dlci[i]); // <-- this will free the dlci object
``` 

One other thing to mention is the **use**. When we configure a dlci object (like above), we can pass arguments such that a timer is armed in `gsm_dlci_config`:
```c
static int gsm_dlci_config(struct gsm_dlci *dlci, struct gsm_dlci_config *dc, int open) {
    // ...
    if (need_open) {
        if (gsm->initiator)
            gsm_dlci_begin_open(dlci);
        else
            gsm_dlci_set_opening(dlci);
    }
    // ...
}
```

`gsm_dlci_begin_open` allows us to arm the timer to trigger at any point we choose, because control `gsm->t1`:
```c
static void gsm_dlci_begin_open(struct gsm_dlci *dlci) {
    // ...

    switch (dlci->state) {
    case DLCI_CLOSED:
    case DLCI_WAITING_CONFIG:
    case DLCI_CLOSING:
        // ...
        mod_timer(&dlci->t1, jiffies + gsm->t1 * HZ / 100); // <-- arm the timer for gsm_dlci_t1
        break;
    // ...
    }
}
```

After however much time has passed, the still-active dlci (the one that missed being deleted) will trigger `gsm_dlci_t1`:
```c
static void gsm_dlci_t1(struct timer_list *t) {
    struct gsm_dlci *dlci = from_timer(dlci, t, t1);
    struct gsm_mux *gsm = dlci->gsm;

    // in our exploit flow, at this point, gsm is free'd ! :)

    switch (dlci->state) {
    case DLCI_CONFIGURE:
        if (dlci->retries && gsm_dlci_negotiate(dlci) == 0) {
            dlci->retries--;
            mod_timer(&dlci->t1, jiffies + gsm->t1 * HZ / 100);
        } else {
            gsm_dlci_begin_close(dlci); /* prevent half open link */
        }
        break;
    case DLCI_OPENING:
        if (dlci->retries) {
            dlci->retries--;
            gsm_command(dlci->gsm, dlci->addr, SABM|PF);
            mod_timer(&dlci->t1, jiffies + gsm->t1 * HZ / 100);
        } else if (!dlci->addr && gsm->control == (DM | PF)) {
            if (debug & DBG_ERRORS)
                pr_info("DLCI %d opening in ADM mode.\n",
                    dlci->addr);
            dlci->mode = DLCI_MODE_ADM;
            gsm_dlci_open(dlci);
        } else {
            gsm_dlci_begin_close(dlci); /* prevent half open link */
        }

        break;
    case DLCI_CLOSING:
        if (dlci->retries) {
            dlci->retries--;
            gsm_command(dlci->gsm, dlci->addr, DISC|PF);
            mod_timer(&dlci->t1, jiffies + gsm->t1 * HZ / 100);
        } else
            gsm_dlci_close(dlci);
        break;
    default:
        pr_debug("%s: unhandled state: %d\n", __func__, dlci->state);
        break;
    }
}
```


## Exploit flow
We race two threads to call the ioctl, setup two objects, delete the gsm, then wait for the timer to figre -- this is implemented in `ixode.c`.

The above process gives us the following KASAN use-after-free splat:
```
[   56.886978] ==================================================================
[   56.889663] BUG: KASAN: slab-use-after-free in gsm_dlci_begin_close+0x45/0x100 [n_gsm]
[   56.889858] Read of size 4 at addr ffff8881037eab94 by task swapper/1/0
[   56.889858] 
[   56.889858] CPU: 1 PID: 0 Comm: swapper/1 Not tainted 6.5.13ASAN+ #13
[   56.889858] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
[   56.889858] Call Trace:
[   56.889858]  <IRQ>
[   56.889858]  dump_stack_lvl+0x48/0x70
[   56.889858]  print_report+0xcf/0x630
[   56.889858]  ? gsm_dlci_begin_close+0x45/0x100 [n_gsm]
[   56.889858]  ? kasan_complete_mode_report_info+0x8a/0x220
[   56.889858]  ? gsm_dlci_begin_close+0x45/0x100 [n_gsm]
[   56.889858]  kasan_report+0xb9/0x100
[   56.889858]  ? gsm_dlci_begin_close+0x45/0x100 [n_gsm]
[   56.889858]  __asan_load4+0x8d/0xd0
[   56.889858]  gsm_dlci_begin_close+0x45/0x100 [n_gsm]
[   56.889858]  gsm_dlci_t1+0x18a/0x2a0 [n_gsm]
[   56.889858]  ? __pfx_gsm_dlci_t1+0x10/0x10 [n_gsm]
[   56.889858]  ? _find_next_bit+0x42/0xf0
[   56.889858]  ? __pfx_gsm_dlci_t1+0x10/0x10 [n_gsm]
[   56.889858]  ? __pfx_gsm_dlci_t1+0x10/0x10 [n_gsm]
[   56.889858]  call_timer_fn+0x2d/0x1b0
[   56.889858]  ? __pfx_gsm_dlci_t1+0x10/0x10 [n_gsm]
[   56.889858]  __run_timers.part.0+0x451/0x530
[   56.889858]  ? __pfx___run_timers.part.0+0x10/0x10
[   56.889858]  ? ktime_get+0x54/0xd0
[   56.889858]  ? lapic_next_event+0x3a/0x50
[   56.889858]  ? clockevents_program_event+0x11c/0x1c0
[   56.889858]  run_timer_softirq+0x47/0x90
[   56.889858]  __do_softirq+0xf9/0x40c
[   56.889858]  __irq_exit_rcu+0x82/0xc0
[   56.889858]  irq_exit_rcu+0xe/0x20
[   56.889858]  sysvec_apic_timer_interrupt+0x93/0xa0
[   56.889858]  </IRQ>
[   56.889858]  <TASK>
[   56.889858]  asm_sysvec_apic_timer_interrupt+0x1b/0x20
[   56.889858] RIP: 0010:pv_native_safe_halt+0xb/0x10
[   56.889858] Code: 0b 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 90 90 90 90 90 90 90 90 90 90 90 90 95
[   56.889858] RSP: 0018:ffffc9000013fdc0 EFLAGS: 00000246
[   56.889858] RAX: 0001ad4000000004 RBX: ffff8881003e1940 RCX: 0000000000000000
[   56.889858] RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
[   56.889858] RBP: ffffc9000013fdc8 R08: 0000000000000000 R09: 0000000000000000
[   56.889858] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000001
[   56.889858] R13: ffffffff84b942e0 R14: 0000000000000000 R15: 0000000000000000
[   56.889858]  ? default_idle+0x9/0x30
[   56.889858]  amd_e400_idle+0x48/0x60
[   56.889858]  arch_cpu_idle+0x9/0x10
[   56.889858]  default_idle_call+0x34/0x60
[   56.889858]  do_idle+0x2e9/0x340
[   56.889858]  ? __pfx_do_idle+0x10/0x10
[   56.889858]  ? wake_up_process+0x15/0x30
[   56.889858]  ? complete+0xad/0xd0
[   56.889858]  cpu_startup_entry+0x37/0x40
[   56.889858]  start_secondary+0x1b5/0x1f0
[   56.889858]  ? __pfx_start_secondary+0x10/0x10
[   56.889858]  ? soft_restart_cpu+0x15/0x15
[   56.889858]  secondary_startup_64_no_verify+0x17e/0x18b
[   56.889858]  </TASK>
[   56.889858] 
[   56.889858] Allocated by task 70:
[   56.889858]  kasan_save_stack+0x26/0x60
[   56.889858]  kasan_set_track+0x25/0x40
[   56.889858]  kasan_save_alloc_info+0x1e/0x40
[   56.889858]  __kasan_kmalloc+0xc1/0xd0
[   56.889858]  kmalloc_trace+0x4a/0xc0
[   56.889858]  gsmld_open+0x5e/0x5f0 [n_gsm]
[   56.889858]  tty_ldisc_open+0x5c/0xb0
[   56.889858]  tty_set_ldisc+0x1bb/0x320
[   56.889858]  tty_ioctl+0x46b/0xce0
[   56.889858]  __x64_sys_ioctl+0xd2/0x120
[   56.889858]  do_syscall_64+0x59/0x90
[   56.889858]  entry_SYSCALL_64_after_hwframe+0x6e/0xd8
[   56.889858] 
[   56.889858] Freed by task 74:
[   56.889858]  kasan_save_stack+0x26/0x60
[   56.889858]  kasan_set_track+0x25/0x40
[   56.889858]  kasan_save_free_info+0x2b/0x60
[   56.889858]  ____kasan_slab_free+0x17f/0x200
[   56.889858]  __kasan_slab_free+0x12/0x30
[   56.889858]  slab_free_freelist_hook+0xd0/0x1a0
[   56.889858]  __kmem_cache_free+0x19d/0x2f0
[   56.889858]  kfree+0x79/0x120
[   56.889858]  gsm_free_muxr+0x73/0xc0 [n_gsm]
[   56.889858]  gsmld_close+0xe5/0x100 [n_gsm]
[   56.889858]  tty_ldisc_close+0x76/0x90
[   56.889858]  tty_ldisc_release+0xef/0x240
[   56.889858]  tty_release_struct+0x22/0xb0
[   56.889858]  tty_release+0x72e/0x8e0
[   56.889858]  __fput+0x207/0x4c0
[   56.889858]  ____fput+0xe/0x20
[   56.889858]  task_work_run+0x108/0x190
[   56.889858]  get_signal+0x161/0x1090
[   56.889858]  arch_do_signal_or_restart+0x84/0x3d0
[   56.889858]  exit_to_user_mode_prepare+0x11b/0x190
[   56.889858]  syscall_exit_to_user_mode+0x2a/0x60
[   56.889858]  do_syscall_64+0x69/0x90
[   56.889858]  entry_SYSCALL_64_after_hwframe+0x6e/0xd8
[   56.889858] 
[   56.889858] Last potentially related work creation:
[   56.889858]  kasan_save_stack+0x26/0x60
[   56.889858]  __kasan_record_aux_stack+0xb3/0xd0
[   56.889858]  kasan_record_aux_stack_noalloc+0xb/0x20
[   56.889858]  insert_work+0x3b/0x170
[   56.889858]  __queue_work+0x356/0x760
[   56.889858]  queue_work_on+0x75/0x80
[   56.889858]  gsmld_write_trigger+0x88/0xb0 [n_gsm]
[   56.889858]  gsm_send.isra.0+0x262/0x2c0 [n_gsm]
[   56.889858]  gsm_dlci_begin_close+0x7e/0x100 [n_gsm]
[   56.889858]  gsm_dlci_t1+0x18a/0x2a0 [n_gsm]
[   56.889858]  call_timer_fn+0x2d/0x1b0
[   56.889858]  __run_timers.part.0+0x451/0x530
[   56.889858]  run_timer_softirq+0x47/0x90
[   56.889858]  __do_softirq+0xf9/0x40c
[   56.889858] 
[   56.889858] Second to last potentially related work creation:
[   56.889858]  kasan_save_stack+0x26/0x60
[   56.889858]  __kasan_record_aux_stack+0xb3/0xd0
[   56.889858]  kasan_record_aux_stack_noalloc+0xb/0x20
[   56.889858]  insert_work+0x3b/0x170
[   56.889858]  __queue_work+0x356/0x760
[   56.889858]  queue_work_on+0x75/0x80
[   56.889858]  gsmld_write_trigger+0x88/0xb0 [n_gsm]
[   56.889858]  gsm_send.isra.0+0x262/0x2c0 [n_gsm]
[   56.889858]  gsm_dlci_begin_close+0x7e/0x100 [n_gsm]
[   56.889858]  gsm_dlci_t1+0x18a/0x2a0 [n_gsm]
[   56.889858]  call_timer_fn+0x2d/0x1b0
[   56.889858]  __run_timers.part.0+0x451/0x530
[   56.889858]  run_timer_softirq+0x47/0x90
[   56.889858]  __do_softirq+0xf9/0x40c
[   56.889858] 
[   56.889858] The buggy address belongs to the object at ffff8881037ea800
[   56.889858]  which belongs to the cache kmalloc-1k of size 1024
[   56.889858] The buggy address is located 916 bytes inside of
[   56.889858]  freed 1024-byte region [ffff8881037ea800, ffff8881037eac00)
[   56.889858] 
[   56.889858] The buggy address belongs to the physical page:
[   56.889858] page:(____ptrval____) refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x1038
[   56.889858] head:(____ptrval____) order:3 entire_mapcount:0 nr_pages_mapped:0 pincount:0
[   56.889858] flags: 0x17ffffc0010200(slab|head|node=0|zone=2|lastcpupid=0x1fffff)
[   56.889858] page_type: 0xffffffff()
[   56.889858] raw: 0017ffffc0010200 ffff888100041dc0 dead000000000122 0000000000000000
[   56.889858] raw: 0000000000000000 0000000000100010 00000001ffffffff 0000000000000000
[   56.889858] page dumped because: kasan: bad access detected
[   56.889858] 
[   56.889858] Memory state around the buggy address:
[   56.889858]  ffff8881037eaa80: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   56.889858]  ffff8881037eab00: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   56.889858] >ffff8881037eab80: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   56.889858]                          ^
[   56.889858]  ffff8881037eac00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   56.889858]  ffff8881037eac80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   56.889858] ==================================================================
[   56.889858] Disabling lock debugging due to kernel taint
```

## Mitigation
This bug (and other stupid n_gsm bugs) can be mitigated by disabling line discipline autoloading.

You can also blacklist the n_gsm module, which I strongly suggest:
```
# sysctl dev.tty.ldisc_autoload=0                                    # disable autoloading sysctl until reboot
# echo -e "\n\ndev.tty.ldisc_autoload=0\n" >> /etc/sysctl.conf       # disable autoloading on future boots
# echo -e "\n\nblacklist n_gsm\n" >> /etc/modprobe.d/blacklist.conf  # blacklist the n_gsm module
```
