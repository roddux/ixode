See [`notes.md`](notes.md) for information on the bug, and [`ixode.c`](ixode.c) for the proof-of-concept exploit that triggers the KASAN splat in [`splat.txt`](splat.txt).

Tested on `6.10.2`, with the config in [`repro_config`](repro_config) -- which is a lightly modified (+KASAN, -Canonical certs) config pulled from Ubuntu LTS. It's overkill for what we're doing here, but hey ho.

---

Source ref: https://github.com/torvalds/linux/blob/master/drivers/tty/n_gsm.c

---


To reproduce, make sure you have `/dev/pts` mounted, so you can grab a pseudoterminal:
```
# mount proc -t proc /proc
# mkdir /dev/pts
# mount devpts -t devpts /dev/pts
```

You can't reproduce this on `/dev/tty1` anymore, as there are now checks to prevent setting weird line disciplines for the main console.