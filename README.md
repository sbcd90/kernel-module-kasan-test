kernel-module-kasan-test
========================

A simple `hello-world` kernel module to test `kasan use-after-free detection` errors.

Build the kernel
================

- Build linux kernel with following configurations to enable `kasan`.

```
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
# CONFIG_KASAN_OUTLINE is not set
CONFIG_KASAN_INLINE=y
CONFIG_KUNIT=y
CONFIG_STACKTRACE=y
```

Check unit tests
================

- in Linux kernel code, refer to files for unit tests for checking unit test failures in `dmesg` logs.

```
lib/test_kasan.c
lib/test_kasan_module.c
```

Compile & Install the module
============================

```
make
sudo insmod test_kasan1.ko
```

Find the error
==============

```
sudo dmesg | less > log.txt
```

```
[  807.043548] BUG: KASAN: use-after-free in access_ptr+0x32/0x36 [test_kasan1]
[  807.043554] Read of size 4 at addr ffff888102af5e38 by task insmod/2187

[  807.043558] CPU: 0 PID: 2187 Comm: insmod Tainted: G    B      OE     5.17.0-rc7-master-00060-g92f90cc9fe0e #2 53babe967a2e4dfa0f2321fbcd210d7c803628fd
[  807.043563] Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS VirtualBox 12/01/2006
[  807.043565] Call Trace:
[  807.043567]  <TASK>
[  807.043569]  dump_stack_lvl+0x48/0x5e
[  807.043574]  print_address_description.constprop.0+0x1f/0x150
[  807.043579]  ? access_ptr+0x32/0x36 [test_kasan1 eeb1848df346114a9e97087ac53e8e37b9fa222f]
[  807.043583]  kasan_report.cold+0x7f/0x11b
[  807.043586]  ? access_ptr+0x32/0x36 [test_kasan1 eeb1848df346114a9e97087ac53e8e37b9fa222f]
[  807.043590]  ? 0xffffffffc0d62000
[  807.043594]  access_ptr+0x32/0x36 [test_kasan1 eeb1848df346114a9e97087ac53e8e37b9fa222f]
[  807.043597]  test_kasan_module_init+0x26/0x1000 [test_kasan1 eeb1848df346114a9e97087ac53e8e37b9fa222f]
[  807.043602]  do_one_initcall+0x89/0x2e0
[  807.043606]  ? trace_event_raw_event_initcall_level+0x190/0x190
[  807.043609]  ? kfree+0xb9/0x400
[  807.043612]  ? kasan_set_track+0x21/0x30
[  807.043615]  ? kasan_unpoison+0x40/0x70
[  807.043619]  do_init_module+0x190/0x710
[  807.043623]  load_module+0x780e/0x9c60
[  807.043629]  ? module_frob_arch_sections+0x20/0x20
[  807.043633]  ? bpf_lsm_kernel_read_file+0x10/0x10
[  807.043637]  ? security_kernel_post_read_file+0x56/0x90
[  807.043641]  ? kernel_read_file+0x286/0x6a0
[  807.043645]  ? __do_sys_finit_module+0x11a/0x1c0
[  807.043649]  __do_sys_finit_module+0x11a/0x1c0
[  807.043652]  ? __ia32_sys_init_module+0xa0/0xa0
[  807.043656]  ? vm_mmap_pgoff+0x185/0x210
[  807.043660]  do_syscall_64+0x5c/0x80
[  807.043664]  ? exc_page_fault+0x5d/0xd0
[  807.043667]  entry_SYSCALL_64_after_hwframe+0x44/0xae
[  807.043670] RIP: 0033:0x7f3caa948a9d
[  807.043673] Code: 5b 41 5c c3 66 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d cb e2 0e 00 f7 d8 64 89 01 48
[  807.043676] RSP: 002b:00007ffffbe0c888 EFLAGS: 00000246 ORIG_RAX: 0000000000000139
[  807.043680] RAX: ffffffffffffffda RBX: 0000558fac3ab750 RCX: 00007f3caa948a9d
[  807.043682] RDX: 0000000000000000 RSI: 0000558fac232a2a RDI: 0000000000000003
[  807.043684] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[  807.043686] R10: 0000000000000003 R11: 0000000000000246 R12: 0000558fac232a2a
[  807.043688] R13: 0000558fac3ab700 R14: 0000558fac231618 R15: 0000558fac3ab860
[  807.043691]  </TASK>

[  807.043694] Allocated by task 2187:
[  807.043696]  kasan_save_stack+0x1e/0x40
[  807.043699]  __kasan_kmalloc+0xa9/0xd0
[  807.043701]  create_ptr+0x43/0x64 [test_kasan1]
[  807.043704]  test_kasan_module_init+0x13/0x1000 [test_kasan1]
[  807.043707]  do_one_initcall+0x89/0x2e0
[  807.043710]  do_init_module+0x190/0x710
[  807.043713]  load_module+0x780e/0x9c60
[  807.043716]  __do_sys_finit_module+0x11a/0x1c0
[  807.043719]  do_syscall_64+0x5c/0x80
[  807.043721]  entry_SYSCALL_64_after_hwframe+0x44/0xae

[  807.043724] Freed by task 2187:
[  807.043726]  kasan_save_stack+0x1e/0x40
[  807.043728]  kasan_set_track+0x21/0x30
[  807.043730]  kasan_set_free_info+0x20/0x30
[  807.043733]  ____kasan_slab_free+0x12f/0x160
[  807.043735]  slab_free_freelist_hook+0x8e/0x190
[  807.043738]  kfree+0xb9/0x400
[  807.043741]  test_kasan_module_init+0x1e/0x1000 [test_kasan1]
[  807.043744]  do_one_initcall+0x89/0x2e0
[  807.043746]  do_init_module+0x190/0x710
[  807.043749]  load_module+0x780e/0x9c60
[  807.043752]  __do_sys_finit_module+0x11a/0x1c0
[  807.043755]  do_syscall_64+0x5c/0x80
[  807.043757]  entry_SYSCALL_64_after_hwframe+0x44/0xae

[  807.043760] The buggy address belongs to the object at ffff888102af5e38
                which belongs to the cache kmalloc-8 of size 8
[  807.043763] The buggy address is located 0 bytes inside of
                8-byte region [ffff888102af5e38, ffff888102af5e40)
[  807.043765] The buggy address belongs to the page:
[  807.043767] page:00000000be601e46 refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x102af5
[  807.043770] flags: 0x2ffff0000000200(slab|node=0|zone=2|lastcpupid=0xffff)
[  807.043775] raw: 02ffff0000000200 ffffea00042aa300 dead000000000003 ffff888100041280
[  807.043778] raw: 0000000000000000 0000000080660066 00000001ffffffff 0000000000000000
[  807.043780] page dumped because: kasan: bad access detected

[  807.043782] Memory state around the buggy address:
[  807.043784]  ffff888102af5d00: fc fc fc fc 00 fc fc fc fc fa fc fc fc fc fa fc
[  807.043786]  ffff888102af5d80: fc fc fc 00 fc fc fc fc 00 fc fc fc fc fa fc fc
[  807.043787] >ffff888102af5e00: fc fc 00 fc fc fc fc fa fc fc fc fc 00 fc fc fc
[  807.043789]                                         ^
[  807.043791]  ffff888102af5e80: fc 00 fc fc fc fc fa fc fc fc fc 00 fc fc fc fc
[  807.043792]  ffff888102af5f00: fa fc fc fc fc 00 fc fc fc fc 00 fc fc fc fc 00
[  807.043794] ==================================================================
[  807.061506] audit: type=1106 audit(1646936532.139:72): pid=2186 uid=1000 auid=1000 ses=1 msg='op=PAM:session_close grantors=pam_systemd_home,pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  807.061855] audit: type=1104 audit(1646936532.139:73): pid=2186 uid=1000 auid=1000 ses=1 msg='op=PAM:setcred grantors=pam_faillock,pam_permit,pam_env,pam_faillock acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  816.126597] audit: type=1101 audit(1646936541.206:74): pid=2188 uid=1000 auid=1000 ses=1 msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct="sbcd90" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  816.135034] audit: type=1110 audit(1646936541.216:75): pid=2188 uid=1000 auid=1000 ses=1 msg='op=PAM:setcred grantors=pam_faillock,pam_permit,pam_env,pam_faillock acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  816.139723] audit: type=1105 audit(1646936541.219:76): pid=2188 uid=1000 auid=1000 ses=1 msg='op=PAM:session_open grantors=pam_systemd_home,pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
```

Verify memory state content
===========================

- Access Location in log has content `fa`

- Looking at file `mm/kasan/kasan.h` in `linux kernel` code, it confirms the code is for `freed memory`.

```
#ifdef CONFIG_KASAN_GENERIC
#define KASAN_FREE_PAGE         0xFF  /* page was freed */
#define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
#define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
#define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
#define KASAN_KMALLOC_FREETRACK 0xFA  /* object was freed and has free track set */
#else
#define KASAN_FREE_PAGE         KASAN_TAG_INVALID
#define KASAN_PAGE_REDZONE      KASAN_TAG_INVALID
#define KASAN_KMALLOC_REDZONE   KASAN_TAG_INVALID
#define KASAN_KMALLOC_FREE      KASAN_TAG_INVALID
#define KASAN_KMALLOC_FREETRACK KASAN_TAG_INVALID
#endif
```