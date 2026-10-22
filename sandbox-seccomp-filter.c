/*
 * Copyright (c) 2012 Will Drewry <wad@dataspill.org>
 * Copyright (c) 2015,2017,2019,2020,2023 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Uncomment the SANDBOX_SECCOMP_FILTER_DEBUG macro below to help diagnose
 * filter breakage during development. *Do not* use this in production,
 * as it relies on making library calls that are unsafe in signal context.
 *
 * Instead, live systems the auditctl(8) may be used to monitor failures.
 * E.g.
 *   auditctl -a task,always -F uid=<privsep uid>
 */
/* #define SANDBOX_SECCOMP_FILTER_DEBUG 1 */

#اگر 0
/*
 * For older toolchains, it may be necessary to use the kernel
 * headers directly.
 */
#اگر_تعریف_شدہ SANDBOX_SECCOMP_FILTER_DEBUG
# include <asm/siginfo.h>
# define __have_siginfo_t 1
# define __have_sigval_t 1
# define __have_sigevent_t 1
#اگر_ختم /* SANDBOX_SECCOMP_FILTER_DEBUG */
#اگر_ختم

#شامل "includes.h"

#اگر_تعریف_شدہ SANDBOX_SECCOMP_FILTER

#شامل <sys/types.h>
#شامل <sys/resource.h>
#شامل <sys/prctl.h>
#شامل <sys/mman.h>
#شامل <sys/syscall.h>

#شامل <netinet/ip.h>

#شامل <linux/futex.h>
#شامل <linux/net.h>
#شامل <linux/audit.h>
#شامل <linux/filter.h>
#شامل <linux/seccomp.h>
#شامل <elf.h>

#شامل <asm/unistd.h>
#اگر_تعریف_شدہ __s390__
#شامل <asm/zcrypt.h>
#اگر_ختم

#شامل <errno.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stddef.h>  /* for offsetof */
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "log.h"
#شامل "ssh-sandbox.h"
#شامل "xmalloc.h"

/* Linux seccomp_filter sandbox */
#تعریف_کرو SECCOMP_FILTER_FAIL SECCOMP_RET_KILL

/* Use a signal handler to emit violations when debugging */
#اگر_تعریف_شدہ SANDBOX_SECCOMP_FILTER_DEBUG
# undef SECCOMP_FILTER_FAIL
# define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#اگر_ختم /* SANDBOX_SECCOMP_FILTER_DEBUG */

#اگر __BYTE_ORDER == __LITTLE_ENDIAN
# define ARG_LO_انحراف  0
# define ARG_HI_انحراف  حجم(uint32_t)
#وگرنہ_اگر __BYTE_ORDER == __BIG_ENDIAN
# define ARG_LO_انحراف  حجم(uint32_t)
# define ARG_HI_انحراف  0
#ورنہ
#غلطی "Unknown endianness"
#اگر_ختم

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#تعریف_کرو SC_DENY(_nr, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#تعریف_کرو SC_ALLOW(_nr) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#تعریف_کرو SC_ALLOW_ARG(_nr, _arg_nr, _arg_val) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 6), \
	/* load and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ساخت seccomp_ڈیٹا, دلائل[(_arg_nr)]) + ARG_LO_انحراف), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_arg_val) & 0xFFFFFFFF), 0, 3), \
	/* load and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ساخت seccomp_ڈیٹا, دلائل[(_arg_nr)]) + ARG_HI_انحراف), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_arg_val) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(ساخت seccomp_ڈیٹا, nr))
/* Allow if syscall argument contains only values in mask */
#تعریف_کرو SC_ALLOW_ARG_نقاب(_nr, _arg_nr, arg_نقاب) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ساخت seccomp_ڈیٹا, دلائل[(_arg_nr)]) + ARG_LO_انحراف), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_نقاب) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 4), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ساخت seccomp_ڈیٹا, دلائل[(_arg_nr)]) + ARG_HI_انحراف), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_نقاب) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(ساخت seccomp_ڈیٹا, nr))
/* Deny unless syscall argument contains only values in mask */
#تعریف_کرو SC_DENY_UNLESS_ARG_نقاب(_nr, _arg_nr, arg_نقاب, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ساخت seccomp_ڈیٹا, دلائل[(_arg_nr)]) + ARG_LO_انحراف), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_نقاب) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 3), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ساخت seccomp_ڈیٹا, دلائل[(_arg_nr)]) + ARG_HI_انحراف), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_نقاب) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno)), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(ساخت seccomp_ڈیٹا, nr))
#تعریف_کرو SC_DENY_UNLESS_نقاب(_nr, _arg_nr, _arg_val, _errno) \
/* Special handling for futex(2) that combines a bitmap and operation number */
#اگر defined(__NR_futex) || defined(__NR_futex_time64)
#تعریف_کرو SC_FUTEX_نقاب (FUTEX_نجی_FLAG|FUTEX_CLOCK_REALTIME)
#تعریف_کرو SC_ALLOW_FUTEX_OP(_nr, _op) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ساخت seccomp_ڈیٹا, دلائل[1]) + ARG_LO_انحراف), \
	/* mask off allowed bitmap values, low word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~(SC_FUTEX_نقاب & 0xFFFFFFFF)), \
	/* test operation number, low word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ((_op) & 0xFFFFFFFF), 0, 4), \
	/* load syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ساخت seccomp_ڈیٹا, دلائل[1]) + ARG_HI_انحراف), \
	/* mask off allowed bitmap values, high word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)SC_FUTEX_نقاب >> 32)) & 0xFFFFFFFF)), \
	/* test operation number, high word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_op) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(ساخت seccomp_ڈیٹا, nr))

/* Use this for both __NR_futex and __NR_futex_time64 */
# define SC_FUTEX(_nr) \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_REQUEUE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_CMP_REQUEUE)
#اگر_ختم /* __NR_futex || __NR_futex_time64 */

#اگر defined(__NR_mmap) || defined(__NR_mmap2)
# ifdef MAP_FIXED_NOREPLACE
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_FIXED_NOREPLACE
# ورنہ
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED
# endif /* MAP_FIXED_NOREPLACE */
/* Use this for both __NR_mmap and __NR_mmap2 variants */
# define SC_MMAP(_nr) \
	SC_DENY_UNLESS_ARG_نقاب(_nr, 3, SC_MMAP_FLAGS, EINVAL), \
	SC_ALLOW_ARG_نقاب(_nr, 2, PROT_READ|PROT_WRITE|PROT_NONE)
#اگر_ختم /* __NR_mmap || __NR_mmap2 */

/* Special handling for setsockopt(2) */
#تعریف_کرو SC_ALLOW_SETSOCKOPT(_level, _optname) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setsockopt, 0, 10), \
	/* load and test level, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ساخت seccomp_ڈیٹا, دلائل[1]) + ARG_LO_انحراف), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_level) & 0xFFFFFFFF), 0, 7), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ساخت seccomp_ڈیٹا, دلائل[1]) + ARG_HI_انحراف), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 5), \
	/* load and test optname, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ساخت seccomp_ڈیٹا, دلائل[2]) + ARG_LO_انحراف), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_optname) & 0xFFFFFFFF), 0, 3), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ساخت seccomp_ڈیٹا, دلائل[2]) + ARG_HI_انحراف), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(ساخت seccomp_ڈیٹا, nr))

/* Syscall filtering set for preauth. */
ساکن ثابت ساخت sock_filter preauth_insns[] = {
	/* Ensure the syscall arch convention is as expected. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(ساخت seccomp_ڈیٹا, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
	/* Load the syscall number for checking. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(ساخت seccomp_ڈیٹا, nr)),

	/* Syscalls to non-fatally deny */
#اگر_تعریف_شدہ __NR_lstat
	SC_DENY(__NR_lstat, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_lstat64
	SC_DENY(__NR_lstat64, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_fstat
	SC_DENY(__NR_fstat, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_fstat64
	SC_DENY(__NR_fstat64, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_fstatat64
	SC_DENY(__NR_fstatat64, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_open
	SC_DENY(__NR_open, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_openat
	SC_DENY(__NR_openat, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_newfstatat
	SC_DENY(__NR_newfstatat, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_stat
	SC_DENY(__NR_stat, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_stat64
	SC_DENY(__NR_stat64, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_shmget
	SC_DENY(__NR_shmget, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_shmat
	SC_DENY(__NR_shmat, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_shmdt
	SC_DENY(__NR_shmdt, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_ipc
	SC_DENY(__NR_ipc, EACCES),
#اگر_ختم
#اگر_تعریف_شدہ __NR_statx
	SC_DENY(__NR_statx, EACCES),
#اگر_ختم

	/* Syscalls to permit */
#اگر_تعریف_شدہ __NR_brk
	SC_ALLOW(__NR_brk),
#اگر_ختم
#اگر_تعریف_شدہ __NR_clock_gettime
	SC_ALLOW(__NR_clock_gettime),
#اگر_ختم
#اگر_تعریف_شدہ __NR_clock_gettime64
	SC_ALLOW(__NR_clock_gettime64),
#اگر_ختم
#اگر_تعریف_شدہ __NR_close
	SC_ALLOW(__NR_close),
#اگر_ختم
#اگر_تعریف_شدہ __NR_exit
	SC_ALLOW(__NR_exit),
#اگر_ختم
#اگر_تعریف_شدہ __NR_exit_group
	SC_ALLOW(__NR_exit_group),
#اگر_ختم
#اگر_تعریف_شدہ __NR_futex
	SC_FUTEX(__NR_futex),
#اگر_ختم
#اگر_تعریف_شدہ __NR_futex_time64
	SC_FUTEX(__NR_futex_time64),
#اگر_ختم
#اگر_تعریف_شدہ __NR_geteuid
	SC_ALLOW(__NR_geteuid),
#اگر_ختم
#اگر_تعریف_شدہ __NR_geteuid32
	SC_ALLOW(__NR_geteuid32),
#اگر_ختم
#اگر_تعریف_شدہ __NR_getpgid
	SC_ALLOW(__NR_getpgid),
#اگر_ختم
#اگر_تعریف_شدہ __NR_getpid
	SC_ALLOW(__NR_getpid),
#اگر_ختم
#اگر_تعریف_شدہ __NR_getrandom
	SC_ALLOW(__NR_getrandom),
#اگر_ختم
#اگر_تعریف_شدہ __NR_gettid
	SC_ALLOW(__NR_gettid),
#اگر_ختم
#اگر_تعریف_شدہ __NR_gettimeofday
	SC_ALLOW(__NR_gettimeofday),
#اگر_ختم
#اگر_تعریف_شدہ __NR_getuid
	SC_ALLOW(__NR_getuid),
#اگر_ختم
#اگر_تعریف_شدہ __NR_getuid32
	SC_ALLOW(__NR_getuid32),
#اگر_ختم
#اگر_تعریف_شدہ __NR_madvise
	SC_ALLOW_ARG(__NR_madvise, 2, MADV_NORMAL),
# ifdef MADV_FREE
	SC_ALLOW_ARG(__NR_madvise, 2, MADV_FREE),
# endif
# ifdef MADV_DONTNEED
	SC_ALLOW_ARG(__NR_madvise, 2, MADV_DONTNEED),
# endif
# ifdef MADV_DONTNEED_LOCKED
	SC_ALLOW_ARG(__NR_madvise, 2, MADV_DONTNEED_LOCKED),
# endif
# ifdef MADV_DONTFORK
	SC_ALLOW_ARG(__NR_madvise, 2, MADV_DONTFORK),
# endif
# ifdef MADV_DONTDUMP
	SC_ALLOW_ARG(__NR_madvise, 2, MADV_DONTDUMP),
# endif
# ifdef MADV_WIPEONFORK
	SC_ALLOW_ARG(__NR_madvise, 2, MADV_WIPEONFORK),
# endif
	SC_DENY(__NR_madvise, EINVAL),
#اگر_ختم
#اگر_تعریف_شدہ __NR_mmap
	SC_MMAP(__NR_mmap),
#اگر_ختم
#اگر_تعریف_شدہ __NR_mmap2
	SC_MMAP(__NR_mmap2),
#اگر_ختم
#اگر_تعریف_شدہ __NR_mprotect
	SC_ALLOW_ARG_نقاب(__NR_mprotect, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#اگر_ختم
#اگر_تعریف_شدہ __NR_mremap
	SC_ALLOW_ARG_نقاب(__NR_mremap, 3, MREMAP_MAYMOVE),
#اگر_ختم
#اگر_تعریف_شدہ __NR_munmap
	SC_ALLOW(__NR_munmap),
#اگر_ختم
#اگر_تعریف_شدہ __NR_nanosleep
	SC_ALLOW(__NR_nanosleep),
#اگر_ختم
#اگر_تعریف_شدہ __NR_clock_nanosleep
	SC_ALLOW(__NR_clock_nanosleep),
#اگر_ختم
#اگر_تعریف_شدہ __NR_clock_nanosleep_time64
	SC_ALLOW(__NR_clock_nanosleep_time64),
#اگر_ختم
#اگر_تعریف_شدہ __NR__newselect
	SC_ALLOW(__NR__newselect),
#اگر_ختم
#اگر_تعریف_شدہ __NR_ppoll
	SC_ALLOW(__NR_ppoll),
#اگر_ختم
#اگر_تعریف_شدہ __NR_ppoll_time64
	SC_ALLOW(__NR_ppoll_time64),
#اگر_ختم
#اگر_تعریف_شدہ __NR_poll
	SC_ALLOW(__NR_poll),
#اگر_ختم
#اگر_تعریف_شدہ __NR_pselect6
	SC_ALLOW(__NR_pselect6),
#اگر_ختم
#اگر_تعریف_شدہ __NR_pselect6_time64
	SC_ALLOW(__NR_pselect6_time64),
#اگر_ختم
#اگر_تعریف_شدہ __NR_read
	SC_ALLOW(__NR_read),
#اگر_ختم
#اگر_تعریف_شدہ __NR_riscv_hwprobe
	SC_ALLOW(__NR_riscv_hwprobe),
#اگر_ختم
#اگر_تعریف_شدہ __NR_rt_sigprocmask
	SC_ALLOW(__NR_rt_sigprocmask),
#اگر_ختم
#اگر_تعریف_شدہ __NR_select
	SC_ALLOW(__NR_select),
#اگر_ختم
#اگر_تعریف_شدہ __NR_shutdown
	SC_ALLOW(__NR_shutdown),
#اگر_ختم
#اگر_تعریف_شدہ __NR_sigprocmask
	SC_ALLOW(__NR_sigprocmask),
#اگر_ختم
#اگر_تعریف_شدہ __NR_time
	SC_ALLOW(__NR_time),
#اگر_ختم
#اگر_تعریف_شدہ __NR_write
	SC_ALLOW(__NR_write),
#اگر_ختم
#اگر_تعریف_شدہ __NR_writev
	SC_ALLOW(__NR_writev),
#اگر_ختم
#اگر_تعریف_شدہ __NR_getsockopt
	SC_ALLOW(__NR_getsockopt),
#اگر_ختم
#اگر_تعریف_شدہ __NR_getsockname
	SC_ALLOW(__NR_getsockname),
#اگر_ختم
#اگر_تعریف_شدہ __NR_getpeername
	SC_ALLOW(__NR_getpeername),
#اگر_ختم
#اگر_تعریف_شدہ __NR_uname
	SC_ALLOW(__NR_uname),
#اگر_ختم
#اگر_تعریف_شدہ __NR_restart_syscall
	SC_ALLOW(__NR_restart_syscall),
#اگر_ختم
#اگر_تعریف_شدہ __NR_setsockopt
	SC_ALLOW_SETSOCKOPT(IPPROTO_IPV6, IPV6_TCLASS),
	SC_ALLOW_SETSOCKOPT(IPPROTO_IP, IP_TOS),
#اگر_ختم
#اگر_تعریف_شدہ __NR_socketcall
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETPEERNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKOPT),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
	SC_DENY(__NR_socketcall, EACCES),
#اگر_ختم
#اگر defined(__NR_ioctl) && defined(__s390__)
	/* Allow ioctls for ICA crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, Z90_STAT_حالت_نقاب),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSAMODEXPO),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSACRT),
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSECSENDCPRB),
	/* Allow ioctls for EP11 crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSENDEP11CPRB),
#اگر_ختم
#اگر defined(__x86_64__) && defined(__ILP32__) && defined(__X32_SYSCALL_BIT)
	/*
	 * On Linux x32, the clock_gettime VDSO falls back to the
	 * x86-64 syscall under some circumstances, e.g.
	 * https://bugs.debian.org/849923
	 */
	SC_ALLOW(__NR_clock_gettime & ~__X32_SYSCALL_BIT),
#اگر_ختم

	/* Default deny */
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

ساکن ثابت ساخت sock_fprog preauth_پروگرام = {
	.len = (غیرعلامتی مختصر)(حجم(preauth_insns)/حجم(preauth_insns[0])),
	.filter = (ساخت sock_filter *)preauth_insns,
};

ساخت ssh_sandbox {
	صحیح junk;
};

ساخت ssh_sandbox *
ssh_sandbox_init(ساخت monitor *monitor)
{
	ساخت ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing seccomp filter sandbox");
	box = xcalloc(1, حجم(*box));
	واپس box;
}

#اگر_تعریف_شدہ SANDBOX_SECCOMP_FILTER_DEBUG
خارجی ساخت monitor *pmonitor;
خالی mm_log_handler(LogLevel level, صحیح forced, ثابت حرف *پیغام, خالی *ctx);

ساکن خالی
ssh_sandbox_violation(صحیح signum, siginfo_t *info, خالی *void_context)
{
	حرف پیغام[256];

	snprintf(پیغام, حجم(پیغام),
	    "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)",
	    __func__, info->si_arch, info->si_syscall, info->si_call_addr);
	mm_log_handler(SYSLOG_LEVEL_FATAL, 0, پیغام, pmonitor);
	_exit(1);
}

ساکن خالی
ssh_sandbox_بچہ_debugging(خالی)
{
	ساخت sigaction act;
	sigset_t نقاب;

	debug3_f("installing SIGSYS handler");
	memset(&act, 0, حجم(act));
	sigemptyset(&نقاب);
	sigaddset(&نقاب, SIGSYS);

	act.sa_sigaction = &ssh_sandbox_violation;
	act.sa_flags = SA_SIGINFO;
	اگر (sigaction(SIGSYS, &act, تہی) == -1)
		fatal_f("sigaction(SIGSYS): %s", strerror(errno));
	اگر (sigprocmask(SIG_UNBLOCK, &نقاب, تہی) == -1)
		fatal("%s: sigprocmask(SIGSYS): %s",
		    __func__, strerror(errno));
}
#اگر_ختم /* SANDBOX_SECCOMP_FILTER_DEBUG */

خالی
ssh_sandbox_بچہ(ساخت ssh_sandbox *box)
{
	ساخت rlimit rl_zero, rl_one = {.rlim_cur = 1, .rlim_max = 1};

	/* Set rlimits for completeness if possible. */
	rl_zero.rlim_cur = rl_zero.rlim_max = 0;
	اگر (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
	/*
	 * Cannot use zero for nfds, because poll(2) will fail with
	 * errno=EINVAL if npfds>RLIMIT_NOFILE.
	 */
	اگر (setrlimit(RLIMIT_NOFILE, &rl_one) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
	اگر (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));

#اگر_تعریف_شدہ SANDBOX_SECCOMP_FILTER_DEBUG
	ssh_sandbox_بچہ_debugging();
#اگر_ختم /* SANDBOX_SECCOMP_FILTER_DEBUG */

	debug3_f("setting PR_SET_NO_NEW_PRIVS");
	اگر (prctl(PR_سیٹ_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatal_f("prctl(PR_SET_NO_NEW_PRIVS): %s", strerror(errno));
	debug3_f("attaching seccomp filter program");
	اگر (prctl(PR_سیٹ_SECCOMP, SECCOMP_منوال_FILTER, &preauth_پروگرام) == -1)
		fatal_f("prctl(PR_SET_SECCOMP): %s", strerror(errno));
}

#اگر_ختم /* SANDBOX_SECCOMP_FILTER */
