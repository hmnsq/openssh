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

#إذا 0
/*
 * For older toolchains, it may be necessary to use the kernel
 * headers directly.
 */
#جے_تعریف_شدہ SANDBOX_SECCOMP_FILTER_DEBUG
# include <asm/siginfo.h>
# define __have_siginfo_t 1
# define __have_sigval_t 1
# define __have_sigevent_t 1
#جے_انت /* SANDBOX_SECCOMP_FILTER_DEBUG */
#جے_انت

#ضمن "includes.h"

#جے_تعریف_شدہ SANDBOX_SECCOMP_FILTER

#ضمن <sys/types.h>
#ضمن <sys/resource.h>
#ضمن <sys/prctl.h>
#ضمن <sys/mman.h>
#ضمن <sys/syscall.h>

#ضمن <netinet/ip.h>

#ضمن <linux/futex.h>
#ضمن <linux/net.h>
#ضمن <linux/audit.h>
#ضمن <linux/filter.h>
#ضمن <linux/seccomp.h>
#ضمن <elf.h>

#ضمن <asm/unistd.h>
#جے_تعریف_شدہ __s390__
#ضمن <asm/zcrypt.h>
#جے_انت

#ضمن <errno.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stddef.h>  /* for offsetof */
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "log.h"
#ضمن "ssh-sandbox.h"
#ضمن "xmalloc.h"

/* Linux seccomp_filter sandbox */
#تعریف_کرو SECCOMP_FILTER_FAIL SECCOMP_RET_KILL

/* Use a signal handler to emit violations when debugging */
#جے_تعریف_شدہ SANDBOX_SECCOMP_FILTER_DEBUG
# undef SECCOMP_FILTER_FAIL
# define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#جے_انت /* SANDBOX_SECCOMP_FILTER_DEBUG */

#إذا __BYTE_ORDER == __LITTLE_ENDIAN
# define ARG_LO_وتھ  0
# define ARG_HI_وتھ  حجم(uint32_t)
#وإلاإذا __BYTE_ORDER == __BIG_ENDIAN
# define ARG_LO_وتھ  حجم(uint32_t)
# define ARG_HI_وتھ  0
#وإلا
#غلطی "Unknown endianness"
#جے_انت

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
	    offsetof(بنية seccomp_انکڑے, دلیلاں[(_arg_nr)]) + ARG_LO_وتھ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_arg_val) & 0xFFFFFFFF), 0, 3), \
	/* load and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_انکڑے, دلیلاں[(_arg_nr)]) + ARG_HI_وتھ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_arg_val) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(بنية seccomp_انکڑے, nr))
/* Allow if syscall argument contains only values in mask */
#تعریف_کرو SC_ALLOW_ARG_نقاب(_nr, _arg_nr, arg_نقاب) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_انکڑے, دلیلاں[(_arg_nr)]) + ARG_LO_وتھ), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_نقاب) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 4), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_انکڑے, دلیلاں[(_arg_nr)]) + ARG_HI_وتھ), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_نقاب) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(بنية seccomp_انکڑے, nr))
/* Deny unless syscall argument contains only values in mask */
#تعریف_کرو SC_DENY_UNLESS_ARG_نقاب(_nr, _arg_nr, arg_نقاب, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_انکڑے, دلیلاں[(_arg_nr)]) + ARG_LO_وتھ), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_نقاب) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 3), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_انکڑے, دلیلاں[(_arg_nr)]) + ARG_HI_وتھ), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_نقاب) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno)), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(بنية seccomp_انکڑے, nr))
#تعریف_کرو SC_DENY_UNLESS_نقاب(_nr, _arg_nr, _arg_val, _errno) \
/* Special handling for futex(2) that combines a bitmap and operation number */
#إذا defined(__NR_futex) || defined(__NR_futex_time64)
#تعریف_کرو SC_FUTEX_نقاب (FUTEX_نجی_FLAG|FUTEX_CLOCK_REALTIME)
#تعریف_کرو SC_ALLOW_FUTEX_OP(_nr, _op) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_انکڑے, دلیلاں[1]) + ARG_LO_وتھ), \
	/* mask off allowed bitmap values, low word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~(SC_FUTEX_نقاب & 0xFFFFFFFF)), \
	/* test operation number, low word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ((_op) & 0xFFFFFFFF), 0, 4), \
	/* load syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_انکڑے, دلیلاں[1]) + ARG_HI_وتھ), \
	/* mask off allowed bitmap values, high word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)SC_FUTEX_نقاب >> 32)) & 0xFFFFFFFF)), \
	/* test operation number, high word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_op) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(بنية seccomp_انکڑے, nr))

/* Use this for both __NR_futex and __NR_futex_time64 */
# define SC_FUTEX(_nr) \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_REQUEUE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_CMP_REQUEUE)
#جے_انت /* __NR_futex || __NR_futex_time64 */

#إذا defined(__NR_mmap) || defined(__NR_mmap2)
# ifdef MAP_FIXED_NOREPLACE
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_FIXED_NOREPLACE
# وإلا
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED
# endif /* MAP_FIXED_NOREPLACE */
/* Use this for both __NR_mmap and __NR_mmap2 variants */
# define SC_MMAP(_nr) \
	SC_DENY_UNLESS_ARG_نقاب(_nr, 3, SC_MMAP_FLAGS, EINVAL), \
	SC_ALLOW_ARG_نقاب(_nr, 2, PROT_READ|PROT_WRITE|PROT_NONE)
#جے_انت /* __NR_mmap || __NR_mmap2 */

/* Special handling for setsockopt(2) */
#تعریف_کرو SC_ALLOW_SETSOCKOPT(_level, _optname) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setsockopt, 0, 10), \
	/* load and test level, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_انکڑے, دلیلاں[1]) + ARG_LO_وتھ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_level) & 0xFFFFFFFF), 0, 7), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_انکڑے, دلیلاں[1]) + ARG_HI_وتھ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 5), \
	/* load and test optname, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_انکڑے, دلیلاں[2]) + ARG_LO_وتھ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_optname) & 0xFFFFFFFF), 0, 3), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_انکڑے, دلیلاں[2]) + ARG_HI_وتھ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(بنية seccomp_انکڑے, nr))

/* Syscall filtering set for preauth. */
ساكن ثابت بنية sock_filter preauth_insns[] = {
	/* Ensure the syscall arch convention is as expected. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(بنية seccomp_انکڑے, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
	/* Load the syscall number for checking. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(بنية seccomp_انکڑے, nr)),

	/* Syscalls to non-fatally deny */
#جے_تعریف_شدہ __NR_lstat
	SC_DENY(__NR_lstat, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_lstat64
	SC_DENY(__NR_lstat64, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_fstat
	SC_DENY(__NR_fstat, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_fstat64
	SC_DENY(__NR_fstat64, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_fstatat64
	SC_DENY(__NR_fstatat64, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_open
	SC_DENY(__NR_open, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_openat
	SC_DENY(__NR_openat, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_newfstatat
	SC_DENY(__NR_newfstatat, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_stat
	SC_DENY(__NR_stat, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_stat64
	SC_DENY(__NR_stat64, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_shmget
	SC_DENY(__NR_shmget, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_shmat
	SC_DENY(__NR_shmat, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_shmdt
	SC_DENY(__NR_shmdt, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_ipc
	SC_DENY(__NR_ipc, EACCES),
#جے_انت
#جے_تعریف_شدہ __NR_statx
	SC_DENY(__NR_statx, EACCES),
#جے_انت

	/* Syscalls to permit */
#جے_تعریف_شدہ __NR_brk
	SC_ALLOW(__NR_brk),
#جے_انت
#جے_تعریف_شدہ __NR_clock_gettime
	SC_ALLOW(__NR_clock_gettime),
#جے_انت
#جے_تعریف_شدہ __NR_clock_gettime64
	SC_ALLOW(__NR_clock_gettime64),
#جے_انت
#جے_تعریف_شدہ __NR_close
	SC_ALLOW(__NR_close),
#جے_انت
#جے_تعریف_شدہ __NR_exit
	SC_ALLOW(__NR_exit),
#جے_انت
#جے_تعریف_شدہ __NR_exit_group
	SC_ALLOW(__NR_exit_group),
#جے_انت
#جے_تعریف_شدہ __NR_futex
	SC_FUTEX(__NR_futex),
#جے_انت
#جے_تعریف_شدہ __NR_futex_time64
	SC_FUTEX(__NR_futex_time64),
#جے_انت
#جے_تعریف_شدہ __NR_geteuid
	SC_ALLOW(__NR_geteuid),
#جے_انت
#جے_تعریف_شدہ __NR_geteuid32
	SC_ALLOW(__NR_geteuid32),
#جے_انت
#جے_تعریف_شدہ __NR_getpgid
	SC_ALLOW(__NR_getpgid),
#جے_انت
#جے_تعریف_شدہ __NR_getpid
	SC_ALLOW(__NR_getpid),
#جے_انت
#جے_تعریف_شدہ __NR_getrandom
	SC_ALLOW(__NR_getrandom),
#جے_انت
#جے_تعریف_شدہ __NR_gettid
	SC_ALLOW(__NR_gettid),
#جے_انت
#جے_تعریف_شدہ __NR_gettimeofday
	SC_ALLOW(__NR_gettimeofday),
#جے_انت
#جے_تعریف_شدہ __NR_getuid
	SC_ALLOW(__NR_getuid),
#جے_انت
#جے_تعریف_شدہ __NR_getuid32
	SC_ALLOW(__NR_getuid32),
#جے_انت
#جے_تعریف_شدہ __NR_madvise
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
#جے_انت
#جے_تعریف_شدہ __NR_mmap
	SC_MMAP(__NR_mmap),
#جے_انت
#جے_تعریف_شدہ __NR_mmap2
	SC_MMAP(__NR_mmap2),
#جے_انت
#جے_تعریف_شدہ __NR_mprotect
	SC_ALLOW_ARG_نقاب(__NR_mprotect, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#جے_انت
#جے_تعریف_شدہ __NR_mremap
	SC_ALLOW_ARG_نقاب(__NR_mremap, 3, MREMAP_MAYMOVE),
#جے_انت
#جے_تعریف_شدہ __NR_munmap
	SC_ALLOW(__NR_munmap),
#جے_انت
#جے_تعریف_شدہ __NR_nanosleep
	SC_ALLOW(__NR_nanosleep),
#جے_انت
#جے_تعریف_شدہ __NR_clock_nanosleep
	SC_ALLOW(__NR_clock_nanosleep),
#جے_انت
#جے_تعریف_شدہ __NR_clock_nanosleep_time64
	SC_ALLOW(__NR_clock_nanosleep_time64),
#جے_انت
#جے_تعریف_شدہ __NR__newselect
	SC_ALLOW(__NR__newselect),
#جے_انت
#جے_تعریف_شدہ __NR_ppoll
	SC_ALLOW(__NR_ppoll),
#جے_انت
#جے_تعریف_شدہ __NR_ppoll_time64
	SC_ALLOW(__NR_ppoll_time64),
#جے_انت
#جے_تعریف_شدہ __NR_poll
	SC_ALLOW(__NR_poll),
#جے_انت
#جے_تعریف_شدہ __NR_pselect6
	SC_ALLOW(__NR_pselect6),
#جے_انت
#جے_تعریف_شدہ __NR_pselect6_time64
	SC_ALLOW(__NR_pselect6_time64),
#جے_انت
#جے_تعریف_شدہ __NR_read
	SC_ALLOW(__NR_read),
#جے_انت
#جے_تعریف_شدہ __NR_riscv_hwprobe
	SC_ALLOW(__NR_riscv_hwprobe),
#جے_انت
#جے_تعریف_شدہ __NR_rt_sigprocmask
	SC_ALLOW(__NR_rt_sigprocmask),
#جے_انت
#جے_تعریف_شدہ __NR_select
	SC_ALLOW(__NR_select),
#جے_انت
#جے_تعریف_شدہ __NR_shutdown
	SC_ALLOW(__NR_shutdown),
#جے_انت
#جے_تعریف_شدہ __NR_sigprocmask
	SC_ALLOW(__NR_sigprocmask),
#جے_انت
#جے_تعریف_شدہ __NR_time
	SC_ALLOW(__NR_time),
#جے_انت
#جے_تعریف_شدہ __NR_write
	SC_ALLOW(__NR_write),
#جے_انت
#جے_تعریف_شدہ __NR_writev
	SC_ALLOW(__NR_writev),
#جے_انت
#جے_تعریف_شدہ __NR_getsockopt
	SC_ALLOW(__NR_getsockopt),
#جے_انت
#جے_تعریف_شدہ __NR_getsockname
	SC_ALLOW(__NR_getsockname),
#جے_انت
#جے_تعریف_شدہ __NR_getpeername
	SC_ALLOW(__NR_getpeername),
#جے_انت
#جے_تعریف_شدہ __NR_uname
	SC_ALLOW(__NR_uname),
#جے_انت
#جے_تعریف_شدہ __NR_restart_syscall
	SC_ALLOW(__NR_restart_syscall),
#جے_انت
#جے_تعریف_شدہ __NR_setsockopt
	SC_ALLOW_SETSOCKOPT(IPPROTO_IPV6, IPV6_TCLASS),
	SC_ALLOW_SETSOCKOPT(IPPROTO_IP, IP_TOS),
#جے_انت
#جے_تعریف_شدہ __NR_socketcall
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETPEERNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKOPT),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
	SC_DENY(__NR_socketcall, EACCES),
#جے_انت
#إذا defined(__NR_ioctl) && defined(__s390__)
	/* Allow ioctls for ICA crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, Z90_STAT_حالت_نقاب),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSAMODEXPO),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSACRT),
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSECSENDCPRB),
	/* Allow ioctls for EP11 crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSENDEP11CPRB),
#جے_انت
#إذا defined(__x86_64__) && defined(__ILP32__) && defined(__X32_SYSCALL_BIT)
	/*
	 * On Linux x32, the clock_gettime VDSO falls back to the
	 * x86-64 syscall under some circumstances, e.g.
	 * https://bugs.debian.org/849923
	 */
	SC_ALLOW(__NR_clock_gettime & ~__X32_SYSCALL_BIT),
#جے_انت

	/* Default deny */
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

ساكن ثابت بنية sock_fprog preauth_پروگرام = {
	.len = (بنانشانی چھوٹا)(حجم(preauth_insns)/حجم(preauth_insns[0])),
	.filter = (بنية sock_filter *)preauth_insns,
};

بنية ssh_sandbox {
	صحيح junk;
};

بنية ssh_sandbox *
ssh_sandbox_init(بنية monitor *monitor)
{
	بنية ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing seccomp filter sandbox");
	box = xcalloc(1, حجم(*box));
	أرجع box;
}

#جے_تعریف_شدہ SANDBOX_SECCOMP_FILTER_DEBUG
خارجي بنية monitor *pmonitor;
فراغ mm_log_handler(LogLevel level, صحيح forced, ثابت حرف *پیغام, فراغ *ctx);

ساكن فراغ
ssh_sandbox_violation(صحيح signum, siginfo_t *info, فراغ *void_context)
{
	حرف پیغام[256];

	snprintf(پیغام, حجم(پیغام),
	    "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)",
	    __func__, info->si_arch, info->si_syscall, info->si_call_addr);
	mm_log_handler(SYSLOG_LEVEL_FATAL, 0, پیغام, pmonitor);
	_exit(1);
}

ساكن فراغ
ssh_sandbox_بچہ_debugging(فراغ)
{
	بنية sigaction act;
	sigset_t نقاب;

	debug3_f("installing SIGSYS handler");
	memset(&act, 0, حجم(act));
	sigemptyset(&نقاب);
	sigaddset(&نقاب, SIGSYS);

	act.sa_sigaction = &ssh_sandbox_violation;
	act.sa_flags = SA_SIGINFO;
	إذا (sigaction(SIGSYS, &act, عدم) == -1)
		fatal_f("sigaction(SIGSYS): %s", strerror(errno));
	إذا (sigprocmask(SIG_UNBLOCK, &نقاب, عدم) == -1)
		fatal("%s: sigprocmask(SIGSYS): %s",
		    __func__, strerror(errno));
}
#جے_انت /* SANDBOX_SECCOMP_FILTER_DEBUG */

فراغ
ssh_sandbox_بچہ(بنية ssh_sandbox *box)
{
	بنية rlimit rl_zero, rl_one = {.rlim_cur = 1, .rlim_max = 1};

	/* Set rlimits for completeness if possible. */
	rl_zero.rlim_cur = rl_zero.rlim_max = 0;
	إذا (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
	/*
	 * Cannot use zero for nfds, because poll(2) will fail with
	 * errno=EINVAL if npfds>RLIMIT_NOFILE.
	 */
	إذا (setrlimit(RLIMIT_NOFILE, &rl_one) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
	إذا (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));

#جے_تعریف_شدہ SANDBOX_SECCOMP_FILTER_DEBUG
	ssh_sandbox_بچہ_debugging();
#جے_انت /* SANDBOX_SECCOMP_FILTER_DEBUG */

	debug3_f("setting PR_SET_NO_NEW_PRIVS");
	إذا (prctl(PR_سیٹ_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatal_f("prctl(PR_SET_NO_NEW_PRIVS): %s", strerror(errno));
	debug3_f("attaching seccomp filter program");
	إذا (prctl(PR_سیٹ_SECCOMP, SECCOMP_منوال_FILTER, &preauth_پروگرام) == -1)
		fatal_f("prctl(PR_SET_SECCOMP): %s", strerror(errno));
}

#جے_انت /* SANDBOX_SECCOMP_FILTER */
