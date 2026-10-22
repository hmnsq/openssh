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
#جيڪڏهن_وصف_ٿيل SANDBOX_SECCOMP_FILTER_DEBUG
# include <asm/siginfo.h>
# define __have_siginfo_t 1
# define __have_sigval_t 1
# define __have_sigevent_t 1
#جيڪڏهن_پورو /* SANDBOX_SECCOMP_FILTER_DEBUG */
#جيڪڏهن_پورو

#ضمن "includes.h"

#جيڪڏهن_وصف_ٿيل SANDBOX_SECCOMP_FILTER

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
#جيڪڏهن_وصف_ٿيل __s390__
#ضمن <asm/zcrypt.h>
#جيڪڏهن_پورو

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
#وصف_ڪريو SECCOMP_FILTER_FAIL SECCOMP_RET_KILL

/* Use a signal handler to emit violations when debugging */
#جيڪڏهن_وصف_ٿيل SANDBOX_SECCOMP_FILTER_DEBUG
# undef SECCOMP_FILTER_FAIL
# define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#جيڪڏهن_پورو /* SANDBOX_SECCOMP_FILTER_DEBUG */

#إذا __BYTE_ORDER == __LITTLE_ENDIAN
# define ARG_LO_وٿي  0
# define ARG_HI_وٿي  حجم(uint32_t)
#وإلاإذا __BYTE_ORDER == __BIG_ENDIAN
# define ARG_LO_وٿي  حجم(uint32_t)
# define ARG_HI_وٿي  0
#وإلا
#غلطي "Unknown endianness"
#جيڪڏهن_پورو

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#وصف_ڪريو SC_DENY(_nr, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#وصف_ڪريو SC_ALLOW(_nr) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#وصف_ڪريو SC_ALLOW_ARG(_nr, _arg_nr, _arg_val) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 6), \
	/* load and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_معلومات, دليلون[(_arg_nr)]) + ARG_LO_وٿي), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_arg_val) & 0xFFFFFFFF), 0, 3), \
	/* load and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_معلومات, دليلون[(_arg_nr)]) + ARG_HI_وٿي), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_arg_val) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(بنية seccomp_معلومات, nr))
/* Allow if syscall argument contains only values in mask */
#وصف_ڪريو SC_ALLOW_ARG_نقاب(_nr, _arg_nr, arg_نقاب) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_معلومات, دليلون[(_arg_nr)]) + ARG_LO_وٿي), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_نقاب) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 4), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_معلومات, دليلون[(_arg_nr)]) + ARG_HI_وٿي), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_نقاب) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(بنية seccomp_معلومات, nr))
/* Deny unless syscall argument contains only values in mask */
#وصف_ڪريو SC_DENY_UNLESS_ARG_نقاب(_nr, _arg_nr, arg_نقاب, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_معلومات, دليلون[(_arg_nr)]) + ARG_LO_وٿي), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_نقاب) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 3), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_معلومات, دليلون[(_arg_nr)]) + ARG_HI_وٿي), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_نقاب) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno)), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(بنية seccomp_معلومات, nr))
#وصف_ڪريو SC_DENY_UNLESS_نقاب(_nr, _arg_nr, _arg_val, _errno) \
/* Special handling for futex(2) that combines a bitmap and operation number */
#إذا defined(__NR_futex) || defined(__NR_futex_time64)
#وصف_ڪريو SC_FUTEX_نقاب (FUTEX_ذاتي_FLAG|FUTEX_CLOCK_REALTIME)
#وصف_ڪريو SC_ALLOW_FUTEX_OP(_nr, _op) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_معلومات, دليلون[1]) + ARG_LO_وٿي), \
	/* mask off allowed bitmap values, low word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~(SC_FUTEX_نقاب & 0xFFFFFFFF)), \
	/* test operation number, low word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ((_op) & 0xFFFFFFFF), 0, 4), \
	/* load syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_معلومات, دليلون[1]) + ARG_HI_وٿي), \
	/* mask off allowed bitmap values, high word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)SC_FUTEX_نقاب >> 32)) & 0xFFFFFFFF)), \
	/* test operation number, high word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_op) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(بنية seccomp_معلومات, nr))

/* Use this for both __NR_futex and __NR_futex_time64 */
# define SC_FUTEX(_nr) \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_REQUEUE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_CMP_REQUEUE)
#جيڪڏهن_پورو /* __NR_futex || __NR_futex_time64 */

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
#جيڪڏهن_پورو /* __NR_mmap || __NR_mmap2 */

/* Special handling for setsockopt(2) */
#وصف_ڪريو SC_ALLOW_SETSOCKOPT(_level, _optname) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setsockopt, 0, 10), \
	/* load and test level, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_معلومات, دليلون[1]) + ARG_LO_وٿي), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_level) & 0xFFFFFFFF), 0, 7), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_معلومات, دليلون[1]) + ARG_HI_وٿي), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 5), \
	/* load and test optname, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_معلومات, دليلون[2]) + ARG_LO_وٿي), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_optname) & 0xFFFFFFFF), 0, 3), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(بنية seccomp_معلومات, دليلون[2]) + ARG_HI_وٿي), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(بنية seccomp_معلومات, nr))

/* Syscall filtering set for preauth. */
ساكن ثابت بنية sock_filter preauth_insns[] = {
	/* Ensure the syscall arch convention is as expected. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(بنية seccomp_معلومات, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
	/* Load the syscall number for checking. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(بنية seccomp_معلومات, nr)),

	/* Syscalls to non-fatally deny */
#جيڪڏهن_وصف_ٿيل __NR_lstat
	SC_DENY(__NR_lstat, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_lstat64
	SC_DENY(__NR_lstat64, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_fstat
	SC_DENY(__NR_fstat, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_fstat64
	SC_DENY(__NR_fstat64, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_fstatat64
	SC_DENY(__NR_fstatat64, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_open
	SC_DENY(__NR_open, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_openat
	SC_DENY(__NR_openat, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_newfstatat
	SC_DENY(__NR_newfstatat, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_stat
	SC_DENY(__NR_stat, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_stat64
	SC_DENY(__NR_stat64, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_shmget
	SC_DENY(__NR_shmget, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_shmat
	SC_DENY(__NR_shmat, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_shmdt
	SC_DENY(__NR_shmdt, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_ipc
	SC_DENY(__NR_ipc, EACCES),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_statx
	SC_DENY(__NR_statx, EACCES),
#جيڪڏهن_پورو

	/* Syscalls to permit */
#جيڪڏهن_وصف_ٿيل __NR_brk
	SC_ALLOW(__NR_brk),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_clock_gettime
	SC_ALLOW(__NR_clock_gettime),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_clock_gettime64
	SC_ALLOW(__NR_clock_gettime64),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_close
	SC_ALLOW(__NR_close),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_exit
	SC_ALLOW(__NR_exit),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_exit_group
	SC_ALLOW(__NR_exit_group),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_futex
	SC_FUTEX(__NR_futex),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_futex_time64
	SC_FUTEX(__NR_futex_time64),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_geteuid
	SC_ALLOW(__NR_geteuid),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_geteuid32
	SC_ALLOW(__NR_geteuid32),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_getpgid
	SC_ALLOW(__NR_getpgid),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_getpid
	SC_ALLOW(__NR_getpid),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_getrandom
	SC_ALLOW(__NR_getrandom),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_gettid
	SC_ALLOW(__NR_gettid),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_gettimeofday
	SC_ALLOW(__NR_gettimeofday),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_getuid
	SC_ALLOW(__NR_getuid),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_getuid32
	SC_ALLOW(__NR_getuid32),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_madvise
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
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_mmap
	SC_MMAP(__NR_mmap),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_mmap2
	SC_MMAP(__NR_mmap2),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_mprotect
	SC_ALLOW_ARG_نقاب(__NR_mprotect, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_mremap
	SC_ALLOW_ARG_نقاب(__NR_mremap, 3, MREMAP_MAYMOVE),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_munmap
	SC_ALLOW(__NR_munmap),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_nanosleep
	SC_ALLOW(__NR_nanosleep),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_clock_nanosleep
	SC_ALLOW(__NR_clock_nanosleep),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_clock_nanosleep_time64
	SC_ALLOW(__NR_clock_nanosleep_time64),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR__newselect
	SC_ALLOW(__NR__newselect),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_ppoll
	SC_ALLOW(__NR_ppoll),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_ppoll_time64
	SC_ALLOW(__NR_ppoll_time64),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_poll
	SC_ALLOW(__NR_poll),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_pselect6
	SC_ALLOW(__NR_pselect6),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_pselect6_time64
	SC_ALLOW(__NR_pselect6_time64),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_read
	SC_ALLOW(__NR_read),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_riscv_hwprobe
	SC_ALLOW(__NR_riscv_hwprobe),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_rt_sigprocmask
	SC_ALLOW(__NR_rt_sigprocmask),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_select
	SC_ALLOW(__NR_select),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_shutdown
	SC_ALLOW(__NR_shutdown),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_sigprocmask
	SC_ALLOW(__NR_sigprocmask),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_time
	SC_ALLOW(__NR_time),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_write
	SC_ALLOW(__NR_write),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_writev
	SC_ALLOW(__NR_writev),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_getsockopt
	SC_ALLOW(__NR_getsockopt),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_getsockname
	SC_ALLOW(__NR_getsockname),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_getpeername
	SC_ALLOW(__NR_getpeername),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_uname
	SC_ALLOW(__NR_uname),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_restart_syscall
	SC_ALLOW(__NR_restart_syscall),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_setsockopt
	SC_ALLOW_SETSOCKOPT(IPPROTO_IPV6, IPV6_TCLASS),
	SC_ALLOW_SETSOCKOPT(IPPROTO_IP, IP_TOS),
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل __NR_socketcall
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETPEERNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKOPT),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
	SC_DENY(__NR_socketcall, EACCES),
#جيڪڏهن_پورو
#إذا defined(__NR_ioctl) && defined(__s390__)
	/* Allow ioctls for ICA crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, Z90_STAT_حالت_نقاب),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSAMODEXPO),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSACRT),
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSECSENDCPRB),
	/* Allow ioctls for EP11 crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSENDEP11CPRB),
#جيڪڏهن_پورو
#إذا defined(__x86_64__) && defined(__ILP32__) && defined(__X32_SYSCALL_BIT)
	/*
	 * On Linux x32, the clock_gettime VDSO falls back to the
	 * x86-64 syscall under some circumstances, e.g.
	 * https://bugs.debian.org/849923
	 */
	SC_ALLOW(__NR_clock_gettime & ~__X32_SYSCALL_BIT),
#جيڪڏهن_پورو

	/* Default deny */
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

ساكن ثابت بنية sock_fprog preauth_پروگرام = {
	.len = (بنانشان ننڍو)(حجم(preauth_insns)/حجم(preauth_insns[0])),
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

#جيڪڏهن_وصف_ٿيل SANDBOX_SECCOMP_FILTER_DEBUG
خارجي بنية monitor *pmonitor;
فراغ mm_log_handler(LogLevel level, صحيح forced, ثابت حرف *نياپو, فراغ *ctx);

ساكن فراغ
ssh_sandbox_violation(صحيح signum, siginfo_t *info, فراغ *void_context)
{
	حرف نياپو[256];

	snprintf(نياپو, حجم(نياپو),
	    "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)",
	    __func__, info->si_arch, info->si_syscall, info->si_call_addr);
	mm_log_handler(SYSLOG_LEVEL_FATAL, 0, نياپو, pmonitor);
	_exit(1);
}

ساكن فراغ
ssh_sandbox_ٻار_debugging(فراغ)
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
#جيڪڏهن_پورو /* SANDBOX_SECCOMP_FILTER_DEBUG */

فراغ
ssh_sandbox_ٻار(بنية ssh_sandbox *box)
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

#جيڪڏهن_وصف_ٿيل SANDBOX_SECCOMP_FILTER_DEBUG
	ssh_sandbox_ٻار_debugging();
#جيڪڏهن_پورو /* SANDBOX_SECCOMP_FILTER_DEBUG */

	debug3_f("setting PR_SET_NO_NEW_PRIVS");
	إذا (prctl(PR_سيٽ_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatal_f("prctl(PR_SET_NO_NEW_PRIVS): %s", strerror(errno));
	debug3_f("attaching seccomp filter program");
	إذا (prctl(PR_سيٽ_SECCOMP, SECCOMP_گهڻائي_FILTER, &preauth_پروگرام) == -1)
		fatal_f("prctl(PR_SET_SECCOMP): %s", strerror(errno));
}

#جيڪڏهن_پورو /* SANDBOX_SECCOMP_FILTER */
