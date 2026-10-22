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

#ఒకవేళ 0
/*
 * For older toolchains, it may be necessary to use the kernel
 * headers directly.
 */
#నిర్వచితమైతే SANDBOX_SECCOMP_FILTER_DEBUG
# include <asm/siginfo.h>
# define __have_siginfo_t 1
# define __have_sigval_t 1
# define __have_sigevent_t 1
#అయితే_ముగింపు /* SANDBOX_SECCOMP_FILTER_DEBUG */
#అయితే_ముగింపు

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే SANDBOX_SECCOMP_FILTER

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/resource.h>
#అన్తర్భావ <sys/prctl.h>
#అన్తర్భావ <sys/mman.h>
#అన్తర్భావ <sys/syscall.h>

#అన్తర్భావ <netinet/ip.h>

#అన్తర్భావ <linux/futex.h>
#అన్తర్భావ <linux/net.h>
#అన్తర్భావ <linux/audit.h>
#అన్తర్భావ <linux/filter.h>
#అన్తర్భావ <linux/seccomp.h>
#అన్తర్భావ <elf.h>

#అన్తర్భావ <asm/unistd.h>
#నిర్వచితమైతే __s390__
#అన్తర్భావ <asm/zcrypt.h>
#అయితే_ముగింపు

#అన్తర్భావ <errno.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stddef.h>  /* for offsetof */
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "ssh-sandbox.h"
#అన్తర్భావ "xmalloc.h"

/* Linux seccomp_filter sandbox */
#నిర్వచించు SECCOMP_FILTER_FAIL SECCOMP_RET_KILL

/* Use a signal handler to emit violations when debugging */
#నిర్వచితమైతే SANDBOX_SECCOMP_FILTER_DEBUG
# undef SECCOMP_FILTER_FAIL
# define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#అయితే_ముగింపు /* SANDBOX_SECCOMP_FILTER_DEBUG */

#ఒకవేళ __BYTE_ORDER == __LITTLE_ENDIAN
# define ARG_LO_స్థానభ్రంశం  0
# define ARG_HI_స్థానభ్రంశం  పరిమాణం(uint32_t)
#లేదావేళ __BYTE_ORDER == __BIG_ENDIAN
# define ARG_LO_స్థానభ్రంశం  పరిమాణం(uint32_t)
# define ARG_HI_స్థానభ్రంశం  0
#లేకపోతే
#దోషం "Unknown endianness"
#అయితే_ముగింపు

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#నిర్వచించు SC_DENY(_nr, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#నిర్వచించు SC_ALLOW(_nr) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#నిర్వచించు SC_ALLOW_ARG(_nr, _arg_nr, _arg_val) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 6), \
	/* load and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(నిర్మాణం seccomp_దత్తాంశం, వాదనలు[(_arg_nr)]) + ARG_LO_స్థానభ్రంశం), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_arg_val) & 0xFFFFFFFF), 0, 3), \
	/* load and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(నిర్మాణం seccomp_దత్తాంశం, వాదనలు[(_arg_nr)]) + ARG_HI_స్థానభ్రంశం), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_arg_val) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(నిర్మాణం seccomp_దత్తాంశం, nr))
/* Allow if syscall argument contains only values in mask */
#నిర్వచించు SC_ALLOW_ARG_ముసుగు(_nr, _arg_nr, arg_ముసుగు) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(నిర్మాణం seccomp_దత్తాంశం, వాదనలు[(_arg_nr)]) + ARG_LO_స్థానభ్రంశం), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_ముసుగు) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 4), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(నిర్మాణం seccomp_దత్తాంశం, వాదనలు[(_arg_nr)]) + ARG_HI_స్థానభ్రంశం), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_ముసుగు) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(నిర్మాణం seccomp_దత్తాంశం, nr))
/* Deny unless syscall argument contains only values in mask */
#నిర్వచించు SC_DENY_UNLESS_ARG_ముసుగు(_nr, _arg_nr, arg_ముసుగు, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(నిర్మాణం seccomp_దత్తాంశం, వాదనలు[(_arg_nr)]) + ARG_LO_స్థానభ్రంశం), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_ముసుగు) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 3), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(నిర్మాణం seccomp_దత్తాంశం, వాదనలు[(_arg_nr)]) + ARG_HI_స్థానభ్రంశం), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_ముసుగు) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno)), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(నిర్మాణం seccomp_దత్తాంశం, nr))
#నిర్వచించు SC_DENY_UNLESS_ముసుగు(_nr, _arg_nr, _arg_val, _errno) \
/* Special handling for futex(2) that combines a bitmap and operation number */
#ఒకవేళ defined(__NR_futex) || defined(__NR_futex_time64)
#నిర్వచించు SC_FUTEX_ముసుగు (FUTEX_వ్యక్తిగత_FLAG|FUTEX_CLOCK_REALTIME)
#నిర్వచించు SC_ALLOW_FUTEX_OP(_nr, _op) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(నిర్మాణం seccomp_దత్తాంశం, వాదనలు[1]) + ARG_LO_స్థానభ్రంశం), \
	/* mask off allowed bitmap values, low word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~(SC_FUTEX_ముసుగు & 0xFFFFFFFF)), \
	/* test operation number, low word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ((_op) & 0xFFFFFFFF), 0, 4), \
	/* load syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(నిర్మాణం seccomp_దత్తాంశం, వాదనలు[1]) + ARG_HI_స్థానభ్రంశం), \
	/* mask off allowed bitmap values, high word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)SC_FUTEX_ముసుగు >> 32)) & 0xFFFFFFFF)), \
	/* test operation number, high word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_op) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(నిర్మాణం seccomp_దత్తాంశం, nr))

/* Use this for both __NR_futex and __NR_futex_time64 */
# define SC_FUTEX(_nr) \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_REQUEUE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_CMP_REQUEUE)
#అయితే_ముగింపు /* __NR_futex || __NR_futex_time64 */

#ఒకవేళ defined(__NR_mmap) || defined(__NR_mmap2)
# ifdef MAP_FIXED_NOREPLACE
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_FIXED_NOREPLACE
# లేకపోతే
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED
# endif /* MAP_FIXED_NOREPLACE */
/* Use this for both __NR_mmap and __NR_mmap2 variants */
# define SC_MMAP(_nr) \
	SC_DENY_UNLESS_ARG_ముసుగు(_nr, 3, SC_MMAP_FLAGS, EINVAL), \
	SC_ALLOW_ARG_ముసుగు(_nr, 2, PROT_READ|PROT_WRITE|PROT_NONE)
#అయితే_ముగింపు /* __NR_mmap || __NR_mmap2 */

/* Special handling for setsockopt(2) */
#నిర్వచించు SC_ALLOW_SETSOCKOPT(_level, _optname) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setsockopt, 0, 10), \
	/* load and test level, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(నిర్మాణం seccomp_దత్తాంశం, వాదనలు[1]) + ARG_LO_స్థానభ్రంశం), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_level) & 0xFFFFFFFF), 0, 7), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(నిర్మాణం seccomp_దత్తాంశం, వాదనలు[1]) + ARG_HI_స్థానభ్రంశం), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 5), \
	/* load and test optname, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(నిర్మాణం seccomp_దత్తాంశం, వాదనలు[2]) + ARG_LO_స్థానభ్రంశం), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_optname) & 0xFFFFFFFF), 0, 3), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(నిర్మాణం seccomp_దత్తాంశం, వాదనలు[2]) + ARG_HI_స్థానభ్రంశం), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(నిర్మాణం seccomp_దత్తాంశం, nr))

/* Syscall filtering set for preauth. */
స్థిర స్థిరరాశి నిర్మాణం sock_filter preauth_insns[] = {
	/* Ensure the syscall arch convention is as expected. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(నిర్మాణం seccomp_దత్తాంశం, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
	/* Load the syscall number for checking. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(నిర్మాణం seccomp_దత్తాంశం, nr)),

	/* Syscalls to non-fatally deny */
#నిర్వచితమైతే __NR_lstat
	SC_DENY(__NR_lstat, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_lstat64
	SC_DENY(__NR_lstat64, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_fstat
	SC_DENY(__NR_fstat, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_fstat64
	SC_DENY(__NR_fstat64, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_fstatat64
	SC_DENY(__NR_fstatat64, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_open
	SC_DENY(__NR_open, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_openat
	SC_DENY(__NR_openat, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_newfstatat
	SC_DENY(__NR_newfstatat, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_stat
	SC_DENY(__NR_stat, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_stat64
	SC_DENY(__NR_stat64, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_shmget
	SC_DENY(__NR_shmget, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_shmat
	SC_DENY(__NR_shmat, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_shmdt
	SC_DENY(__NR_shmdt, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_ipc
	SC_DENY(__NR_ipc, EACCES),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_statx
	SC_DENY(__NR_statx, EACCES),
#అయితే_ముగింపు

	/* Syscalls to permit */
#నిర్వచితమైతే __NR_brk
	SC_ALLOW(__NR_brk),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_clock_gettime
	SC_ALLOW(__NR_clock_gettime),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_clock_gettime64
	SC_ALLOW(__NR_clock_gettime64),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_close
	SC_ALLOW(__NR_close),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_exit
	SC_ALLOW(__NR_exit),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_exit_group
	SC_ALLOW(__NR_exit_group),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_futex
	SC_FUTEX(__NR_futex),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_futex_time64
	SC_FUTEX(__NR_futex_time64),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_geteuid
	SC_ALLOW(__NR_geteuid),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_geteuid32
	SC_ALLOW(__NR_geteuid32),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_getpgid
	SC_ALLOW(__NR_getpgid),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_getpid
	SC_ALLOW(__NR_getpid),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_getrandom
	SC_ALLOW(__NR_getrandom),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_gettid
	SC_ALLOW(__NR_gettid),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_gettimeofday
	SC_ALLOW(__NR_gettimeofday),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_getuid
	SC_ALLOW(__NR_getuid),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_getuid32
	SC_ALLOW(__NR_getuid32),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_madvise
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
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_mmap
	SC_MMAP(__NR_mmap),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_mmap2
	SC_MMAP(__NR_mmap2),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_mprotect
	SC_ALLOW_ARG_ముసుగు(__NR_mprotect, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_mremap
	SC_ALLOW_ARG_ముసుగు(__NR_mremap, 3, MREMAP_MAYMOVE),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_munmap
	SC_ALLOW(__NR_munmap),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_nanosleep
	SC_ALLOW(__NR_nanosleep),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_clock_nanosleep
	SC_ALLOW(__NR_clock_nanosleep),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_clock_nanosleep_time64
	SC_ALLOW(__NR_clock_nanosleep_time64),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR__newselect
	SC_ALLOW(__NR__newselect),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_ppoll
	SC_ALLOW(__NR_ppoll),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_ppoll_time64
	SC_ALLOW(__NR_ppoll_time64),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_poll
	SC_ALLOW(__NR_poll),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_pselect6
	SC_ALLOW(__NR_pselect6),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_pselect6_time64
	SC_ALLOW(__NR_pselect6_time64),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_read
	SC_ALLOW(__NR_read),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_riscv_hwprobe
	SC_ALLOW(__NR_riscv_hwprobe),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_rt_sigprocmask
	SC_ALLOW(__NR_rt_sigprocmask),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_select
	SC_ALLOW(__NR_select),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_shutdown
	SC_ALLOW(__NR_shutdown),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_sigprocmask
	SC_ALLOW(__NR_sigprocmask),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_time
	SC_ALLOW(__NR_time),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_write
	SC_ALLOW(__NR_write),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_writev
	SC_ALLOW(__NR_writev),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_getsockopt
	SC_ALLOW(__NR_getsockopt),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_getsockname
	SC_ALLOW(__NR_getsockname),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_getpeername
	SC_ALLOW(__NR_getpeername),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_uname
	SC_ALLOW(__NR_uname),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_restart_syscall
	SC_ALLOW(__NR_restart_syscall),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_setsockopt
	SC_ALLOW_SETSOCKOPT(IPPROTO_IPV6, IPV6_TCLASS),
	SC_ALLOW_SETSOCKOPT(IPPROTO_IP, IP_TOS),
#అయితే_ముగింపు
#నిర్వచితమైతే __NR_socketcall
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETPEERNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKOPT),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
	SC_DENY(__NR_socketcall, EACCES),
#అయితే_ముగింపు
#ఒకవేళ defined(__NR_ioctl) && defined(__s390__)
	/* Allow ioctls for ICA crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, Z90_STAT_స్థితి_ముసుగు),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSAMODEXPO),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSACRT),
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSECSENDCPRB),
	/* Allow ioctls for EP11 crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSENDEP11CPRB),
#అయితే_ముగింపు
#ఒకవేళ defined(__x86_64__) && defined(__ILP32__) && defined(__X32_SYSCALL_BIT)
	/*
	 * On Linux x32, the clock_gettime VDSO falls back to the
	 * x86-64 syscall under some circumstances, e.g.
	 * https://bugs.debian.org/849923
	 */
	SC_ALLOW(__NR_clock_gettime & ~__X32_SYSCALL_BIT),
#అయితే_ముగింపు

	/* Default deny */
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

స్థిర స్థిరరాశి నిర్మాణం sock_fprog preauth_కార్యక్రమం = {
	.len = (గుర్తులేని పొట్టి)(పరిమాణం(preauth_insns)/పరిమాణం(preauth_insns[0])),
	.filter = (నిర్మాణం sock_filter *)preauth_insns,
};

నిర్మాణం ssh_sandbox {
	పూర్ణాంకం junk;
};

నిర్మాణం ssh_sandbox *
ssh_sandbox_init(నిర్మాణం monitor *monitor)
{
	నిర్మాణం ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing seccomp filter sandbox");
	box = xcalloc(1, పరిమాణం(*box));
	తిరిగి box;
}

#నిర్వచితమైతే SANDBOX_SECCOMP_FILTER_DEBUG
బాహ్య నిర్మాణం monitor *pmonitor;
శూన్య mm_log_handler(LogLevel level, పూర్ణాంకం forced, స్థిరరాశి అక్షరం *సందేశం, శూన్య *ctx);

స్థిర శూన్య
ssh_sandbox_violation(పూర్ణాంకం signum, siginfo_t *info, శూన్య *void_context)
{
	అక్షరం సందేశం[256];

	snprintf(సందేశం, పరిమాణం(సందేశం),
	    "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)",
	    __func__, info->si_arch, info->si_syscall, info->si_call_addr);
	mm_log_handler(SYSLOG_LEVEL_FATAL, 0, సందేశం, pmonitor);
	_exit(1);
}

స్థిర శూన్య
ssh_sandbox_బిడ్డ_debugging(శూన్య)
{
	నిర్మాణం sigaction act;
	sigset_t ముసుగు;

	debug3_f("installing SIGSYS handler");
	memset(&act, 0, పరిమాణం(act));
	sigemptyset(&ముసుగు);
	sigaddset(&ముసుగు, SIGSYS);

	act.sa_sigaction = &ssh_sandbox_violation;
	act.sa_flags = SA_SIGINFO;
	ఒకవేళ (sigaction(SIGSYS, &act, ఖాళీ) == -1)
		fatal_f("sigaction(SIGSYS): %s", strerror(errno));
	ఒకవేళ (sigprocmask(SIG_UNBLOCK, &ముసుగు, ఖాళీ) == -1)
		fatal("%s: sigprocmask(SIGSYS): %s",
		    __func__, strerror(errno));
}
#అయితే_ముగింపు /* SANDBOX_SECCOMP_FILTER_DEBUG */

శూన్య
ssh_sandbox_బిడ్డ(నిర్మాణం ssh_sandbox *box)
{
	నిర్మాణం rlimit rl_zero, rl_one = {.rlim_cur = 1, .rlim_max = 1};

	/* Set rlimits for completeness if possible. */
	rl_zero.rlim_cur = rl_zero.rlim_max = 0;
	ఒకవేళ (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
	/*
	 * Cannot use zero for nfds, because poll(2) will fail with
	 * errno=EINVAL if npfds>RLIMIT_NOFILE.
	 */
	ఒకవేళ (setrlimit(RLIMIT_NOFILE, &rl_one) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
	ఒకవేళ (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));

#నిర్వచితమైతే SANDBOX_SECCOMP_FILTER_DEBUG
	ssh_sandbox_బిడ్డ_debugging();
#అయితే_ముగింపు /* SANDBOX_SECCOMP_FILTER_DEBUG */

	debug3_f("setting PR_SET_NO_NEW_PRIVS");
	ఒకవేళ (prctl(PR_సమితి_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatal_f("prctl(PR_SET_NO_NEW_PRIVS): %s", strerror(errno));
	debug3_f("attaching seccomp filter program");
	ఒకవేళ (prctl(PR_సమితి_SECCOMP, SECCOMP_బహుళకం_FILTER, &preauth_కార్యక్రమం) == -1)
		fatal_f("prctl(PR_SET_SECCOMP): %s", strerror(errno));
}

#అయితే_ముగింపు /* SANDBOX_SECCOMP_FILTER */
