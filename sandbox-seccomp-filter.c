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

#यदि 0
/*
 * For older toolchains, it may be necessary to use the kernel
 * headers directly.
 */
#यदि_परिभाषितम् SANDBOX_SECCOMP_FILTER_DEBUG
# include <asm/siginfo.h>
# define __have_siginfo_t 1
# define __have_sigval_t 1
# define __have_sigevent_t 1
#यदि_अन्तः /* SANDBOX_SECCOMP_FILTER_DEBUG */
#यदि_अन्तः

#अन्तर्भाव "includes.h"

#यदि_परिभाषितम् SANDBOX_SECCOMP_FILTER

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/resource.h>
#अन्तर्भाव <sys/prctl.h>
#अन्तर्भाव <sys/mman.h>
#अन्तर्भाव <sys/syscall.h>

#अन्तर्भाव <netinet/ip.h>

#अन्तर्भाव <linux/futex.h>
#अन्तर्भाव <linux/net.h>
#अन्तर्भाव <linux/audit.h>
#अन्तर्भाव <linux/filter.h>
#अन्तर्भाव <linux/seccomp.h>
#अन्तर्भाव <elf.h>

#अन्तर्भाव <asm/unistd.h>
#यदि_परिभाषितम् __s390__
#अन्तर्भाव <asm/zcrypt.h>
#यदि_अन्तः

#अन्तर्भाव <errno.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stddef.h>  /* for offsetof */
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "ssh-sandbox.h"
#अन्तर्भाव "xmalloc.h"

/* Linux seccomp_filter sandbox */
#परिभाषय SECCOMP_FILTER_FAIL SECCOMP_RET_KILL

/* Use a signal handler to emit violations when debugging */
#यदि_परिभाषितम् SANDBOX_SECCOMP_FILTER_DEBUG
# undef SECCOMP_FILTER_FAIL
# define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#यदि_अन्तः /* SANDBOX_SECCOMP_FILTER_DEBUG */

#यदि __BYTE_ORDER == __LITTLE_ENDIAN
# define ARG_LO_विस्थापनम्  0
# define ARG_HI_विस्थापनम्  परिमाण(uint32_t)
#नोचेद्यदि __BYTE_ORDER == __BIG_ENDIAN
# define ARG_LO_विस्थापनम्  परिमाण(uint32_t)
# define ARG_HI_विस्थापनम्  0
#अन्यथा
#दोषः "Unknown endianness"
#यदि_अन्तः

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#परिभाषय SC_DENY(_nr, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#परिभाषय SC_ALLOW(_nr) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#परिभाषय SC_ALLOW_ARG(_nr, _arg_nr, _arg_val) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 6), \
	/* load and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(संरचना seccomp_दत्त, तर्काः[(_arg_nr)]) + ARG_LO_विस्थापनम्), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_arg_val) & 0xFFFFFFFF), 0, 3), \
	/* load and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(संरचना seccomp_दत्त, तर्काः[(_arg_nr)]) + ARG_HI_विस्थापनम्), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_arg_val) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(संरचना seccomp_दत्त, nr))
/* Allow if syscall argument contains only values in mask */
#परिभाषय SC_ALLOW_ARG_आवरणम्(_nr, _arg_nr, arg_आवरणम्) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(संरचना seccomp_दत्त, तर्काः[(_arg_nr)]) + ARG_LO_विस्थापनम्), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_आवरणम्) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 4), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(संरचना seccomp_दत्त, तर्काः[(_arg_nr)]) + ARG_HI_विस्थापनम्), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_आवरणम्) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(संरचना seccomp_दत्त, nr))
/* Deny unless syscall argument contains only values in mask */
#परिभाषय SC_DENY_UNLESS_ARG_आवरणम्(_nr, _arg_nr, arg_आवरणम्, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(संरचना seccomp_दत्त, तर्काः[(_arg_nr)]) + ARG_LO_विस्थापनम्), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_आवरणम्) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 3), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(संरचना seccomp_दत्त, तर्काः[(_arg_nr)]) + ARG_HI_विस्थापनम्), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_आवरणम्) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno)), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(संरचना seccomp_दत्त, nr))
#परिभाषय SC_DENY_UNLESS_आवरणम्(_nr, _arg_nr, _arg_val, _errno) \
/* Special handling for futex(2) that combines a bitmap and operation number */
#यदि defined(__NR_futex) || defined(__NR_futex_time64)
#परिभाषय SC_FUTEX_आवरणम् (FUTEX_वैयक्तिकम्_FLAG|FUTEX_CLOCK_REALTIME)
#परिभाषय SC_ALLOW_FUTEX_OP(_nr, _op) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(संरचना seccomp_दत्त, तर्काः[1]) + ARG_LO_विस्थापनम्), \
	/* mask off allowed bitmap values, low word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~(SC_FUTEX_आवरणम् & 0xFFFFFFFF)), \
	/* test operation number, low word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ((_op) & 0xFFFFFFFF), 0, 4), \
	/* load syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(संरचना seccomp_दत्त, तर्काः[1]) + ARG_HI_विस्थापनम्), \
	/* mask off allowed bitmap values, high word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)SC_FUTEX_आवरणम् >> 32)) & 0xFFFFFFFF)), \
	/* test operation number, high word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_op) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(संरचना seccomp_दत्त, nr))

/* Use this for both __NR_futex and __NR_futex_time64 */
# define SC_FUTEX(_nr) \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_REQUEUE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_CMP_REQUEUE)
#यदि_अन्तः /* __NR_futex || __NR_futex_time64 */

#यदि defined(__NR_mmap) || defined(__NR_mmap2)
# ifdef MAP_FIXED_NOREPLACE
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_FIXED_NOREPLACE
# अन्यथा
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED
# endif /* MAP_FIXED_NOREPLACE */
/* Use this for both __NR_mmap and __NR_mmap2 variants */
# define SC_MMAP(_nr) \
	SC_DENY_UNLESS_ARG_आवरणम्(_nr, 3, SC_MMAP_FLAGS, EINVAL), \
	SC_ALLOW_ARG_आवरणम्(_nr, 2, PROT_READ|PROT_WRITE|PROT_NONE)
#यदि_अन्तः /* __NR_mmap || __NR_mmap2 */

/* Special handling for setsockopt(2) */
#परिभाषय SC_ALLOW_SETSOCKOPT(_level, _optname) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setsockopt, 0, 10), \
	/* load and test level, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(संरचना seccomp_दत्त, तर्काः[1]) + ARG_LO_विस्थापनम्), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_level) & 0xFFFFFFFF), 0, 7), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(संरचना seccomp_दत्त, तर्काः[1]) + ARG_HI_विस्थापनम्), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 5), \
	/* load and test optname, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(संरचना seccomp_दत्त, तर्काः[2]) + ARG_LO_विस्थापनम्), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_optname) & 0xFFFFFFFF), 0, 3), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(संरचना seccomp_दत्त, तर्काः[2]) + ARG_HI_विस्थापनम्), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(संरचना seccomp_दत्त, nr))

/* Syscall filtering set for preauth. */
स्थिर ध्रुव संरचना sock_filter preauth_insns[] = {
	/* Ensure the syscall arch convention is as expected. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(संरचना seccomp_दत्त, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
	/* Load the syscall number for checking. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(संरचना seccomp_दत्त, nr)),

	/* Syscalls to non-fatally deny */
#यदि_परिभाषितम् __NR_lstat
	SC_DENY(__NR_lstat, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_lstat64
	SC_DENY(__NR_lstat64, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_fstat
	SC_DENY(__NR_fstat, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_fstat64
	SC_DENY(__NR_fstat64, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_fstatat64
	SC_DENY(__NR_fstatat64, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_open
	SC_DENY(__NR_open, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_openat
	SC_DENY(__NR_openat, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_newfstatat
	SC_DENY(__NR_newfstatat, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_stat
	SC_DENY(__NR_stat, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_stat64
	SC_DENY(__NR_stat64, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_shmget
	SC_DENY(__NR_shmget, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_shmat
	SC_DENY(__NR_shmat, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_shmdt
	SC_DENY(__NR_shmdt, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_ipc
	SC_DENY(__NR_ipc, EACCES),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_statx
	SC_DENY(__NR_statx, EACCES),
#यदि_अन्तः

	/* Syscalls to permit */
#यदि_परिभाषितम् __NR_brk
	SC_ALLOW(__NR_brk),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_clock_gettime
	SC_ALLOW(__NR_clock_gettime),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_clock_gettime64
	SC_ALLOW(__NR_clock_gettime64),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_close
	SC_ALLOW(__NR_close),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_exit
	SC_ALLOW(__NR_exit),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_exit_group
	SC_ALLOW(__NR_exit_group),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_futex
	SC_FUTEX(__NR_futex),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_futex_time64
	SC_FUTEX(__NR_futex_time64),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_geteuid
	SC_ALLOW(__NR_geteuid),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_geteuid32
	SC_ALLOW(__NR_geteuid32),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_getpgid
	SC_ALLOW(__NR_getpgid),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_getpid
	SC_ALLOW(__NR_getpid),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_getrandom
	SC_ALLOW(__NR_getrandom),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_gettid
	SC_ALLOW(__NR_gettid),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_gettimeofday
	SC_ALLOW(__NR_gettimeofday),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_getuid
	SC_ALLOW(__NR_getuid),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_getuid32
	SC_ALLOW(__NR_getuid32),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_madvise
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
#यदि_अन्तः
#यदि_परिभाषितम् __NR_mmap
	SC_MMAP(__NR_mmap),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_mmap2
	SC_MMAP(__NR_mmap2),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_mprotect
	SC_ALLOW_ARG_आवरणम्(__NR_mprotect, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_mremap
	SC_ALLOW_ARG_आवरणम्(__NR_mremap, 3, MREMAP_MAYMOVE),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_munmap
	SC_ALLOW(__NR_munmap),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_nanosleep
	SC_ALLOW(__NR_nanosleep),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_clock_nanosleep
	SC_ALLOW(__NR_clock_nanosleep),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_clock_nanosleep_time64
	SC_ALLOW(__NR_clock_nanosleep_time64),
#यदि_अन्तः
#यदि_परिभाषितम् __NR__newselect
	SC_ALLOW(__NR__newselect),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_ppoll
	SC_ALLOW(__NR_ppoll),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_ppoll_time64
	SC_ALLOW(__NR_ppoll_time64),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_poll
	SC_ALLOW(__NR_poll),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_pselect6
	SC_ALLOW(__NR_pselect6),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_pselect6_time64
	SC_ALLOW(__NR_pselect6_time64),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_read
	SC_ALLOW(__NR_read),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_riscv_hwprobe
	SC_ALLOW(__NR_riscv_hwprobe),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_rt_sigprocmask
	SC_ALLOW(__NR_rt_sigprocmask),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_select
	SC_ALLOW(__NR_select),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_shutdown
	SC_ALLOW(__NR_shutdown),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_sigprocmask
	SC_ALLOW(__NR_sigprocmask),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_time
	SC_ALLOW(__NR_time),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_write
	SC_ALLOW(__NR_write),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_writev
	SC_ALLOW(__NR_writev),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_getsockopt
	SC_ALLOW(__NR_getsockopt),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_getsockname
	SC_ALLOW(__NR_getsockname),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_getpeername
	SC_ALLOW(__NR_getpeername),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_uname
	SC_ALLOW(__NR_uname),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_restart_syscall
	SC_ALLOW(__NR_restart_syscall),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_setsockopt
	SC_ALLOW_SETSOCKOPT(IPPROTO_IPV6, IPV6_TCLASS),
	SC_ALLOW_SETSOCKOPT(IPPROTO_IP, IP_TOS),
#यदि_अन्तः
#यदि_परिभाषितम् __NR_socketcall
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETPEERNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKOPT),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
	SC_DENY(__NR_socketcall, EACCES),
#यदि_अन्तः
#यदि defined(__NR_ioctl) && defined(__s390__)
	/* Allow ioctls for ICA crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, Z90_STAT_स्थितिः_आवरणम्),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSAMODEXPO),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSACRT),
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSECSENDCPRB),
	/* Allow ioctls for EP11 crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSENDEP11CPRB),
#यदि_अन्तः
#यदि defined(__x86_64__) && defined(__ILP32__) && defined(__X32_SYSCALL_BIT)
	/*
	 * On Linux x32, the clock_gettime VDSO falls back to the
	 * x86-64 syscall under some circumstances, e.g.
	 * https://bugs.debian.org/849923
	 */
	SC_ALLOW(__NR_clock_gettime & ~__X32_SYSCALL_BIT),
#यदि_अन्तः

	/* Default deny */
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

स्थिर ध्रुव संरचना sock_fprog preauth_क्रमादेशः = {
	.len = (अचिह्नित ह्रस्व)(परिमाण(preauth_insns)/परिमाण(preauth_insns[0])),
	.filter = (संरचना sock_filter *)preauth_insns,
};

संरचना ssh_sandbox {
	पूर्णाङ्क junk;
};

संरचना ssh_sandbox *
ssh_sandbox_init(संरचना monitor *monitor)
{
	संरचना ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing seccomp filter sandbox");
	box = xcalloc(1, परिमाण(*box));
	प्रत्यागम box;
}

#यदि_परिभाषितम् SANDBOX_SECCOMP_FILTER_DEBUG
बाह्य संरचना monitor *pmonitor;
शून्य mm_log_handler(LogLevel level, पूर्णाङ्क forced, ध्रुव वर्ण *सन्देशः, शून्य *ctx);

स्थिर शून्य
ssh_sandbox_violation(पूर्णाङ्क signum, siginfo_t *info, शून्य *void_context)
{
	वर्ण सन्देशः[256];

	snprintf(सन्देशः, परिमाण(सन्देशः),
	    "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)",
	    __func__, info->si_arch, info->si_syscall, info->si_call_addr);
	mm_log_handler(SYSLOG_LEVEL_FATAL, 0, सन्देशः, pmonitor);
	_exit(1);
}

स्थिर शून्य
ssh_sandbox_child_debugging(शून्य)
{
	संरचना sigaction act;
	sigset_t आवरणम्;

	debug3_f("installing SIGSYS handler");
	स्मृतिं_पूरय(&act, 0, परिमाण(act));
	sigemptyset(&आवरणम्);
	sigaddset(&आवरणम्, SIGSYS);

	act.sa_sigaction = &ssh_sandbox_violation;
	act.sa_flags = SA_SIGINFO;
	यदि (sigaction(SIGSYS, &act, रिक्त) == -1)
		fatal_f("sigaction(SIGSYS): %s", strerror(errno));
	यदि (sigprocmask(SIG_UNBLOCK, &आवरणम्, रिक्त) == -1)
		fatal("%s: sigprocmask(SIGSYS): %s",
		    __func__, strerror(errno));
}
#यदि_अन्तः /* SANDBOX_SECCOMP_FILTER_DEBUG */

शून्य
ssh_sandbox_child(संरचना ssh_sandbox *box)
{
	संरचना rlimit rl_zero, rl_one = {.rlim_cur = 1, .rlim_max = 1};

	/* Set rlimits for completeness if possible. */
	rl_zero.rlim_cur = rl_zero.rlim_max = 0;
	यदि (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
	/*
	 * Cannot use zero for nfds, because poll(2) will fail with
	 * errno=EINVAL if npfds>RLIMIT_NOFILE.
	 */
	यदि (setrlimit(RLIMIT_NOFILE, &rl_one) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
	यदि (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));

#यदि_परिभाषितम् SANDBOX_SECCOMP_FILTER_DEBUG
	ssh_sandbox_child_debugging();
#यदि_अन्तः /* SANDBOX_SECCOMP_FILTER_DEBUG */

	debug3_f("setting PR_SET_NO_NEW_PRIVS");
	यदि (prctl(PR_समुच्चयः_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatal_f("prctl(PR_SET_NO_NEW_PRIVS): %s", strerror(errno));
	debug3_f("attaching seccomp filter program");
	यदि (prctl(PR_समुच्चयः_SECCOMP, SECCOMP_बहुलकम्_FILTER, &preauth_क्रमादेशः) == -1)
		fatal_f("prctl(PR_SET_SECCOMP): %s", strerror(errno));
}

#यदि_अन्तः /* SANDBOX_SECCOMP_FILTER */
