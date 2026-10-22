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

#अगर 0
/*
 * For older toolchains, it may be necessary to use the kernel
 * headers directly.
 */
#अगर_घोषित SANDBOX_SECCOMP_FILTER_DEBUG
# include <asm/siginfo.h>
# define __have_siginfo_t 1
# define __have_sigval_t 1
# define __have_sigevent_t 1
#पूर्ण_अगर /* SANDBOX_SECCOMP_FILTER_DEBUG */
#पूर्ण_अगर

#समावेश "includes.h"

#अगर_घोषित SANDBOX_SECCOMP_FILTER

#समावेश <sys/types.h>
#समावेश <sys/resource.h>
#समावेश <sys/prctl.h>
#समावेश <sys/mman.h>
#समावेश <sys/syscall.h>

#समावेश <netinet/ip.h>

#समावेश <linux/futex.h>
#समावेश <linux/net.h>
#समावेश <linux/audit.h>
#समावेश <linux/filter.h>
#समावेश <linux/seccomp.h>
#समावेश <elf.h>

#समावेश <asm/unistd.h>
#अगर_घोषित __s390__
#समावेश <asm/zcrypt.h>
#पूर्ण_अगर

#समावेश <errno.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stddef.h>  /* for offsetof */
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "log.h"
#समावेश "ssh-sandbox.h"
#समावेश "xmalloc.h"

/* Linux seccomp_filter sandbox */
#घोषणा SECCOMP_FILTER_FAIL SECCOMP_RET_KILL

/* Use a signal handler to emit violations when debugging */
#अगर_घोषित SANDBOX_SECCOMP_FILTER_DEBUG
# undef SECCOMP_FILTER_FAIL
# define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#पूर्ण_अगर /* SANDBOX_SECCOMP_FILTER_DEBUG */

#अगर __BYTE_ORDER == __LITTLE_ENDIAN
# define ARG_LO_OFFSET  0
# define ARG_HI_OFFSET  माप(uint32_t)
#या_अगर __BYTE_ORDER == __BIG_ENDIAN
# define ARG_LO_OFFSET  माप(uint32_t)
# define ARG_HI_OFFSET  0
#अन्यथा
#त्रुटि "Unknown endianness"
#पूर्ण_अगर

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#घोषणा SC_DENY(_nr, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#घोषणा SC_ALLOW(_nr) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#घोषणा SC_ALLOW_ARG(_nr, _arg_nr, _arg_val) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 6), \
	/* load and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    दुरत्व(काष्ठा seccomp_तथ्य, args[(_arg_nr)]) + ARG_LO_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_arg_val) & 0xFFFFFFFF), 0, 3), \
	/* load and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    दुरत्व(काष्ठा seccomp_तथ्य, args[(_arg_nr)]) + ARG_HI_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_arg_val) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		दुरत्व(काष्ठा seccomp_तथ्य, nr))
/* Allow if syscall argument contains only values in mask */
#घोषणा SC_ALLOW_ARG_MASK(_nr, _arg_nr, _arg_mask) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    दुरत्व(काष्ठा seccomp_तथ्य, args[(_arg_nr)]) + ARG_LO_OFFSET), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((_arg_mask) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 4), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    दुरत्व(काष्ठा seccomp_तथ्य, args[(_arg_nr)]) + ARG_HI_OFFSET), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(_arg_mask) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		दुरत्व(काष्ठा seccomp_तथ्य, nr))
/* Deny unless syscall argument contains only values in mask */
#घोषणा SC_DENY_UNLESS_ARG_MASK(_nr, _arg_nr, _arg_mask, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    दुरत्व(काष्ठा seccomp_तथ्य, args[(_arg_nr)]) + ARG_LO_OFFSET), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((_arg_mask) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 3), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    दुरत्व(काष्ठा seccomp_तथ्य, args[(_arg_nr)]) + ARG_HI_OFFSET), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(_arg_mask) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno)), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		दुरत्व(काष्ठा seccomp_तथ्य, nr))
#घोषणा SC_DENY_UNLESS_MASK(_nr, _arg_nr, _arg_val, _errno) \
/* Special handling for futex(2) that combines a bitmap and operation number */
#अगर defined(__NR_futex) || defined(__NR_futex_time64)
#घोषणा SC_FUTEX_MASK (FUTEX_PRIVATE_FLAG|FUTEX_CLOCK_REALTIME)
#घोषणा SC_ALLOW_FUTEX_OP(_nr, _op) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    दुरत्व(काष्ठा seccomp_तथ्य, args[1]) + ARG_LO_OFFSET), \
	/* mask off allowed bitmap values, low word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~(SC_FUTEX_MASK & 0xFFFFFFFF)), \
	/* test operation number, low word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ((_op) & 0xFFFFFFFF), 0, 4), \
	/* load syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    दुरत्व(काष्ठा seccomp_तथ्य, args[1]) + ARG_HI_OFFSET), \
	/* mask off allowed bitmap values, high word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)SC_FUTEX_MASK >> 32)) & 0xFFFFFFFF)), \
	/* test operation number, high word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_op) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, दुरत्व(काष्ठा seccomp_तथ्य, nr))

/* Use this for both __NR_futex and __NR_futex_time64 */
# define SC_FUTEX(_nr) \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_REQUEUE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_CMP_REQUEUE)
#पूर्ण_अगर /* __NR_futex || __NR_futex_time64 */

#अगर defined(__NR_mmap) || defined(__NR_mmap2)
# ifdef MAP_FIXED_NOREPLACE
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_FIXED_NOREPLACE
# अन्यथा
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED
# endif /* MAP_FIXED_NOREPLACE */
/* Use this for both __NR_mmap and __NR_mmap2 variants */
# define SC_MMAP(_nr) \
	SC_DENY_UNLESS_ARG_MASK(_nr, 3, SC_MMAP_FLAGS, EINVAL), \
	SC_ALLOW_ARG_MASK(_nr, 2, PROT_READ|PROT_WRITE|PROT_NONE)
#पूर्ण_अगर /* __NR_mmap || __NR_mmap2 */

/* Special handling for setsockopt(2) */
#घोषणा SC_ALLOW_SETSOCKOPT(_level, _optname) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setsockopt, 0, 10), \
	/* load and test level, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    दुरत्व(काष्ठा seccomp_तथ्य, args[1]) + ARG_LO_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_level) & 0xFFFFFFFF), 0, 7), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    दुरत्व(काष्ठा seccomp_तथ्य, args[1]) + ARG_HI_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 5), \
	/* load and test optname, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    दुरत्व(काष्ठा seccomp_तथ्य, args[2]) + ARG_LO_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_optname) & 0xFFFFFFFF), 0, 3), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    दुरत्व(काष्ठा seccomp_तथ्य, args[2]) + ARG_HI_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		दुरत्व(काष्ठा seccomp_तथ्य, nr))

/* Syscall filtering set for preauth. */
अटल स्थिर काष्ठा sock_filter preauth_insns[] = {
	/* Ensure the syscall arch convention is as expected. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		दुरत्व(काष्ठा seccomp_तथ्य, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
	/* Load the syscall number for checking. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		दुरत्व(काष्ठा seccomp_तथ्य, nr)),

	/* Syscalls to non-fatally deny */
#अगर_घोषित __NR_lstat
	SC_DENY(__NR_lstat, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_lstat64
	SC_DENY(__NR_lstat64, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_fstat
	SC_DENY(__NR_fstat, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_fstat64
	SC_DENY(__NR_fstat64, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_fstatat64
	SC_DENY(__NR_fstatat64, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_open
	SC_DENY(__NR_open, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_openat
	SC_DENY(__NR_openat, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_newfstatat
	SC_DENY(__NR_newfstatat, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_stat
	SC_DENY(__NR_stat, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_stat64
	SC_DENY(__NR_stat64, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_shmget
	SC_DENY(__NR_shmget, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_shmat
	SC_DENY(__NR_shmat, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_shmdt
	SC_DENY(__NR_shmdt, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_ipc
	SC_DENY(__NR_ipc, EACCES),
#पूर्ण_अगर
#अगर_घोषित __NR_statx
	SC_DENY(__NR_statx, EACCES),
#पूर्ण_अगर

	/* Syscalls to permit */
#अगर_घोषित __NR_brk
	SC_ALLOW(__NR_brk),
#पूर्ण_अगर
#अगर_घोषित __NR_clock_gettime
	SC_ALLOW(__NR_clock_gettime),
#पूर्ण_अगर
#अगर_घोषित __NR_clock_gettime64
	SC_ALLOW(__NR_clock_gettime64),
#पूर्ण_अगर
#अगर_घोषित __NR_close
	SC_ALLOW(__NR_close),
#पूर्ण_अगर
#अगर_घोषित __NR_exit
	SC_ALLOW(__NR_exit),
#पूर्ण_अगर
#अगर_घोषित __NR_exit_group
	SC_ALLOW(__NR_exit_group),
#पूर्ण_अगर
#अगर_घोषित __NR_futex
	SC_FUTEX(__NR_futex),
#पूर्ण_अगर
#अगर_घोषित __NR_futex_time64
	SC_FUTEX(__NR_futex_time64),
#पूर्ण_अगर
#अगर_घोषित __NR_geteuid
	SC_ALLOW(__NR_geteuid),
#पूर्ण_अगर
#अगर_घोषित __NR_geteuid32
	SC_ALLOW(__NR_geteuid32),
#पूर्ण_अगर
#अगर_घोषित __NR_getpgid
	SC_ALLOW(__NR_getpgid),
#पूर्ण_अगर
#अगर_घोषित __NR_getpid
	SC_ALLOW(__NR_getpid),
#पूर्ण_अगर
#अगर_घोषित __NR_getrandom
	SC_ALLOW(__NR_getrandom),
#पूर्ण_अगर
#अगर_घोषित __NR_gettid
	SC_ALLOW(__NR_gettid),
#पूर्ण_अगर
#अगर_घोषित __NR_gettimeofday
	SC_ALLOW(__NR_gettimeofday),
#पूर्ण_अगर
#अगर_घोषित __NR_getuid
	SC_ALLOW(__NR_getuid),
#पूर्ण_अगर
#अगर_घोषित __NR_getuid32
	SC_ALLOW(__NR_getuid32),
#पूर्ण_अगर
#अगर_घोषित __NR_madvise
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
#पूर्ण_अगर
#अगर_घोषित __NR_mmap
	SC_MMAP(__NR_mmap),
#पूर्ण_अगर
#अगर_घोषित __NR_mmap2
	SC_MMAP(__NR_mmap2),
#पूर्ण_अगर
#अगर_घोषित __NR_mprotect
	SC_ALLOW_ARG_MASK(__NR_mprotect, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#पूर्ण_अगर
#अगर_घोषित __NR_mremap
	SC_ALLOW_ARG_MASK(__NR_mremap, 3, MREMAP_MAYMOVE),
#पूर्ण_अगर
#अगर_घोषित __NR_munmap
	SC_ALLOW(__NR_munmap),
#पूर्ण_अगर
#अगर_घोषित __NR_nanosleep
	SC_ALLOW(__NR_nanosleep),
#पूर्ण_अगर
#अगर_घोषित __NR_clock_nanosleep
	SC_ALLOW(__NR_clock_nanosleep),
#पूर्ण_अगर
#अगर_घोषित __NR_clock_nanosleep_time64
	SC_ALLOW(__NR_clock_nanosleep_time64),
#पूर्ण_अगर
#अगर_घोषित __NR__newselect
	SC_ALLOW(__NR__newselect),
#पूर्ण_अगर
#अगर_घोषित __NR_ppoll
	SC_ALLOW(__NR_ppoll),
#पूर्ण_अगर
#अगर_घोषित __NR_ppoll_time64
	SC_ALLOW(__NR_ppoll_time64),
#पूर्ण_अगर
#अगर_घोषित __NR_poll
	SC_ALLOW(__NR_poll),
#पूर्ण_अगर
#अगर_घोषित __NR_pselect6
	SC_ALLOW(__NR_pselect6),
#पूर्ण_अगर
#अगर_घोषित __NR_pselect6_time64
	SC_ALLOW(__NR_pselect6_time64),
#पूर्ण_अगर
#अगर_घोषित __NR_read
	SC_ALLOW(__NR_read),
#पूर्ण_अगर
#अगर_घोषित __NR_riscv_hwprobe
	SC_ALLOW(__NR_riscv_hwprobe),
#पूर्ण_अगर
#अगर_घोषित __NR_rt_sigprocmask
	SC_ALLOW(__NR_rt_sigprocmask),
#पूर्ण_अगर
#अगर_घोषित __NR_select
	SC_ALLOW(__NR_select),
#पूर्ण_अगर
#अगर_घोषित __NR_shutdown
	SC_ALLOW(__NR_shutdown),
#पूर्ण_अगर
#अगर_घोषित __NR_sigprocmask
	SC_ALLOW(__NR_sigprocmask),
#पूर्ण_अगर
#अगर_घोषित __NR_time
	SC_ALLOW(__NR_time),
#पूर्ण_अगर
#अगर_घोषित __NR_write
	SC_ALLOW(__NR_write),
#पूर्ण_अगर
#अगर_घोषित __NR_writev
	SC_ALLOW(__NR_writev),
#पूर्ण_अगर
#अगर_घोषित __NR_getsockopt
	SC_ALLOW(__NR_getsockopt),
#पूर्ण_अगर
#अगर_घोषित __NR_getsockname
	SC_ALLOW(__NR_getsockname),
#पूर्ण_अगर
#अगर_घोषित __NR_getpeername
	SC_ALLOW(__NR_getpeername),
#पूर्ण_अगर
#अगर_घोषित __NR_uname
	SC_ALLOW(__NR_uname),
#पूर्ण_अगर
#अगर_घोषित __NR_restart_syscall
	SC_ALLOW(__NR_restart_syscall),
#पूर्ण_अगर
#अगर_घोषित __NR_setsockopt
	SC_ALLOW_SETSOCKOPT(IPPROTO_IPV6, IPV6_TCLASS),
	SC_ALLOW_SETSOCKOPT(IPPROTO_IP, IP_TOS),
#पूर्ण_अगर
#अगर_घोषित __NR_socketcall
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETPEERNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKOPT),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
	SC_DENY(__NR_socketcall, EACCES),
#पूर्ण_अगर
#अगर defined(__NR_ioctl) && defined(__s390__)
	/* Allow ioctls for ICA crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, Z90STAT_STATUS_MASK),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSAMODEXPO),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSACRT),
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSECSENDCPRB),
	/* Allow ioctls for EP11 crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSENDEP11CPRB),
#पूर्ण_अगर
#अगर defined(__x86_64__) && defined(__ILP32__) && defined(__X32_SYSCALL_BIT)
	/*
	 * On Linux x32, the clock_gettime VDSO falls back to the
	 * x86-64 syscall under some circumstances, e.g.
	 * https://bugs.debian.org/849923
	 */
	SC_ALLOW(__NR_clock_gettime & ~__X32_SYSCALL_BIT),
#पूर्ण_अगर

	/* Default deny */
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

अटल स्थिर काष्ठा sock_fprog preauth_program = {
	.len = (अचिन्हित लघु)(माप(preauth_insns)/माप(preauth_insns[0])),
	.filter = (काष्ठा sock_filter *)preauth_insns,
};

काष्ठा ssh_sandbox {
	पूर्णांक junk;
};

काष्ठा ssh_sandbox *
ssh_sandbox_init(काष्ठा monitor *monitor)
{
	काष्ठा ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing seccomp filter sandbox");
	box = xcalloc(1, माप(*box));
	वापस box;
}

#अगर_घोषित SANDBOX_SECCOMP_FILTER_DEBUG
बाह्य काष्ठा monitor *pmonitor;
व्योम mm_log_handler(LogLevel level, पूर्णांक forced, स्थिर अक्षर *संदेश, व्योम *ctx);

अटल व्योम
ssh_sandbox_violation(पूर्णांक signum, siginfo_t *info, व्योम *void_context)
{
	अक्षर संदेश[256];

	snprintf(संदेश, माप(संदेश),
	    "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)",
	    __func__, info->si_arch, info->si_syscall, info->si_call_addr);
	mm_log_handler(SYSLOG_LEVEL_FATAL, 0, संदेश, pmonitor);
	_निकास(1);
}

अटल व्योम
ssh_sandbox_child_debugging(व्योम)
{
	काष्ठा sigaction act;
	sigset_t mask;

	debug3_f("installing SIGSYS handler");
	स_रखो(&act, 0, माप(act));
	sigemptyset(&mask);
	sigaddset(&mask, SIGSYS);

	act.sa_sigaction = &ssh_sandbox_violation;
	act.sa_flags = SA_SIGINFO;
	अगर (sigaction(SIGSYS, &act, शून्य) == -1)
		fatal_f("sigaction(SIGSYS): %s", म_त्रुटि(त्रुटि_सं));
	अगर (sigprocmask(SIG_UNBLOCK, &mask, शून्य) == -1)
		fatal("%s: sigprocmask(SIGSYS): %s",
		    __func__, म_त्रुटि(त्रुटि_सं));
}
#पूर्ण_अगर /* SANDBOX_SECCOMP_FILTER_DEBUG */

व्योम
ssh_sandbox_child(काष्ठा ssh_sandbox *box)
{
	काष्ठा rlimit rl_zero, rl_one = {.rlim_cur = 1, .rlim_max = 1};

	/* Set rlimits for completeness if possible. */
	rl_zero.rlim_cur = rl_zero.rlim_max = 0;
	अगर (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, म_त्रुटि(त्रुटि_सं));
	/*
	 * Cannot use zero for nfds, because poll(2) will fail with
	 * errno=EINVAL if npfds>RLIMIT_NOFILE.
	 */
	अगर (setrlimit(RLIMIT_NOFILE, &rl_one) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, म_त्रुटि(त्रुटि_सं));
	अगर (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, म_त्रुटि(त्रुटि_सं));

#अगर_घोषित SANDBOX_SECCOMP_FILTER_DEBUG
	ssh_sandbox_child_debugging();
#पूर्ण_अगर /* SANDBOX_SECCOMP_FILTER_DEBUG */

	debug3_f("setting PR_SET_NO_NEW_PRIVS");
	अगर (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatal_f("prctl(PR_SET_NO_NEW_PRIVS): %s", म_त्रुटि(त्रुटि_सं));
	debug3_f("attaching seccomp filter program");
	अगर (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &preauth_program) == -1)
		fatal_f("prctl(PR_SET_SECCOMP): %s", म_त्रुटि(त्रुटि_सं));
}

#पूर्ण_अगर /* SANDBOX_SECCOMP_FILTER */
