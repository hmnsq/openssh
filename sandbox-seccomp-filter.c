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

#ਜੇ 0
/*
 * For older toolchains, it may be necessary to use the kernel
 * headers directly.
 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SANDBOX_SECCOMP_FILTER_DEBUG
# include <asm/siginfo.h>
# define __have_siginfo_t 1
# define __have_sigval_t 1
# define __have_sigevent_t 1
#ਜੇ_ਅੰਤ /* SANDBOX_SECCOMP_FILTER_DEBUG */
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SANDBOX_SECCOMP_FILTER

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/resource.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/prctl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/mman.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/syscall.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/ip.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <linux/futex.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <linux/net.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <linux/audit.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <linux/filter.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <linux/seccomp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <elf.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <asm/unistd.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __s390__
#ਅਨ੍ਤਰ੍ਭਾਵ <asm/zcrypt.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>  /* for offsetof */
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-sandbox.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

/* Linux seccomp_filter sandbox */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SECCOMP_FILTER_FAIL SECCOMP_RET_KILL

/* Use a signal handler to emit violations when debugging */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SANDBOX_SECCOMP_FILTER_DEBUG
# undef SECCOMP_FILTER_FAIL
# define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#ਜੇ_ਅੰਤ /* SANDBOX_SECCOMP_FILTER_DEBUG */

#ਜੇ __BYTE_ORDER == __LITTLE_ENDIAN
# define ARG_LO_ਵਿੱਥ  0
# define ARG_HI_ਵਿੱਥ  ਆਕਾਰ(uint32_t)
#ਜਾਂਜੇ __BYTE_ORDER == __BIG_ENDIAN
# define ARG_LO_ਵਿੱਥ  ਆਕਾਰ(uint32_t)
# define ARG_HI_ਵਿੱਥ  0
#ਨਹੀਂਤਾਂ
#ਗਲਤੀ "Unknown endianness"
#ਜੇ_ਅੰਤ

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SC_DENY(_nr, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SC_ALLOW(_nr) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SC_ALLOW_ARG(_nr, _arg_nr, _arg_val) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 6), \
	/* load and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, ਦਲੀਲਾਂ[(_arg_nr)]) + ARG_LO_ਵਿੱਥ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_arg_val) & 0xFFFFFFFF), 0, 3), \
	/* load and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, ਦਲੀਲਾਂ[(_arg_nr)]) + ARG_HI_ਵਿੱਥ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_arg_val) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, nr))
/* Allow if syscall argument contains only values in mask */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SC_ALLOW_ARG_ਨਕਾਬ(_nr, _arg_nr, arg_ਨਕਾਬ) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, ਦਲੀਲਾਂ[(_arg_nr)]) + ARG_LO_ਵਿੱਥ), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_ਨਕਾਬ) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 4), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, ਦਲੀਲਾਂ[(_arg_nr)]) + ARG_HI_ਵਿੱਥ), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_ਨਕਾਬ) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, nr))
/* Deny unless syscall argument contains only values in mask */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SC_DENY_UNLESS_ARG_ਨਕਾਬ(_nr, _arg_nr, arg_ਨਕਾਬ, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, ਦਲੀਲਾਂ[(_arg_nr)]) + ARG_LO_ਵਿੱਥ), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_ਨਕਾਬ) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 3), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, ਦਲੀਲਾਂ[(_arg_nr)]) + ARG_HI_ਵਿੱਥ), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_ਨਕਾਬ) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno)), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, nr))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SC_DENY_UNLESS_ਨਕਾਬ(_nr, _arg_nr, _arg_val, _errno) \
/* Special handling for futex(2) that combines a bitmap and operation number */
#ਜੇ defined(__NR_futex) || defined(__NR_futex_time64)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SC_FUTEX_ਨਕਾਬ (FUTEX_ਨਿੱਜੀ_FLAG|FUTEX_CLOCK_REALTIME)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SC_ALLOW_FUTEX_OP(_nr, _op) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, ਦਲੀਲਾਂ[1]) + ARG_LO_ਵਿੱਥ), \
	/* mask off allowed bitmap values, low word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~(SC_FUTEX_ਨਕਾਬ & 0xFFFFFFFF)), \
	/* test operation number, low word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ((_op) & 0xFFFFFFFF), 0, 4), \
	/* load syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, ਦਲੀਲਾਂ[1]) + ARG_HI_ਵਿੱਥ), \
	/* mask off allowed bitmap values, high word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)SC_FUTEX_ਨਕਾਬ >> 32)) & 0xFFFFFFFF)), \
	/* test operation number, high word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_op) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, nr))

/* Use this for both __NR_futex and __NR_futex_time64 */
# define SC_FUTEX(_nr) \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_REQUEUE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_CMP_REQUEUE)
#ਜੇ_ਅੰਤ /* __NR_futex || __NR_futex_time64 */

#ਜੇ defined(__NR_mmap) || defined(__NR_mmap2)
# ifdef MAP_FIXED_NOREPLACE
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_FIXED_NOREPLACE
# ਨਹੀਂਤਾਂ
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED
# endif /* MAP_FIXED_NOREPLACE */
/* Use this for both __NR_mmap and __NR_mmap2 variants */
# define SC_MMAP(_nr) \
	SC_DENY_UNLESS_ARG_ਨਕਾਬ(_nr, 3, SC_MMAP_FLAGS, EINVAL), \
	SC_ALLOW_ARG_ਨਕਾਬ(_nr, 2, PROT_READ|PROT_WRITE|PROT_NONE)
#ਜੇ_ਅੰਤ /* __NR_mmap || __NR_mmap2 */

/* Special handling for setsockopt(2) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SC_ALLOW_SETSOCKOPT(_level, _optname) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setsockopt, 0, 10), \
	/* load and test level, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, ਦਲੀਲਾਂ[1]) + ARG_LO_ਵਿੱਥ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_level) & 0xFFFFFFFF), 0, 7), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, ਦਲੀਲਾਂ[1]) + ARG_HI_ਵਿੱਥ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 5), \
	/* load and test optname, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, ਦਲੀਲਾਂ[2]) + ARG_LO_ਵਿੱਥ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_optname) & 0xFFFFFFFF), 0, 3), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, ਦਲੀਲਾਂ[2]) + ARG_HI_ਵਿੱਥ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, nr))

/* Syscall filtering set for preauth. */
ਸਥਿਰ ਅਚਲ ਬਣਤਰ sock_filter preauth_insns[] = {
	/* Ensure the syscall arch convention is as expected. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
	/* Load the syscall number for checking. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(ਬਣਤਰ seccomp_ਅੰਕੜੇ, nr)),

	/* Syscalls to non-fatally deny */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_lstat
	SC_DENY(__NR_lstat, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_lstat64
	SC_DENY(__NR_lstat64, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_fstat
	SC_DENY(__NR_fstat, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_fstat64
	SC_DENY(__NR_fstat64, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_fstatat64
	SC_DENY(__NR_fstatat64, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_open
	SC_DENY(__NR_open, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_openat
	SC_DENY(__NR_openat, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_newfstatat
	SC_DENY(__NR_newfstatat, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_stat
	SC_DENY(__NR_stat, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_stat64
	SC_DENY(__NR_stat64, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_shmget
	SC_DENY(__NR_shmget, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_shmat
	SC_DENY(__NR_shmat, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_shmdt
	SC_DENY(__NR_shmdt, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_ipc
	SC_DENY(__NR_ipc, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_statx
	SC_DENY(__NR_statx, EACCES),
#ਜੇ_ਅੰਤ

	/* Syscalls to permit */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_brk
	SC_ALLOW(__NR_brk),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_clock_gettime
	SC_ALLOW(__NR_clock_gettime),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_clock_gettime64
	SC_ALLOW(__NR_clock_gettime64),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_close
	SC_ALLOW(__NR_close),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_exit
	SC_ALLOW(__NR_exit),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_exit_group
	SC_ALLOW(__NR_exit_group),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_futex
	SC_FUTEX(__NR_futex),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_futex_time64
	SC_FUTEX(__NR_futex_time64),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_geteuid
	SC_ALLOW(__NR_geteuid),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_geteuid32
	SC_ALLOW(__NR_geteuid32),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_getpgid
	SC_ALLOW(__NR_getpgid),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_getpid
	SC_ALLOW(__NR_getpid),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_getrandom
	SC_ALLOW(__NR_getrandom),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_gettid
	SC_ALLOW(__NR_gettid),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_gettimeofday
	SC_ALLOW(__NR_gettimeofday),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_getuid
	SC_ALLOW(__NR_getuid),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_getuid32
	SC_ALLOW(__NR_getuid32),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_madvise
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
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_mmap
	SC_MMAP(__NR_mmap),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_mmap2
	SC_MMAP(__NR_mmap2),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_mprotect
	SC_ALLOW_ARG_ਨਕਾਬ(__NR_mprotect, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_mremap
	SC_ALLOW_ARG_ਨਕਾਬ(__NR_mremap, 3, MREMAP_MAYMOVE),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_munmap
	SC_ALLOW(__NR_munmap),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_nanosleep
	SC_ALLOW(__NR_nanosleep),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_clock_nanosleep
	SC_ALLOW(__NR_clock_nanosleep),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_clock_nanosleep_time64
	SC_ALLOW(__NR_clock_nanosleep_time64),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR__newselect
	SC_ALLOW(__NR__newselect),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_ppoll
	SC_ALLOW(__NR_ppoll),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_ppoll_time64
	SC_ALLOW(__NR_ppoll_time64),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_poll
	SC_ALLOW(__NR_poll),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_pselect6
	SC_ALLOW(__NR_pselect6),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_pselect6_time64
	SC_ALLOW(__NR_pselect6_time64),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_read
	SC_ALLOW(__NR_read),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_riscv_hwprobe
	SC_ALLOW(__NR_riscv_hwprobe),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_rt_sigprocmask
	SC_ALLOW(__NR_rt_sigprocmask),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_select
	SC_ALLOW(__NR_select),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_shutdown
	SC_ALLOW(__NR_shutdown),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_sigprocmask
	SC_ALLOW(__NR_sigprocmask),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_time
	SC_ALLOW(__NR_time),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_write
	SC_ALLOW(__NR_write),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_writev
	SC_ALLOW(__NR_writev),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_getsockopt
	SC_ALLOW(__NR_getsockopt),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_getsockname
	SC_ALLOW(__NR_getsockname),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_getpeername
	SC_ALLOW(__NR_getpeername),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_uname
	SC_ALLOW(__NR_uname),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_restart_syscall
	SC_ALLOW(__NR_restart_syscall),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_setsockopt
	SC_ALLOW_SETSOCKOPT(IPPROTO_IPV6, IPV6_TCLASS),
	SC_ALLOW_SETSOCKOPT(IPPROTO_IP, IP_TOS),
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __NR_socketcall
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETPEERNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKOPT),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
	SC_DENY(__NR_socketcall, EACCES),
#ਜੇ_ਅੰਤ
#ਜੇ defined(__NR_ioctl) && defined(__s390__)
	/* Allow ioctls for ICA crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, Z90_STAT_ਸਥਿਤੀ_ਨਕਾਬ),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSAMODEXPO),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSACRT),
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSECSENDCPRB),
	/* Allow ioctls for EP11 crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSENDEP11CPRB),
#ਜੇ_ਅੰਤ
#ਜੇ defined(__x86_64__) && defined(__ILP32__) && defined(__X32_SYSCALL_BIT)
	/*
	 * On Linux x32, the clock_gettime VDSO falls back to the
	 * x86-64 syscall under some circumstances, e.g.
	 * https://bugs.debian.org/849923
	 */
	SC_ALLOW(__NR_clock_gettime & ~__X32_SYSCALL_BIT),
#ਜੇ_ਅੰਤ

	/* Default deny */
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

ਸਥਿਰ ਅਚਲ ਬਣਤਰ sock_fprog preauth_ਪ੍ਰੋਗਰਾਮ = {
	.len = (ਬਿਨਾਨਿਸ਼ਾਨੀ ਛੋਟਾ)(ਆਕਾਰ(preauth_insns)/ਆਕਾਰ(preauth_insns[0])),
	.filter = (ਬਣਤਰ sock_filter *)preauth_insns,
};

ਬਣਤਰ ssh_sandbox {
	ਪੂਰਨ junk;
};

ਬਣਤਰ ssh_sandbox *
ssh_sandbox_init(ਬਣਤਰ monitor *monitor)
{
	ਬਣਤਰ ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing seccomp filter sandbox");
	box = xcalloc(1, ਆਕਾਰ(*box));
	ਵਾਪਸ box;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SANDBOX_SECCOMP_FILTER_DEBUG
ਬਾਹਰੀ ਬਣਤਰ monitor *pmonitor;
ਖਾਲੀ mm_log_handler(LogLevel level, ਪੂਰਨ forced, ਅਚਲ ਅੱਖਰ *ਸੁਨੇਹਾ, ਖਾਲੀ *ctx);

ਸਥਿਰ ਖਾਲੀ
ssh_sandbox_violation(ਪੂਰਨ signum, siginfo_t *info, ਖਾਲੀ *void_context)
{
	ਅੱਖਰ ਸੁਨੇਹਾ[256];

	snprintf(ਸੁਨੇਹਾ, ਆਕਾਰ(ਸੁਨੇਹਾ),
	    "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)",
	    __func__, info->si_arch, info->si_syscall, info->si_call_addr);
	mm_log_handler(SYSLOG_LEVEL_FATAL, 0, ਸੁਨੇਹਾ, pmonitor);
	_exit(1);
}

ਸਥਿਰ ਖਾਲੀ
ssh_sandbox_ਬੱਚਾ_debugging(ਖਾਲੀ)
{
	ਬਣਤਰ sigaction act;
	sigset_t ਨਕਾਬ;

	debug3_f("installing SIGSYS handler");
	memset(&act, 0, ਆਕਾਰ(act));
	sigemptyset(&ਨਕਾਬ);
	sigaddset(&ਨਕਾਬ, SIGSYS);

	act.sa_sigaction = &ssh_sandbox_violation;
	act.sa_flags = SA_SIGINFO;
	ਜੇ (sigaction(SIGSYS, &act, ਨਿਰਾ) == -1)
		fatal_f("sigaction(SIGSYS): %s", strerror(errno));
	ਜੇ (sigprocmask(SIG_UNBLOCK, &ਨਕਾਬ, ਨਿਰਾ) == -1)
		fatal("%s: sigprocmask(SIGSYS): %s",
		    __func__, strerror(errno));
}
#ਜੇ_ਅੰਤ /* SANDBOX_SECCOMP_FILTER_DEBUG */

ਖਾਲੀ
ssh_sandbox_ਬੱਚਾ(ਬਣਤਰ ssh_sandbox *box)
{
	ਬਣਤਰ rlimit rl_zero, rl_one = {.rlim_cur = 1, .rlim_max = 1};

	/* Set rlimits for completeness if possible. */
	rl_zero.rlim_cur = rl_zero.rlim_max = 0;
	ਜੇ (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
	/*
	 * Cannot use zero for nfds, because poll(2) will fail with
	 * errno=EINVAL if npfds>RLIMIT_NOFILE.
	 */
	ਜੇ (setrlimit(RLIMIT_NOFILE, &rl_one) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
	ਜੇ (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SANDBOX_SECCOMP_FILTER_DEBUG
	ssh_sandbox_ਬੱਚਾ_debugging();
#ਜੇ_ਅੰਤ /* SANDBOX_SECCOMP_FILTER_DEBUG */

	debug3_f("setting PR_SET_NO_NEW_PRIVS");
	ਜੇ (prctl(PR_ਸੈੱਟ_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatal_f("prctl(PR_SET_NO_NEW_PRIVS): %s", strerror(errno));
	debug3_f("attaching seccomp filter program");
	ਜੇ (prctl(PR_ਸੈੱਟ_SECCOMP, SECCOMP_ਬਹੁਲਕ_FILTER, &preauth_ਪ੍ਰੋਗਰਾਮ) == -1)
		fatal_f("prctl(PR_SET_SECCOMP): %s", strerror(errno));
}

#ਜੇ_ਅੰਤ /* SANDBOX_SECCOMP_FILTER */
