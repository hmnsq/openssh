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

#જો 0
/*
 * For older toolchains, it may be necessary to use the kernel
 * headers directly.
 */
#ifdef SANDBOX_SECCOMP_FILTER_DEBUG
# include <asm/siginfo.h>
# define __have_siginfo_t 1
# define __have_sigval_t 1
# define __have_sigevent_t 1
#endif /* SANDBOX_SECCOMP_FILTER_DEBUG */
#endif

#અન્તર્ભાવ "includes.h"

#ifdef SANDBOX_SECCOMP_FILTER

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/resource.h>
#અન્તર્ભાવ <sys/prctl.h>
#અન્તર્ભાવ <sys/mman.h>
#અન્તર્ભાવ <sys/syscall.h>

#અન્તર્ભાવ <netinet/ip.h>

#અન્તર્ભાવ <linux/futex.h>
#અન્તર્ભાવ <linux/net.h>
#અન્તર્ભાવ <linux/audit.h>
#અન્તર્ભાવ <linux/filter.h>
#અન્તર્ભાવ <linux/seccomp.h>
#અન્તર્ભાવ <elf.h>

#અન્તર્ભાવ <asm/unistd.h>
#ifdef __s390__
#અન્તર્ભાવ <asm/zcrypt.h>
#endif

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stddef.h>  /* for offsetof */
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "ssh-sandbox.h"
#અન્તર્ભાવ "xmalloc.h"

/* Linux seccomp_filter sandbox */
#define SECCOMP_FILTER_FAIL SECCOMP_RET_KILL

/* Use a signal handler to emit violations when debugging */
#ifdef SANDBOX_SECCOMP_FILTER_DEBUG
# undef SECCOMP_FILTER_FAIL
# define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#endif /* SANDBOX_SECCOMP_FILTER_DEBUG */

#જો __BYTE_ORDER == __LITTLE_ENDIAN
# define ARG_LO_OFFSET  0
# define ARG_HI_OFFSET  કદ(uint32_t)
#અથવાજો __BYTE_ORDER == __BIG_ENDIAN
# define ARG_LO_OFFSET  કદ(uint32_t)
# define ARG_HI_OFFSET  0
#નહીંતર
#error "Unknown endianness"
#endif

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#define SC_DENY(_nr, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#define SC_ALLOW(_nr) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#define SC_ALLOW_ARG(_nr, _arg_nr, _arg_val) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 6), \
	/* load and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(સંરચના seccomp_data, args[(_arg_nr)]) + ARG_LO_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_arg_val) & 0xFFFFFFFF), 0, 3), \
	/* load and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(સંરચના seccomp_data, args[(_arg_nr)]) + ARG_HI_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_arg_val) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(સંરચના seccomp_data, nr))
/* Allow if syscall argument contains only values in mask */
#define SC_ALLOW_ARG_MASK(_nr, _arg_nr, _arg_mask) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(સંરચના seccomp_data, args[(_arg_nr)]) + ARG_LO_OFFSET), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((_arg_mask) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 4), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(સંરચના seccomp_data, args[(_arg_nr)]) + ARG_HI_OFFSET), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(_arg_mask) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(સંરચના seccomp_data, nr))
/* Deny unless syscall argument contains only values in mask */
#define SC_DENY_UNLESS_ARG_MASK(_nr, _arg_nr, _arg_mask, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(સંરચના seccomp_data, args[(_arg_nr)]) + ARG_LO_OFFSET), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((_arg_mask) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 3), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(સંરચના seccomp_data, args[(_arg_nr)]) + ARG_HI_OFFSET), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(_arg_mask) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno)), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(સંરચના seccomp_data, nr))
#define SC_DENY_UNLESS_MASK(_nr, _arg_nr, _arg_val, _errno) \
/* Special handling for futex(2) that combines a bitmap and operation number */
#જો defined(__NR_futex) || defined(__NR_futex_time64)
#define SC_FUTEX_MASK (FUTEX_PRIVATE_FLAG|FUTEX_CLOCK_REALTIME)
#define SC_ALLOW_FUTEX_OP(_nr, _op) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(સંરચના seccomp_data, args[1]) + ARG_LO_OFFSET), \
	/* mask off allowed bitmap values, low word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~(SC_FUTEX_MASK & 0xFFFFFFFF)), \
	/* test operation number, low word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ((_op) & 0xFFFFFFFF), 0, 4), \
	/* load syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(સંરચના seccomp_data, args[1]) + ARG_HI_OFFSET), \
	/* mask off allowed bitmap values, high word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)SC_FUTEX_MASK >> 32)) & 0xFFFFFFFF)), \
	/* test operation number, high word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_op) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(સંરચના seccomp_data, nr))

/* Use this for both __NR_futex and __NR_futex_time64 */
# define SC_FUTEX(_nr) \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_REQUEUE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_CMP_REQUEUE)
#endif /* __NR_futex || __NR_futex_time64 */

#જો defined(__NR_mmap) || defined(__NR_mmap2)
# ifdef MAP_FIXED_NOREPLACE
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_FIXED_NOREPLACE
# નહીંતર
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED
# endif /* MAP_FIXED_NOREPLACE */
/* Use this for both __NR_mmap and __NR_mmap2 variants */
# define SC_MMAP(_nr) \
	SC_DENY_UNLESS_ARG_MASK(_nr, 3, SC_MMAP_FLAGS, EINVAL), \
	SC_ALLOW_ARG_MASK(_nr, 2, PROT_READ|PROT_WRITE|PROT_NONE)
#endif /* __NR_mmap || __NR_mmap2 */

/* Special handling for setsockopt(2) */
#define SC_ALLOW_SETSOCKOPT(_level, _optname) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setsockopt, 0, 10), \
	/* load and test level, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(સંરચના seccomp_data, args[1]) + ARG_LO_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_level) & 0xFFFFFFFF), 0, 7), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(સંરચના seccomp_data, args[1]) + ARG_HI_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 5), \
	/* load and test optname, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(સંરચના seccomp_data, args[2]) + ARG_LO_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_optname) & 0xFFFFFFFF), 0, 3), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(સંરચના seccomp_data, args[2]) + ARG_HI_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(સંરચના seccomp_data, nr))

/* Syscall filtering set for preauth. */
સ્થિર અચલ સંરચના sock_filter preauth_insns[] = {
	/* Ensure the syscall arch convention is as expected. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(સંરચના seccomp_data, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
	/* Load the syscall number for checking. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(સંરચના seccomp_data, nr)),

	/* Syscalls to non-fatally deny */
#ifdef __NR_lstat
	SC_DENY(__NR_lstat, EACCES),
#endif
#ifdef __NR_lstat64
	SC_DENY(__NR_lstat64, EACCES),
#endif
#ifdef __NR_fstat
	SC_DENY(__NR_fstat, EACCES),
#endif
#ifdef __NR_fstat64
	SC_DENY(__NR_fstat64, EACCES),
#endif
#ifdef __NR_fstatat64
	SC_DENY(__NR_fstatat64, EACCES),
#endif
#ifdef __NR_open
	SC_DENY(__NR_open, EACCES),
#endif
#ifdef __NR_openat
	SC_DENY(__NR_openat, EACCES),
#endif
#ifdef __NR_newfstatat
	SC_DENY(__NR_newfstatat, EACCES),
#endif
#ifdef __NR_stat
	SC_DENY(__NR_stat, EACCES),
#endif
#ifdef __NR_stat64
	SC_DENY(__NR_stat64, EACCES),
#endif
#ifdef __NR_shmget
	SC_DENY(__NR_shmget, EACCES),
#endif
#ifdef __NR_shmat
	SC_DENY(__NR_shmat, EACCES),
#endif
#ifdef __NR_shmdt
	SC_DENY(__NR_shmdt, EACCES),
#endif
#ifdef __NR_ipc
	SC_DENY(__NR_ipc, EACCES),
#endif
#ifdef __NR_statx
	SC_DENY(__NR_statx, EACCES),
#endif

	/* Syscalls to permit */
#ifdef __NR_brk
	SC_ALLOW(__NR_brk),
#endif
#ifdef __NR_clock_gettime
	SC_ALLOW(__NR_clock_gettime),
#endif
#ifdef __NR_clock_gettime64
	SC_ALLOW(__NR_clock_gettime64),
#endif
#ifdef __NR_close
	SC_ALLOW(__NR_close),
#endif
#ifdef __NR_exit
	SC_ALLOW(__NR_exit),
#endif
#ifdef __NR_exit_group
	SC_ALLOW(__NR_exit_group),
#endif
#ifdef __NR_futex
	SC_FUTEX(__NR_futex),
#endif
#ifdef __NR_futex_time64
	SC_FUTEX(__NR_futex_time64),
#endif
#ifdef __NR_geteuid
	SC_ALLOW(__NR_geteuid),
#endif
#ifdef __NR_geteuid32
	SC_ALLOW(__NR_geteuid32),
#endif
#ifdef __NR_getpgid
	SC_ALLOW(__NR_getpgid),
#endif
#ifdef __NR_getpid
	SC_ALLOW(__NR_getpid),
#endif
#ifdef __NR_getrandom
	SC_ALLOW(__NR_getrandom),
#endif
#ifdef __NR_gettid
	SC_ALLOW(__NR_gettid),
#endif
#ifdef __NR_gettimeofday
	SC_ALLOW(__NR_gettimeofday),
#endif
#ifdef __NR_getuid
	SC_ALLOW(__NR_getuid),
#endif
#ifdef __NR_getuid32
	SC_ALLOW(__NR_getuid32),
#endif
#ifdef __NR_madvise
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
#endif
#ifdef __NR_mmap
	SC_MMAP(__NR_mmap),
#endif
#ifdef __NR_mmap2
	SC_MMAP(__NR_mmap2),
#endif
#ifdef __NR_mprotect
	SC_ALLOW_ARG_MASK(__NR_mprotect, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#endif
#ifdef __NR_mremap
	SC_ALLOW_ARG_MASK(__NR_mremap, 3, MREMAP_MAYMOVE),
#endif
#ifdef __NR_munmap
	SC_ALLOW(__NR_munmap),
#endif
#ifdef __NR_nanosleep
	SC_ALLOW(__NR_nanosleep),
#endif
#ifdef __NR_clock_nanosleep
	SC_ALLOW(__NR_clock_nanosleep),
#endif
#ifdef __NR_clock_nanosleep_time64
	SC_ALLOW(__NR_clock_nanosleep_time64),
#endif
#ifdef __NR__newselect
	SC_ALLOW(__NR__newselect),
#endif
#ifdef __NR_ppoll
	SC_ALLOW(__NR_ppoll),
#endif
#ifdef __NR_ppoll_time64
	SC_ALLOW(__NR_ppoll_time64),
#endif
#ifdef __NR_poll
	SC_ALLOW(__NR_poll),
#endif
#ifdef __NR_pselect6
	SC_ALLOW(__NR_pselect6),
#endif
#ifdef __NR_pselect6_time64
	SC_ALLOW(__NR_pselect6_time64),
#endif
#ifdef __NR_read
	SC_ALLOW(__NR_read),
#endif
#ifdef __NR_riscv_hwprobe
	SC_ALLOW(__NR_riscv_hwprobe),
#endif
#ifdef __NR_rt_sigprocmask
	SC_ALLOW(__NR_rt_sigprocmask),
#endif
#ifdef __NR_select
	SC_ALLOW(__NR_select),
#endif
#ifdef __NR_shutdown
	SC_ALLOW(__NR_shutdown),
#endif
#ifdef __NR_sigprocmask
	SC_ALLOW(__NR_sigprocmask),
#endif
#ifdef __NR_time
	SC_ALLOW(__NR_time),
#endif
#ifdef __NR_write
	SC_ALLOW(__NR_write),
#endif
#ifdef __NR_writev
	SC_ALLOW(__NR_writev),
#endif
#ifdef __NR_getsockopt
	SC_ALLOW(__NR_getsockopt),
#endif
#ifdef __NR_getsockname
	SC_ALLOW(__NR_getsockname),
#endif
#ifdef __NR_getpeername
	SC_ALLOW(__NR_getpeername),
#endif
#ifdef __NR_uname
	SC_ALLOW(__NR_uname),
#endif
#ifdef __NR_restart_syscall
	SC_ALLOW(__NR_restart_syscall),
#endif
#ifdef __NR_setsockopt
	SC_ALLOW_SETSOCKOPT(IPPROTO_IPV6, IPV6_TCLASS),
	SC_ALLOW_SETSOCKOPT(IPPROTO_IP, IP_TOS),
#endif
#ifdef __NR_socketcall
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETPEERNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKOPT),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
	SC_DENY(__NR_socketcall, EACCES),
#endif
#જો defined(__NR_ioctl) && defined(__s390__)
	/* Allow ioctls for ICA crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, Z90STAT_STATUS_MASK),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSAMODEXPO),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSACRT),
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSECSENDCPRB),
	/* Allow ioctls for EP11 crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSENDEP11CPRB),
#endif
#જો defined(__x86_64__) && defined(__ILP32__) && defined(__X32_SYSCALL_BIT)
	/*
	 * On Linux x32, the clock_gettime VDSO falls back to the
	 * x86-64 syscall under some circumstances, e.g.
	 * https://bugs.debian.org/849923
	 */
	SC_ALLOW(__NR_clock_gettime & ~__X32_SYSCALL_BIT),
#endif

	/* Default deny */
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

સ્થિર અચલ સંરચના sock_fprog preauth_program = {
	.len = (unsigned short)(કદ(preauth_insns)/કદ(preauth_insns[0])),
	.filter = (સંરચના sock_filter *)preauth_insns,
};

સંરચના ssh_sandbox {
	પૂર્ણાંક junk;
};

સંરચના ssh_sandbox *
ssh_sandbox_init(સંરચના monitor *monitor)
{
	સંરચના ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing seccomp filter sandbox");
	box = xcalloc(1, કદ(*box));
	પાછા box;
}

#ifdef SANDBOX_SECCOMP_FILTER_DEBUG
બાહ્ય સંરચના monitor *pmonitor;
શૂન્ય mm_log_handler(LogLevel level, પૂર્ણાંક forced, અચલ અક્ષર *સંદેશ, શૂન્ય *ctx);

સ્થિર શૂન્ય
ssh_sandbox_violation(પૂર્ણાંક signum, siginfo_t *info, શૂન્ય *void_context)
{
	અક્ષર સંદેશ[256];

	snprintf(સંદેશ, કદ(સંદેશ),
	    "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)",
	    __func__, info->si_arch, info->si_syscall, info->si_call_addr);
	mm_log_handler(SYSLOG_LEVEL_FATAL, 0, સંદેશ, pmonitor);
	_exit(1);
}

સ્થિર શૂન્ય
ssh_sandbox_child_debugging(શૂન્ય)
{
	સંરચના sigaction act;
	sigset_t mask;

	debug3_f("installing SIGSYS handler");
	memset(&act, 0, કદ(act));
	sigemptyset(&mask);
	sigaddset(&mask, SIGSYS);

	act.sa_sigaction = &ssh_sandbox_violation;
	act.sa_flags = SA_SIGINFO;
	જો (sigaction(SIGSYS, &act, ખાલી) == -1)
		fatal_f("sigaction(SIGSYS): %s", strerror(errno));
	જો (sigprocmask(SIG_UNBLOCK, &mask, ખાલી) == -1)
		fatal("%s: sigprocmask(SIGSYS): %s",
		    __func__, strerror(errno));
}
#endif /* SANDBOX_SECCOMP_FILTER_DEBUG */

શૂન્ય
ssh_sandbox_child(સંરચના ssh_sandbox *box)
{
	સંરચના rlimit rl_zero, rl_one = {.rlim_cur = 1, .rlim_max = 1};

	/* Set rlimits for completeness if possible. */
	rl_zero.rlim_cur = rl_zero.rlim_max = 0;
	જો (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
	/*
	 * Cannot use zero for nfds, because poll(2) will fail with
	 * errno=EINVAL if npfds>RLIMIT_NOFILE.
	 */
	જો (setrlimit(RLIMIT_NOFILE, &rl_one) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
	જો (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));

#ifdef SANDBOX_SECCOMP_FILTER_DEBUG
	ssh_sandbox_child_debugging();
#endif /* SANDBOX_SECCOMP_FILTER_DEBUG */

	debug3_f("setting PR_SET_NO_NEW_PRIVS");
	જો (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatal_f("prctl(PR_SET_NO_NEW_PRIVS): %s", strerror(errno));
	debug3_f("attaching seccomp filter program");
	જો (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &preauth_program) == -1)
		fatal_f("prctl(PR_SET_SECCOMP): %s", strerror(errno));
}

#endif /* SANDBOX_SECCOMP_FILTER */
