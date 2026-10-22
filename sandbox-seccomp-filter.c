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

#ಆದರೆ 0
/*
 * For older toolchains, it may be necessary to use the kernel
 * headers directly.
 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SANDBOX_SECCOMP_FILTER_DEBUG
# include <asm/siginfo.h>
# define __have_siginfo_t 1
# define __have_sigval_t 1
# define __have_sigevent_t 1
#ಆದರೆ_ಅಂತ್ಯ /* SANDBOX_SECCOMP_FILTER_DEBUG */
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SANDBOX_SECCOMP_FILTER

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/resource.h>
#ಅನ್ತರ್ಭಾವ <sys/prctl.h>
#ಅನ್ತರ್ಭಾವ <sys/mman.h>
#ಅನ್ತರ್ಭಾವ <sys/syscall.h>

#ಅನ್ತರ್ಭಾವ <netinet/ip.h>

#ಅನ್ತರ್ಭಾವ <linux/futex.h>
#ಅನ್ತರ್ಭಾವ <linux/net.h>
#ಅನ್ತರ್ಭಾವ <linux/audit.h>
#ಅನ್ತರ್ಭಾವ <linux/filter.h>
#ಅನ್ತರ್ಭಾವ <linux/seccomp.h>
#ಅನ್ತರ್ಭಾವ <elf.h>

#ಅನ್ತರ್ಭಾವ <asm/unistd.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __s390__
#ಅನ್ತರ್ಭಾವ <asm/zcrypt.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>  /* for offsetof */
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "ssh-sandbox.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

/* Linux seccomp_filter sandbox */
#ವ್ಯಾಖ್ಯಾನಿಸು SECCOMP_FILTER_FAIL SECCOMP_RET_KILL

/* Use a signal handler to emit violations when debugging */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SANDBOX_SECCOMP_FILTER_DEBUG
# undef SECCOMP_FILTER_FAIL
# define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#ಆದರೆ_ಅಂತ್ಯ /* SANDBOX_SECCOMP_FILTER_DEBUG */

#ಆದರೆ __BYTE_ORDER == __LITTLE_ENDIAN
# define ARG_LO_ಸ್ಥಾನಾಂತರ  0
# define ARG_HI_ಸ್ಥಾನಾಂತರ  ಗಾತ್ರ(uint32_t)
#ಅಥವಾಆದರೆ __BYTE_ORDER == __BIG_ENDIAN
# define ARG_LO_ಸ್ಥಾನಾಂತರ  ಗಾತ್ರ(uint32_t)
# define ARG_HI_ಸ್ಥಾನಾಂತರ  0
#ಇಲ್ಲದಿದ್ದರೆ
#ದೋಷ "Unknown endianness"
#ಆದರೆ_ಅಂತ್ಯ

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#ವ್ಯಾಖ್ಯಾನಿಸು SC_DENY(_nr, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#ವ್ಯಾಖ್ಯಾನಿಸು SC_ALLOW(_nr) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#ವ್ಯಾಖ್ಯಾನಿಸು SC_ALLOW_ARG(_nr, _arg_nr, _arg_val) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 6), \
	/* load and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, ವಾದಗಳು[(_arg_nr)]) + ARG_LO_ಸ್ಥಾನಾಂತರ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_arg_val) & 0xFFFFFFFF), 0, 3), \
	/* load and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, ವಾದಗಳು[(_arg_nr)]) + ARG_HI_ಸ್ಥಾನಾಂತರ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_arg_val) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, nr))
/* Allow if syscall argument contains only values in mask */
#ವ್ಯಾಖ್ಯಾನಿಸು SC_ALLOW_ARG_ಮುಖವಾಡ(_nr, _arg_nr, arg_ಮುಖವಾಡ) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, ವಾದಗಳು[(_arg_nr)]) + ARG_LO_ಸ್ಥಾನಾಂತರ), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_ಮುಖವಾಡ) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 4), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, ವಾದಗಳು[(_arg_nr)]) + ARG_HI_ಸ್ಥಾನಾಂತರ), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_ಮುಖವಾಡ) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, nr))
/* Deny unless syscall argument contains only values in mask */
#ವ್ಯಾಖ್ಯಾನಿಸು SC_DENY_UNLESS_ARG_ಮುಖವಾಡ(_nr, _arg_nr, arg_ಮುಖವಾಡ, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, ವಾದಗಳು[(_arg_nr)]) + ARG_LO_ಸ್ಥಾನಾಂತರ), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((arg_ಮುಖವಾಡ) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 3), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, ವಾದಗಳು[(_arg_nr)]) + ARG_HI_ಸ್ಥಾನಾಂತರ), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(arg_ಮುಖವಾಡ) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno)), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, nr))
#ವ್ಯಾಖ್ಯಾನಿಸು SC_DENY_UNLESS_ಮುಖವಾಡ(_nr, _arg_nr, _arg_val, _errno) \
/* Special handling for futex(2) that combines a bitmap and operation number */
#ಆದರೆ defined(__NR_futex) || defined(__NR_futex_time64)
#ವ್ಯಾಖ್ಯಾನಿಸು SC_FUTEX_ಮುಖವಾಡ (FUTEX_ಖಾಸಗಿ_FLAG|FUTEX_CLOCK_REALTIME)
#ವ್ಯಾಖ್ಯಾನಿಸು SC_ALLOW_FUTEX_OP(_nr, _op) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, ವಾದಗಳು[1]) + ARG_LO_ಸ್ಥಾನಾಂತರ), \
	/* mask off allowed bitmap values, low word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~(SC_FUTEX_ಮುಖವಾಡ & 0xFFFFFFFF)), \
	/* test operation number, low word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ((_op) & 0xFFFFFFFF), 0, 4), \
	/* load syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, ವಾದಗಳು[1]) + ARG_HI_ಸ್ಥಾನಾಂತರ), \
	/* mask off allowed bitmap values, high word */ \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)SC_FUTEX_ಮುಖವಾಡ >> 32)) & 0xFFFFFFFF)), \
	/* test operation number, high word */ \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_op) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, nr))

/* Use this for both __NR_futex and __NR_futex_time64 */
# define SC_FUTEX(_nr) \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE_BITSET), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_REQUEUE), \
	SC_ALLOW_FUTEX_OP(_nr, FUTEX_CMP_REQUEUE)
#ಆದರೆ_ಅಂತ್ಯ /* __NR_futex || __NR_futex_time64 */

#ಆದರೆ defined(__NR_mmap) || defined(__NR_mmap2)
# ifdef MAP_FIXED_NOREPLACE
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_FIXED_NOREPLACE
# ಇಲ್ಲದಿದ್ದರೆ
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED
# endif /* MAP_FIXED_NOREPLACE */
/* Use this for both __NR_mmap and __NR_mmap2 variants */
# define SC_MMAP(_nr) \
	SC_DENY_UNLESS_ARG_ಮುಖವಾಡ(_nr, 3, SC_MMAP_FLAGS, EINVAL), \
	SC_ALLOW_ARG_ಮುಖವಾಡ(_nr, 2, PROT_READ|PROT_WRITE|PROT_NONE)
#ಆದರೆ_ಅಂತ್ಯ /* __NR_mmap || __NR_mmap2 */

/* Special handling for setsockopt(2) */
#ವ್ಯಾಖ್ಯಾನಿಸು SC_ALLOW_SETSOCKOPT(_level, _optname) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_setsockopt, 0, 10), \
	/* load and test level, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, ವಾದಗಳು[1]) + ARG_LO_ಸ್ಥಾನಾಂತರ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_level) & 0xFFFFFFFF), 0, 7), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, ವಾದಗಳು[1]) + ARG_HI_ಸ್ಥಾನಾಂತರ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 5), \
	/* load and test optname, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, ವಾದಗಳು[2]) + ARG_LO_ಸ್ಥಾನಾಂತರ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_optname) & 0xFFFFFFFF), 0, 3), \
	/* load and test level high word is zero */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, ವಾದಗಳು[2]) + ARG_HI_ಸ್ಥಾನಾಂತರ), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, nr))

/* Syscall filtering set for preauth. */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ sock_filter preauth_insns[] = {
	/* Ensure the syscall arch convention is as expected. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
	/* Load the syscall number for checking. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(ರಚನೆ seccomp_ದತ್ತಾಂಶ, nr)),

	/* Syscalls to non-fatally deny */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_lstat
	SC_DENY(__NR_lstat, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_lstat64
	SC_DENY(__NR_lstat64, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_fstat
	SC_DENY(__NR_fstat, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_fstat64
	SC_DENY(__NR_fstat64, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_fstatat64
	SC_DENY(__NR_fstatat64, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_open
	SC_DENY(__NR_open, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_openat
	SC_DENY(__NR_openat, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_newfstatat
	SC_DENY(__NR_newfstatat, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_stat
	SC_DENY(__NR_stat, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_stat64
	SC_DENY(__NR_stat64, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_shmget
	SC_DENY(__NR_shmget, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_shmat
	SC_DENY(__NR_shmat, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_shmdt
	SC_DENY(__NR_shmdt, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_ipc
	SC_DENY(__NR_ipc, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_statx
	SC_DENY(__NR_statx, EACCES),
#ಆದರೆ_ಅಂತ್ಯ

	/* Syscalls to permit */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_brk
	SC_ALLOW(__NR_brk),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_clock_gettime
	SC_ALLOW(__NR_clock_gettime),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_clock_gettime64
	SC_ALLOW(__NR_clock_gettime64),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_close
	SC_ALLOW(__NR_close),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_exit
	SC_ALLOW(__NR_exit),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_exit_group
	SC_ALLOW(__NR_exit_group),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_futex
	SC_FUTEX(__NR_futex),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_futex_time64
	SC_FUTEX(__NR_futex_time64),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_geteuid
	SC_ALLOW(__NR_geteuid),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_geteuid32
	SC_ALLOW(__NR_geteuid32),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_getpgid
	SC_ALLOW(__NR_getpgid),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_getpid
	SC_ALLOW(__NR_getpid),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_getrandom
	SC_ALLOW(__NR_getrandom),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_gettid
	SC_ALLOW(__NR_gettid),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_gettimeofday
	SC_ALLOW(__NR_gettimeofday),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_getuid
	SC_ALLOW(__NR_getuid),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_getuid32
	SC_ALLOW(__NR_getuid32),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_madvise
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
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_mmap
	SC_MMAP(__NR_mmap),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_mmap2
	SC_MMAP(__NR_mmap2),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_mprotect
	SC_ALLOW_ARG_ಮುಖವಾಡ(__NR_mprotect, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_mremap
	SC_ALLOW_ARG_ಮುಖವಾಡ(__NR_mremap, 3, MREMAP_MAYMOVE),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_munmap
	SC_ALLOW(__NR_munmap),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_nanosleep
	SC_ALLOW(__NR_nanosleep),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_clock_nanosleep
	SC_ALLOW(__NR_clock_nanosleep),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_clock_nanosleep_time64
	SC_ALLOW(__NR_clock_nanosleep_time64),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR__newselect
	SC_ALLOW(__NR__newselect),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_ppoll
	SC_ALLOW(__NR_ppoll),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_ppoll_time64
	SC_ALLOW(__NR_ppoll_time64),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_poll
	SC_ALLOW(__NR_poll),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_pselect6
	SC_ALLOW(__NR_pselect6),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_pselect6_time64
	SC_ALLOW(__NR_pselect6_time64),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_read
	SC_ALLOW(__NR_read),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_riscv_hwprobe
	SC_ALLOW(__NR_riscv_hwprobe),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_rt_sigprocmask
	SC_ALLOW(__NR_rt_sigprocmask),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_select
	SC_ALLOW(__NR_select),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_shutdown
	SC_ALLOW(__NR_shutdown),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_sigprocmask
	SC_ALLOW(__NR_sigprocmask),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_time
	SC_ALLOW(__NR_time),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_write
	SC_ALLOW(__NR_write),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_writev
	SC_ALLOW(__NR_writev),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_getsockopt
	SC_ALLOW(__NR_getsockopt),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_getsockname
	SC_ALLOW(__NR_getsockname),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_getpeername
	SC_ALLOW(__NR_getpeername),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_uname
	SC_ALLOW(__NR_uname),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_restart_syscall
	SC_ALLOW(__NR_restart_syscall),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_setsockopt
	SC_ALLOW_SETSOCKOPT(IPPROTO_IPV6, IPV6_TCLASS),
	SC_ALLOW_SETSOCKOPT(IPPROTO_IP, IP_TOS),
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __NR_socketcall
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETPEERNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKNAME),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_GETSOCKOPT),
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
	SC_DENY(__NR_socketcall, EACCES),
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(__NR_ioctl) && defined(__s390__)
	/* Allow ioctls for ICA crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, Z90_STAT_ಸ್ಥಿತಿ_ಮುಖವಾಡ),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSAMODEXPO),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSACRT),
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSECSENDCPRB),
	/* Allow ioctls for EP11 crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSENDEP11CPRB),
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(__x86_64__) && defined(__ILP32__) && defined(__X32_SYSCALL_BIT)
	/*
	 * On Linux x32, the clock_gettime VDSO falls back to the
	 * x86-64 syscall under some circumstances, e.g.
	 * https://bugs.debian.org/849923
	 */
	SC_ALLOW(__NR_clock_gettime & ~__X32_SYSCALL_BIT),
#ಆದರೆ_ಅಂತ್ಯ

	/* Default deny */
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ sock_fprog preauth_ಕಾರ್ಯಕ್ರಮ = {
	.len = (ಚಿಹ್ನೆರಹಿತ ಗಿಡ್ಡ)(ಗಾತ್ರ(preauth_insns)/ಗಾತ್ರ(preauth_insns[0])),
	.filter = (ರಚನೆ sock_filter *)preauth_insns,
};

ರಚನೆ ssh_sandbox {
	ಪೂರ್ಣಾಂಕ junk;
};

ರಚನೆ ssh_sandbox *
ssh_sandbox_init(ರಚನೆ monitor *monitor)
{
	ರಚನೆ ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing seccomp filter sandbox");
	box = xcalloc(1, ಗಾತ್ರ(*box));
	ಹಿಂತಿರುಗಿ box;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SANDBOX_SECCOMP_FILTER_DEBUG
ಬಾಹ್ಯ ರಚನೆ monitor *pmonitor;
ಶೂನ್ಯ mm_log_handler(LogLevel level, ಪೂರ್ಣಾಂಕ forced, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಂದೇಶ, ಶೂನ್ಯ *ctx);

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_sandbox_violation(ಪೂರ್ಣಾಂಕ signum, siginfo_t *info, ಶೂನ್ಯ *void_context)
{
	ಅಕ್ಷರ ಸಂದೇಶ[256];

	snprintf(ಸಂದೇಶ, ಗಾತ್ರ(ಸಂದೇಶ),
	    "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)",
	    __func__, info->si_arch, info->si_syscall, info->si_call_addr);
	mm_log_handler(SYSLOG_LEVEL_FATAL, 0, ಸಂದೇಶ, pmonitor);
	_exit(1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_sandbox_ಮಗು_debugging(ಶೂನ್ಯ)
{
	ರಚನೆ sigaction act;
	sigset_t ಮುಖವಾಡ;

	debug3_f("installing SIGSYS handler");
	memset(&act, 0, ಗಾತ್ರ(act));
	sigemptyset(&ಮುಖವಾಡ);
	sigaddset(&ಮುಖವಾಡ, SIGSYS);

	act.sa_sigaction = &ssh_sandbox_violation;
	act.sa_flags = SA_SIGINFO;
	ಆದರೆ (sigaction(SIGSYS, &act, ಖಾಲಿ) == -1)
		fatal_f("sigaction(SIGSYS): %s", strerror(errno));
	ಆದರೆ (sigprocmask(SIG_UNBLOCK, &ಮುಖವಾಡ, ಖಾಲಿ) == -1)
		fatal("%s: sigprocmask(SIGSYS): %s",
		    __func__, strerror(errno));
}
#ಆದರೆ_ಅಂತ್ಯ /* SANDBOX_SECCOMP_FILTER_DEBUG */

ಶೂನ್ಯ
ssh_sandbox_ಮಗು(ರಚನೆ ssh_sandbox *box)
{
	ರಚನೆ rlimit rl_zero, rl_one = {.rlim_cur = 1, .rlim_max = 1};

	/* Set rlimits for completeness if possible. */
	rl_zero.rlim_cur = rl_zero.rlim_max = 0;
	ಆದರೆ (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			__func__, strerror(errno));
	/*
	 * Cannot use zero for nfds, because poll(2) will fail with
	 * errno=EINVAL if npfds>RLIMIT_NOFILE.
	 */
	ಆದರೆ (setrlimit(RLIMIT_NOFILE, &rl_one) == -1)
		fatal("%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s",
			__func__, strerror(errno));
	ಆದರೆ (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal("%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			__func__, strerror(errno));

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SANDBOX_SECCOMP_FILTER_DEBUG
	ssh_sandbox_ಮಗು_debugging();
#ಆದರೆ_ಅಂತ್ಯ /* SANDBOX_SECCOMP_FILTER_DEBUG */

	debug3_f("setting PR_SET_NO_NEW_PRIVS");
	ಆದರೆ (prctl(PR_ಗಣ_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatal_f("prctl(PR_SET_NO_NEW_PRIVS): %s", strerror(errno));
	debug3_f("attaching seccomp filter program");
	ಆದರೆ (prctl(PR_ಗಣ_SECCOMP, SECCOMP_ಬಹುಲಕ_FILTER, &preauth_ಕಾರ್ಯಕ್ರಮ) == -1)
		fatal_f("prctl(PR_SET_SECCOMP): %s", strerror(errno));
}

#ಆದರೆ_ಅಂತ್ಯ /* SANDBOX_SECCOMP_FILTER */
