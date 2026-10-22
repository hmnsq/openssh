/*	$OpenBSD: arc4random_linux.h,v 1.12 2019/07/11 10:37:28 inoguchi Exp $	*/

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2014, Theo de Raadt <deraadt@openbsd.org>
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
 * Stub functions for portability.  From LibreSSL with some adaptations.
 */

#ifdef HAVE_SYS_MMAN_H
#ಅನ್ತರ್ಭಾವ <sys/mman.h>
#endif

#ಅನ್ತರ್ಭಾವ <signal.h>

/* OpenSSH isn't multithreaded */
#define _ARC4_LOCK()
#define _ARC4_UNLOCK()
#define _ARC4_ATFORK(f)

ಸ್ಥಿರ ಅನ್ತಃಸ್ಥ ಶೂನ್ಯ
_getentropy_fail(ಶೂನ್ಯ)
{
	fatal("getentropy failed");
}

ಸ್ಥಿರ ಚಞ್ಚಲ sig_atomic_t _rs_forked;

ಸ್ಥಿರ ಅನ್ತಃಸ್ಥ ಶೂನ್ಯ
_rs_forkhandler(ಶೂನ್ಯ)
{
	_rs_forked = 1;
}

ಸ್ಥಿರ ಅನ್ತಃಸ್ಥ ಶೂನ್ಯ
_rs_forkdetect(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ pid_t _rs_pid = 0;
	pid_t pid = getpid();

	ಯದಿ (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		ಯದಿ (rs)
			memset(rs, 0, ಪರಿಮಾಣ(*rs));
	}
}

ಸ್ಥಿರ ಅನ್ತಃಸ್ಥ ಪೂರ್ಣಾಙ್ಕ
_rs_allocate(ಸಂರಚನಾ _rs **rsp, ಸಂರಚನಾ _rsx **rsxp)
{
#ಯದಿ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	ಯದಿ ((*rsp = mmap(ರಿಕ್ತ, ಪರಿಮಾಣ(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		ಪ್ರತ್ಯಾಗಮ (-1);

	ಯದಿ ((*rsxp = mmap(ರಿಕ್ತ, ಪರಿಮಾಣ(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, ಪರಿಮಾಣ(**rsp));
		*rsp = ರಿಕ್ತ;
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
#ಅನ್ಯಥಾ
	ಯದಿ ((*rsp = calloc(1, ಪರಿಮಾಣ(**rsp))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (-1);
	ಯದಿ ((*rsxp = calloc(1, ಪರಿಮಾಣ(**rsxp))) == ರಿಕ್ತ) {
		ಮುಕ್ತ(*rsp);
		*rsp = ರಿಕ್ತ;
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
#endif /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	ಪ್ರತ್ಯಾಗಮ (0);
}
