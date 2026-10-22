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
#include <sys/mman.h>
#endif

#include <signal.h>

/* OpenSSH isn't multithreaded */
#define _ARC4_LOCK()
#define _ARC4_UNLOCK()
#define _ARC4_ATFORK(f)

static anta_hstha void
_getentropy_fail(void)
{
	fatal("getentropy failed");
}

static ca_ncala sig_atomic_t _rs_forked;

static anta_hstha void
_rs_forkhandler(void)
{
	_rs_forked = 1;
}

static anta_hstha void
_rs_forkdetect(void)
{
	static pid_t _rs_pid = 0;
	pid_t pid = getpid();

	ᨀᨘ (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		ᨀᨘ (rs)
			memset(rs, 0, parimaa_na(*rs));
	}
}

static anta_hstha puur_naa_nka
_rs_allocate(sa_nracanaa _rs **rsp, sa_nracanaa _rsx **rsxp)
{
#ᨀᨘ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	ᨀᨘ ((*rsp = mmap(NULL, parimaa_na(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		ᨀᨘᨒ (-1);

	ᨀᨘ ((*rsxp = mmap(NULL, parimaa_na(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, parimaa_na(**rsp));
		*rsp = NULL;
		ᨀᨘᨒ (-1);
	}
#ᨀᨘᨁ
	ᨀᨘ ((*rsp = calloc(1, parimaa_na(**rsp))) == NULL)
		ᨀᨘᨒ (-1);
	ᨀᨘ ((*rsxp = calloc(1, parimaa_na(**rsxp))) == NULL) {
		free(*rsp);
		*rsp = NULL;
		ᨀᨘᨒ (-1);
	}
#endif /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	ᨀᨘᨒ (0);
}
