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
#അന്തര്ഭാവ <sys/mman.h>
#endif

#അന്തര്ഭാവ <signal.h>

/* OpenSSH isn't multithreaded */
#define _ARC4_LOCK()
#define _ARC4_UNLOCK()
#define _ARC4_ATFORK(f)

സ്ഥിതം വരിയിൽ ശൂന്യം
_getentropy_fail(ശൂന്യം)
{
	fatal("getentropy failed");
}

സ്ഥിതം അസ്ഥിര sig_atomic_t _rs_forked;

സ്ഥിതം വരിയിൽ ശൂന്യം
_rs_forkhandler(ശൂന്യം)
{
	_rs_forked = 1;
}

സ്ഥിതം വരിയിൽ ശൂന്യം
_rs_forkdetect(ശൂന്യം)
{
	സ്ഥിതം pid_t _rs_pid = 0;
	pid_t pid = getpid();

	എങ്കിൽ (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		എങ്കിൽ (rs)
			memset(rs, 0, വലുപ്പം(*rs));
	}
}

സ്ഥിതം വരിയിൽ പൂർണ്ണസംഖ്യ
_rs_allocate(ഘടന _rs **rsp, ഘടന _rsx **rsxp)
{
#എങ്കിൽ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	എങ്കിൽ ((*rsp = mmap(ശൂന്യ, വലുപ്പം(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		തിരികെ (-1);

	എങ്കിൽ ((*rsxp = mmap(ശൂന്യ, വലുപ്പം(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, വലുപ്പം(**rsp));
		*rsp = ശൂന്യ;
		തിരികെ (-1);
	}
#അല്ലെങ്കിൽ
	എങ്കിൽ ((*rsp = calloc(1, വലുപ്പം(**rsp))) == ശൂന്യ)
		തിരികെ (-1);
	എങ്കിൽ ((*rsxp = calloc(1, വലുപ്പം(**rsxp))) == ശൂന്യ) {
		സ്വതന്ത്രം(*rsp);
		*rsp = ശൂന്യ;
		തിരികെ (-1);
	}
#endif /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	തിരികെ (0);
}
