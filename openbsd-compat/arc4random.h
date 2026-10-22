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
#અન્તર્ભાવ <sys/mman.h>
#endif

#અન્તર્ભાવ <signal.h>

/* OpenSSH isn't multithreaded */
#define _ARC4_LOCK()
#define _ARC4_UNLOCK()
#define _ARC4_ATFORK(f)

સ્થિર અંતઃરેખ શૂન્ય
_getentropy_fail(શૂન્ય)
{
	fatal("getentropy failed");
}

સ્થિર અસ્થિર sig_atomic_t _rs_forked;

સ્થિર અંતઃરેખ શૂન્ય
_rs_forkhandler(શૂન્ય)
{
	_rs_forked = 1;
}

સ્થિર અંતઃરેખ શૂન્ય
_rs_forkdetect(શૂન્ય)
{
	સ્થિર pid_t _rs_pid = 0;
	pid_t pid = getpid();

	જો (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		જો (rs)
			memset(rs, 0, કદ(*rs));
	}
}

સ્થિર અંતઃરેખ પૂર્ણાંક
_rs_allocate(સંરચના _rs **rsp, સંરચના _rsx **rsxp)
{
#જો defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	જો ((*rsp = mmap(ખાલી, કદ(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		પાછા (-1);

	જો ((*rsxp = mmap(ખાલી, કદ(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, કદ(**rsp));
		*rsp = ખાલી;
		પાછા (-1);
	}
#નહીંતર
	જો ((*rsp = calloc(1, કદ(**rsp))) == ખાલી)
		પાછા (-1);
	જો ((*rsxp = calloc(1, કદ(**rsxp))) == ખાલી) {
		મુક્ત(*rsp);
		*rsp = ખાલી;
		પાછા (-1);
	}
#endif /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	પાછા (0);
}
