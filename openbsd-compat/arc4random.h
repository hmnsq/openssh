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
#ଅନ୍ତର୍ଭାଵ <sys/mman.h>
#endif

#ଅନ୍ତର୍ଭାଵ <signal.h>

/* OpenSSH isn't multithreaded */
#define _ARC4_LOCK()
#define _ARC4_UNLOCK()
#define _ARC4_ATFORK(f)

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ଶୂନ୍ୟ
_getentropy_fail(ଶୂନ୍ୟ)
{
	fatal("getentropy failed");
}

ସ୍ଥିର ଅସ୍ଥିର sig_atomic_t _rs_forked;

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ଶୂନ୍ୟ
_rs_forkhandler(ଶୂନ୍ୟ)
{
	_rs_forked = 1;
}

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ଶୂନ୍ୟ
_rs_forkdetect(ଶୂନ୍ୟ)
{
	ସ୍ଥିର pid_t _rs_pid = 0;
	pid_t pid = getpid();

	ଯଦି (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		ଯଦି (rs)
			memset(rs, 0, ଆକାର(*rs));
	}
}

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ପୂର୍ଣ୍ଣସଂଖ୍ୟା
_rs_allocate(ସଂରଚନା _rs **rsp, ସଂରଚନା _rsx **rsxp)
{
#ଯଦି defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	ଯଦି ((*rsp = mmap(ଖାଲି, ଆକାର(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		ଫେରନ୍ତୁ (-1);

	ଯଦି ((*rsxp = mmap(ଖାଲି, ଆକାର(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, ଆକାର(**rsp));
		*rsp = ଖାଲି;
		ଫେରନ୍ତୁ (-1);
	}
#ଅନ୍ୟଥା
	ଯଦି ((*rsp = calloc(1, ଆକାର(**rsp))) == ଖାଲି)
		ଫେରନ୍ତୁ (-1);
	ଯଦି ((*rsxp = calloc(1, ଆକାର(**rsxp))) == ଖାଲି) {
		ମୁକ୍ତ(*rsp);
		*rsp = ଖାଲି;
		ଫେରନ୍ତୁ (-1);
	}
#endif /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	ଫେରନ୍ତୁ (0);
}
