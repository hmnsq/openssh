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

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_MMAN_H
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/mman.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>

/* OpenSSH isn't multithreaded */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ARC4_ਤਾਲਾ()
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _ARC4_UNLOCK()
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _ARC4_ATFORK(f)

ਸਥਿਰ ਸਤਰਅੰਦਰ ਖਾਲੀ
_getentropy_fail(ਖਾਲੀ)
{
	fatal("getentropy failed");
}

ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t _rs_forked;

ਸਥਿਰ ਸਤਰਅੰਦਰ ਖਾਲੀ
_rs_forkhandler(ਖਾਲੀ)
{
	_rs_forked = 1;
}

ਸਥਿਰ ਸਤਰਅੰਦਰ ਖਾਲੀ
_rs_forkdetect(ਖਾਲੀ)
{
	ਸਥਿਰ pid_t _rs_pid = 0;
	pid_t pid = getpid();

	ਜੇ (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		ਜੇ (rs)
			memset(rs, 0, ਆਕਾਰ(*rs));
	}
}

ਸਥਿਰ ਸਤਰਅੰਦਰ ਪੂਰਨ
_rs_allocate(ਬਣਤਰ _rs **rsp, ਬਣਤਰ _rsx **rsxp)
{
#ਜੇ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	ਜੇ ((*rsp = mmap(ਨਿਰਾ, ਆਕਾਰ(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		ਵਾਪਸ (-1);

	ਜੇ ((*rsxp = mmap(ਨਿਰਾ, ਆਕਾਰ(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, ਆਕਾਰ(**rsp));
		*rsp = ਨਿਰਾ;
		ਵਾਪਸ (-1);
	}
#ਨਹੀਂਤਾਂ
	ਜੇ ((*rsp = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(**rsp))) == ਨਿਰਾ)
		ਵਾਪਸ (-1);
	ਜੇ ((*rsxp = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(**rsxp))) == ਨਿਰਾ) {
		ਮੁਕਤ(*rsp);
		*rsp = ਨਿਰਾ;
		ਵਾਪਸ (-1);
	}
#ਜੇ_ਅੰਤ /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	ਵਾਪਸ (0);
}
