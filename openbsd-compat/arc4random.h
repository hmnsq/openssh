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

#که_تعریف_شوی HAVE_SYS_MMAN_H
#ضمن <sys/mman.h>
#د_که_پای

#ضمن <signal.h>

/* OpenSSH isn't multithreaded */
#تعریف_کړه ARC4_قلف()
#تعریف_کړه _ARC4_UNLOCK()
#تعریف_کړه _ARC4_ATFORK(f)

ساكن مضمن فراغ
_getentropy_fail(فراغ)
{
	fatal("getentropy failed");
}

ساكن متطاير sig_atomic_t _rs_forked;

ساكن مضمن فراغ
_rs_forkhandler(فراغ)
{
	_rs_forked = 1;
}

ساكن مضمن فراغ
_rs_forkdetect(فراغ)
{
	ساكن pid_t _rs_pid = 0;
	pid_t pid = getpid();

	إذا (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		إذا (rs)
			memset(rs, 0, حجم(*rs));
	}
}

ساكن مضمن صحيح
_rs_allocate(بنية _rs **rsp, بنية _rsx **rsxp)
{
#إذا defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	إذا ((*rsp = mmap(عدم, حجم(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		أرجع (-1);

	إذا ((*rsxp = mmap(عدم, حجم(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, حجم(**rsp));
		*rsp = عدم;
		أرجع (-1);
	}
#وإلا
	إذا ((*rsp = حافظه_صفر_ورکړه(1, حجم(**rsp))) == عدم)
		أرجع (-1);
	إذا ((*rsxp = حافظه_صفر_ورکړه(1, حجم(**rsxp))) == عدم) {
		حرر(*rsp);
		*rsp = عدم;
		أرجع (-1);
	}
#د_که_پای /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	أرجع (0);
}
