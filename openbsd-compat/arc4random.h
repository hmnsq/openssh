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
#شامل <sys/mman.h>
#endif

#شامل <signal.h>

/* OpenSSH isn't multithreaded */
#define _ARC4_LOCK()
#define _ARC4_UNLOCK()
#define _ARC4_ATFORK(f)

ایستا درونخطی تهی
_getentropy_fail(تهی)
{
	fatal("getentropy failed");
}

ایستا فرار sig_atomic_t _rs_forked;

ایستا درونخطی تهی
_rs_forkhandler(تهی)
{
	_rs_forked = 1;
}

ایستا درونخطی تهی
_rs_forkdetect(تهی)
{
	ایستا pid_t _rs_pid = 0;
	pid_t pid = getpid();

	اگر (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		اگر (rs)
			memset(rs, 0, اندازه(*rs));
	}
}

ایستا درونخطی صحیح
_rs_allocate(ساختار _rs **rsp, ساختار _rsx **rsxp)
{
#اگر defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	اگر ((*rsp = mmap(پوچ, اندازه(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		بازگشت (-1);

	اگر ((*rsxp = mmap(پوچ, اندازه(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, اندازه(**rsp));
		*rsp = پوچ;
		بازگشت (-1);
	}
#وگرنه
	اگر ((*rsp = calloc(1, اندازه(**rsp))) == پوچ)
		بازگشت (-1);
	اگر ((*rsxp = calloc(1, اندازه(**rsxp))) == پوچ) {
		آزاد(*rsp);
		*rsp = پوچ;
		بازگشت (-1);
	}
#endif /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	بازگشت (0);
}
