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
#அந்தர்பாவ <sys/mman.h>
#endif

#அந்தர்பாவ <signal.h>

/* OpenSSH isn't multithreaded */
#define _ARC4_LOCK()
#define _ARC4_UNLOCK()
#define _ARC4_ATFORK(f)

நிலையான உள்வரி வெறுமை
_getentropy_fail(வெறுமை)
{
	fatal("getentropy failed");
}

நிலையான நிலையற்ற sig_atomic_t _rs_forked;

நிலையான உள்வரி வெறுமை
_rs_forkhandler(வெறுமை)
{
	_rs_forked = 1;
}

நிலையான உள்வரி வெறுமை
_rs_forkdetect(வெறுமை)
{
	நிலையான pid_t _rs_pid = 0;
	pid_t pid = getpid();

	எனில் (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		எனில் (rs)
			memset(rs, 0, அளவு(*rs));
	}
}

நிலையான உள்வரி முழு
_rs_allocate(கட்டமைப்பு _rs **rsp, கட்டமைப்பு _rsx **rsxp)
{
#எனில் defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	எனில் ((*rsp = mmap(வெற்று, அளவு(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		திரும்பு (-1);

	எனில் ((*rsxp = mmap(வெற்று, அளவு(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, அளவு(**rsp));
		*rsp = வெற்று;
		திரும்பு (-1);
	}
#இல்லையெனில்
	எனில் ((*rsp = calloc(1, அளவு(**rsp))) == வெற்று)
		திரும்பு (-1);
	எனில் ((*rsxp = calloc(1, அளவு(**rsxp))) == வெற்று) {
		விடுவி(*rsp);
		*rsp = வெற்று;
		திரும்பு (-1);
	}
#endif /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	திரும்பு (0);
}
