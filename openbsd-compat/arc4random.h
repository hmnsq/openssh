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

#నిర్వచితమైతే HAVE_SYS_MMAN_H
#అన్తర్భావ <sys/mman.h>
#అయితే_ముగింపు

#అన్తర్భావ <signal.h>

/* OpenSSH isn't multithreaded */
#నిర్వచించు ARC4_తాళం()
#నిర్వచించు _ARC4_UNLOCK()
#నిర్వచించు _ARC4_ATFORK(f)

స్థిర అంతఃవరుస శూన్య
_getentropy_fail(శూన్య)
{
	fatal("getentropy failed");
}

స్థిర అస్థిర sig_atomic_t _rs_forked;

స్థిర అంతఃవరుస శూన్య
_rs_forkhandler(శూన్య)
{
	_rs_forked = 1;
}

స్థిర అంతఃవరుస శూన్య
_rs_forkdetect(శూన్య)
{
	స్థిర pid_t _rs_pid = 0;
	pid_t pid = getpid();

	ఒకవేళ (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		ఒకవేళ (rs)
			memset(rs, 0, పరిమాణం(*rs));
	}
}

స్థిర అంతఃవరుస పూర్ణాంకం
_rs_allocate(నిర్మాణం _rs **rsp, నిర్మాణం _rsx **rsxp)
{
#ఒకవేళ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	ఒకవేళ ((*rsp = mmap(ఖాళీ, పరిమాణం(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		తిరిగి (-1);

	ఒకవేళ ((*rsxp = mmap(ఖాళీ, పరిమాణం(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, పరిమాణం(**rsp));
		*rsp = ఖాళీ;
		తిరిగి (-1);
	}
#లేకపోతే
	ఒకవేళ ((*rsp = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(**rsp))) == ఖాళీ)
		తిరిగి (-1);
	ఒకవేళ ((*rsxp = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(**rsxp))) == ఖాళీ) {
		విడుదల(*rsp);
		*rsp = ఖాళీ;
		తిరిగి (-1);
	}
#అయితే_ముగింపు /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	తిరిగి (0);
}
