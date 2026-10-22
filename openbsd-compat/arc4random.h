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
#अन्तर्भाव <sys/mman.h>
#endif

#अन्तर्भाव <signal.h>

/* OpenSSH isn't multithreaded */
#define _ARC4_LOCK()
#define _ARC4_UNLOCK()
#define _ARC4_ATFORK(f)

स्थिर अन्तःस्थ शून्य
_getentropy_fail(शून्य)
{
	fatal("getentropy failed");
}

स्थिर चञ्चल संक_पूर्ण_प्रकार _rs_forked;

स्थिर अन्तःस्थ शून्य
_rs_forkhandler(शून्य)
{
	_rs_forked = 1;
}

स्थिर अन्तःस्थ शून्य
_rs_forkdetect(शून्य)
{
	स्थिर pid_t _rs_pid = 0;
	pid_t pid = getpid();

	यदि (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		यदि (rs)
			स_रखो(rs, 0, परिमाण(*rs));
	}
}

स्थिर अन्तःस्थ पूर्णाङ्क
_rs_allocate(संरचना _rs **rsp, संरचना _rsx **rsxp)
{
#यदि defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	यदि ((*rsp = mmap(रिक्त, परिमाण(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		प्रत्यागम (-1);

	यदि ((*rsxp = mmap(रिक्त, परिमाण(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, परिमाण(**rsp));
		*rsp = रिक्त;
		प्रत्यागम (-1);
	}
#अन्यथा
	यदि ((*rsp = सुस्मृति(1, परिमाण(**rsp))) == रिक्त)
		प्रत्यागम (-1);
	यदि ((*rsxp = सुस्मृति(1, परिमाण(**rsxp))) == रिक्त) {
		मुक्त(*rsp);
		*rsp = रिक्त;
		प्रत्यागम (-1);
	}
#endif /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	प्रत्यागम (0);
}
