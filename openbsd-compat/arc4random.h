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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_MMAN_H
#ಅನ್ತರ್ಭಾವ <sys/mman.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ <signal.h>

/* OpenSSH isn't multithreaded */
#ವ್ಯಾಖ್ಯಾನಿಸು ARC4_ಬೀಗ()
#ವ್ಯಾಖ್ಯಾನಿಸು _ARC4_UNLOCK()
#ವ್ಯಾಖ್ಯಾನಿಸು _ARC4_ATFORK(f)

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
_getentropy_fail(ಶೂನ್ಯ)
{
	fatal("getentropy failed");
}

ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t _rs_forked;

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
_rs_forkhandler(ಶೂನ್ಯ)
{
	_rs_forked = 1;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
_rs_forkdetect(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ pid_t _rs_pid = 0;
	pid_t pid = getpid();

	ಆದರೆ (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		ಆದರೆ (rs)
			memset(rs, 0, ಗಾತ್ರ(*rs));
	}
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಪೂರ್ಣಾಂಕ
_rs_allocate(ರಚನೆ _rs **rsp, ರಚನೆ _rsx **rsxp)
{
#ಆದರೆ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	ಆದರೆ ((*rsp = mmap(ಖಾಲಿ, ಗಾತ್ರ(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		ಹಿಂತಿರುಗಿ (-1);

	ಆದರೆ ((*rsxp = mmap(ಖಾಲಿ, ಗಾತ್ರ(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, ಗಾತ್ರ(**rsp));
		*rsp = ಖಾಲಿ;
		ಹಿಂತಿರುಗಿ (-1);
	}
#ಇಲ್ಲದಿದ್ದರೆ
	ಆದರೆ ((*rsp = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(**rsp))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (-1);
	ಆದರೆ ((*rsxp = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(**rsxp))) == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(*rsp);
		*rsp = ಖಾಲಿ;
		ಹಿಂತಿರುಗಿ (-1);
	}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	ಹಿಂತಿರುಗಿ (0);
}
