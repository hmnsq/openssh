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

#अगर_घोषित HAVE_SYS_MMAN_H
#समावेश <sys/mman.h>
#पूर्ण_अगर

#समावेश <signal.h>

/* OpenSSH isn't multithreaded */
#घोषणा _ARC4_LOCK()
#घोषणा _ARC4_UNLOCK()
#घोषणा _ARC4_ATFORK(f)

अटल अंतरभूत व्योम
_getentropy_fail(व्योम)
{
	fatal("getentropy failed");
}

अटल अस्थिर संक_पूर्ण_प्रकार _rs_forked;

अटल अंतरभूत व्योम
_rs_forkhandler(व्योम)
{
	_rs_forked = 1;
}

अटल अंतरभूत व्योम
_rs_forkdetect(व्योम)
{
	अटल pid_t _rs_pid = 0;
	pid_t pid = getpid();

	अगर (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		अगर (rs)
			स_रखो(rs, 0, माप(*rs));
	}
}

अटल अंतरभूत पूर्णांक
_rs_allocate(काष्ठा _rs **rsp, काष्ठा _rsx **rsxp)
{
#अगर defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	अगर ((*rsp = mmap(शून्य, माप(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		वापस (-1);

	अगर ((*rsxp = mmap(शून्य, माप(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, माप(**rsp));
		*rsp = शून्य;
		वापस (-1);
	}
#अन्यथा
	अगर ((*rsp = सुस्मृति(1, माप(**rsp))) == शून्य)
		वापस (-1);
	अगर ((*rsxp = सुस्मृति(1, माप(**rsxp))) == शून्य) {
		मुक्त(*rsp);
		*rsp = शून्य;
		वापस (-1);
	}
#पूर्ण_अगर /* HAVE_MMAP et al */

	_ARC4_ATFORK(_rs_forkhandler);
	वापस (0);
}
