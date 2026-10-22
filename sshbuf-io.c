/*	$OpenBSD: sshbuf-io.c,v 1.4 2026/07/05 00:16:21 djm Exp $ */
/*
 * Copyright (c) 2011 Damien Miller
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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "atomicio.h"

/* Load a file from a fd into a buffer */
पूर्णाङ्क
sshbuf_load_fd(पूर्णाङ्क fd, संरचना sshbuf **blobp)
{
	u_char buf[4096];
	size_t len;
	संरचना stat st;
	पूर्णाङ्क r;
	संरचना sshbuf *blob;

	*blobp = रिक्त;

	जइ (fstat(fd, &st) == -1)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	जइ (S_ISREG(st.st_mode) && st.st_size > SSHBUF_SIZE_MAX)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	जइ ((blob = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	प्रति (;;) {
		जइ ((len = atomicio(पठ, fd, buf, परिमाण(buf))) == 0) {
			जइ (errno == EPIPE)
				भङ्ग;
			r = SSH_ERR_SYSTEM_ERROR;
			गच्छ out;
		}
		जइ ((r = sshbuf_put(blob, buf, len)) != 0)
			गच्छ out;
		जइ (sshbuf_len(blob) > SSHBUF_SIZE_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
	}
	जइ (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		गच्छ out;
	}
	/* success */
	*blobp = blob;
	blob = रिक्त; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, परिमाण(buf));
	sshbuf_free(blob);
	प्रत्यागम r;
}

पूर्णाङ्क
sshbuf_load_file(ध्रुव वर्ण *path, संरचना sshbuf **bufp)
{
	पूर्णाङ्क r, fd, oerrno;

	*bufp = रिक्त;
	जइ ((fd = open(path, O_RDONLY)) == -1)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	जइ ((r = sshbuf_load_fd(fd, bufp)) != 0)
		गच्छ out;
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	जइ (r != 0)
		errno = oerrno;
	प्रत्यागम r;
}

पूर्णाङ्क
sshbuf_write_file(ध्रुव वर्ण *path, संरचना sshbuf *buf)
{
	पूर्णाङ्क fd, oerrno;

	जइ ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	जइ (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(path);
		errno = oerrno;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}
	प्रत्यागम 0;
}

