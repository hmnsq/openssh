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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <unistd.h>
#ضمن <string.h>

#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "atomicio.h"

/* Load a file from a fd into a buffer */
صحيح
sshbuf_بارگیری_fd(صحيح fd, بنية sshbuf **blobp)
{
	u_char buf[4096];
	اندازه_t len;
	بنية stat st;
	صحيح r;
	بنية sshbuf *blob;

	*blobp = عدم;

	إذا (fstat(fd, &st) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;
	إذا (S_ISREG(st.st_mode) && st.st_size > SSHBUF_اندازه_MAX)
		أرجع SSH_ERR_INVALID_FORMAT;
	إذا ((blob = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	لكل (;;) {
		إذا ((len = atomicio(اقرأ, fd, buf, حجم(buf))) == 0) {
			إذا (errno == EPIPE)
				اكسر;
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب بیرون;
		}
		إذا ((r = sshbuf_put(blob, buf, len)) != 0)
			اذهب بیرون;
		إذا (sshbuf_len(blob) > SSHBUF_اندازه_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بیرون;
		}
	}
	إذا (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_تغییریافته;
		اذهب بیرون;
	}
	/* success */
	*blobp = blob;
	blob = عدم; /* transferred */
	r = 0;
 بیرون:
	explicit_bzero(buf, حجم(buf));
	sshbuf_free(blob);
	أرجع r;
}

صحيح
sshbuf_بارگیری_file(ثابت حرف *مسیر, بنية sshbuf **bufp)
{
	صحيح r, fd, oerrno;

	*bufp = عدم;
	إذا ((fd = open(مسیر, O_RDONLY)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;
	إذا ((r = sshbuf_بارگیری_fd(fd, bufp)) != 0)
		اذهب بیرون;
	/* success */
	r = 0;
 بیرون:
	oerrno = errno;
	close(fd);
	إذا (r != 0)
		errno = oerrno;
	أرجع r;
}

صحيح
sshbuf_write_file(ثابت حرف *مسیر, بنية sshbuf *buf)
{
	صحيح fd, oerrno;

	إذا ((fd = open(مسیر, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;
	إذا (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(مسیر);
		errno = oerrno;
		أرجع SSH_ERR_SYSTEM_ERROR;
	}
	أرجع 0;
}

