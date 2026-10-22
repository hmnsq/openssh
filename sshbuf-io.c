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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <unistd.h>
#شامل <string.h>

#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "atomicio.h"

/* Load a file from a fd into a buffer */
صحیح
sshbuf_load_fd(صحیح fd, ساختار sshbuf **blobp)
{
	u_char buf[4096];
	size_t len;
	ساختار stat st;
	صحیح r;
	ساختار sshbuf *blob;

	*blobp = پوچ;

	اگر (fstat(fd, &st) == -1)
		بازگشت SSH_ERR_SYSTEM_ERROR;
	اگر (S_ISREG(st.st_mode) && st.st_size > SSHBUF_SIZE_MAX)
		بازگشت SSH_ERR_INVALID_FORMAT;
	اگر ((blob = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	برای (;;) {
		اگر ((len = atomicio(اقرأ, fd, buf, اندازه(buf))) == 0) {
			اگر (errno == EPIPE)
				بشکن;
			r = SSH_ERR_SYSTEM_ERROR;
			برو out;
		}
		اگر ((r = sshbuf_put(blob, buf, len)) != 0)
			برو out;
		اگر (sshbuf_len(blob) > SSHBUF_SIZE_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
	}
	اگر (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		برو out;
	}
	/* success */
	*blobp = blob;
	blob = پوچ; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, اندازه(buf));
	sshbuf_free(blob);
	بازگشت r;
}

صحیح
sshbuf_load_file(ثابت نویسه *path, ساختار sshbuf **bufp)
{
	صحیح r, fd, oerrno;

	*bufp = پوچ;
	اگر ((fd = open(path, O_RDONLY)) == -1)
		بازگشت SSH_ERR_SYSTEM_ERROR;
	اگر ((r = sshbuf_load_fd(fd, bufp)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	اگر (r != 0)
		errno = oerrno;
	بازگشت r;
}

صحیح
sshbuf_write_file(ثابت نویسه *path, ساختار sshbuf *buf)
{
	صحیح fd, oerrno;

	اگر ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		بازگشت SSH_ERR_SYSTEM_ERROR;
	اگر (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(path);
		errno = oerrno;
		بازگشت SSH_ERR_SYSTEM_ERROR;
	}
	بازگشت 0;
}

