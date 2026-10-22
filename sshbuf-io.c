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
sshbuf_load_fd(صحيح fd, بنية sshbuf **blobp)
{
	u_char buf[4096];
	size_t len;
	بنية stat st;
	صحيح r;
	بنية sshbuf *blob;

	*blobp = عدم;

	ܐܢ (fstat(fd, &st) == -1)
		ܦܢܐ SSH_ERR_SYSTEM_ERROR;
	ܐܢ (S_ISREG(st.st_mode) && st.st_size > SSHBUF_SIZE_MAX)
		ܦܢܐ SSH_ERR_INVALID_FORMAT;
	ܐܢ ((blob = sshbuf_new()) == عدم)
		ܦܢܐ SSH_ERR_ALLOC_FAIL;
	لكل (;;) {
		ܐܢ ((len = atomicio(اقرأ, fd, buf, حجم(buf))) == 0) {
			ܐܢ (errno == EPIPE)
				اكسر;
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب out;
		}
		ܐܢ ((r = sshbuf_put(blob, buf, len)) != 0)
			اذهب out;
		ܐܢ (sshbuf_len(blob) > SSHBUF_SIZE_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}
	ܐܢ (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		اذهب out;
	}
	/* success */
	*blobp = blob;
	blob = عدم; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, حجم(buf));
	sshbuf_free(blob);
	ܦܢܐ r;
}

صحيح
sshbuf_load_file(ثابت حرف *path, بنية sshbuf **bufp)
{
	صحيح r, fd, oerrno;

	*bufp = عدم;
	ܐܢ ((fd = open(path, O_RDONLY)) == -1)
		ܦܢܐ SSH_ERR_SYSTEM_ERROR;
	ܐܢ ((r = sshbuf_load_fd(fd, bufp)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	ܐܢ (r != 0)
		errno = oerrno;
	ܦܢܐ r;
}

صحيح
sshbuf_write_file(ثابت حرف *path, بنية sshbuf *buf)
{
	صحيح fd, oerrno;

	ܐܢ ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		ܦܢܐ SSH_ERR_SYSTEM_ERROR;
	ܐܢ (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(path);
		errno = oerrno;
		ܦܢܐ SSH_ERR_SYSTEM_ERROR;
	}
	ܦܢܐ 0;
}

