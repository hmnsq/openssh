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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "atomicio.h"

/* Load a file from a fd into a buffer */
முழு
sshbuf_load_fd(முழு fd, கட்டமைப்பு sshbuf **blobp)
{
	u_char buf[4096];
	size_t len;
	கட்டமைப்பு stat st;
	முழு r;
	கட்டமைப்பு sshbuf *blob;

	*blobp = வெற்று;

	எனில் (fstat(fd, &st) == -1)
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	எனில் (S_ISREG(st.st_mode) && st.st_size > SSHBUF_SIZE_MAX)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	எனில் ((blob = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	க்கு (;;) {
		எனில் ((len = atomicio(பட, fd, buf, அளவு(buf))) == 0) {
			எனில் (errno == EPIPE)
				நிறுத்து;
			r = SSH_ERR_SYSTEM_ERROR;
			செல் out;
		}
		எனில் ((r = sshbuf_put(blob, buf, len)) != 0)
			செல் out;
		எனில் (sshbuf_len(blob) > SSHBUF_SIZE_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
	}
	எனில் (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		செல் out;
	}
	/* success */
	*blobp = blob;
	blob = வெற்று; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, அளவு(buf));
	sshbuf_free(blob);
	திரும்பு r;
}

முழு
sshbuf_load_file(மாறிலி எழுத்து *path, கட்டமைப்பு sshbuf **bufp)
{
	முழு r, fd, oerrno;

	*bufp = வெற்று;
	எனில் ((fd = open(path, O_RDONLY)) == -1)
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	எனில் ((r = sshbuf_load_fd(fd, bufp)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	எனில் (r != 0)
		errno = oerrno;
	திரும்பு r;
}

முழு
sshbuf_write_file(மாறிலி எழுத்து *path, கட்டமைப்பு sshbuf *buf)
{
	முழு fd, oerrno;

	எனில் ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	எனில் (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(path);
		errno = oerrno;
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	}
	திரும்பு 0;
}

