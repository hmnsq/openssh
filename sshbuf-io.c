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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"

/* Load a file from a fd into a buffer */
ਪੂਰਨ
sshbuf_ਲੱਦੋ_fd(ਪੂਰਨ fd, ਬਣਤਰ sshbuf **blobp)
{
	u_char buf[4096];
	ਮਾਪ_t len;
	ਬਣਤਰ stat st;
	ਪੂਰਨ r;
	ਬਣਤਰ sshbuf *blob;

	*blobp = ਨਿਰਾ;

	ਜੇ (fstat(fd, &st) == -1)
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	ਜੇ (S_ISREG(st.st_mode) && st.st_size > SSHBUF_ਮਾਪ_MAX)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਜੇ ((blob = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਲਈ (;;) {
		ਜੇ ((len = atomicio(ਪਠ, fd, buf, ਆਕਾਰ(buf))) == 0) {
			ਜੇ (errno == EPIPE)
				ਰੋਕੋ;
			r = SSH_ERR_SYSTEM_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_put(blob, buf, len)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ (sshbuf_len(blob) > SSHBUF_ਮਾਪ_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ਜੇ (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_ਬਦਲਿਆ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	*blobp = blob;
	blob = ਨਿਰਾ; /* transferred */
	r = 0;
 ਬਾਹਰਲਾ:
	explicit_bzero(buf, ਆਕਾਰ(buf));
	sshbuf_free(blob);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshbuf_ਲੱਦੋ_file(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਬਣਤਰ sshbuf **bufp)
{
	ਪੂਰਨ r, fd, oerrno;

	*bufp = ਨਿਰਾ;
	ਜੇ ((fd = open(ਰਸਤਾ, O_RDONLY)) == -1)
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	ਜੇ ((r = sshbuf_ਲੱਦੋ_fd(fd, bufp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	oerrno = errno;
	close(fd);
	ਜੇ (r != 0)
		errno = oerrno;
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshbuf_write_file(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ fd, oerrno;

	ਜੇ ((fd = open(ਰਸਤਾ, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	ਜੇ (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(ਰਸਤਾ);
		errno = oerrno;
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	}
	ਵਾਪਸ 0;
}

