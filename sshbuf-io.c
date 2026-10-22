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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"

/* Load a file from a fd into a buffer */
ಪೂರ್ಣಾಙ್ಕ
sshbuf_load_fd(ಪೂರ್ಣಾಙ್ಕ fd, ಸಂರಚನಾ sshbuf **blobp)
{
	u_char buf[4096];
	size_t len;
	ಸಂರಚನಾ stat st;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ sshbuf *blob;

	*blobp = ರಿಕ್ತ;

	ಯದಿ (fstat(fd, &st) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	ಯದಿ (S_ISREG(st.st_mode) && st.st_size > SSHBUF_SIZE_MAX)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಯದಿ ((blob = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಪ್ರತಿ (;;) {
		ಯದಿ ((len = atomicio(ಪಠ, fd, buf, ಪರಿಮಾಣ(buf))) == 0) {
			ಯದಿ (errno == EPIPE)
				ಭಙ್ಗ;
			r = SSH_ERR_SYSTEM_ERROR;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_put(blob, buf, len)) != 0)
			ಗಚ್ಛ out;
		ಯದಿ (sshbuf_len(blob) > SSHBUF_SIZE_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
	}
	ಯದಿ (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		ಗಚ್ಛ out;
	}
	/* success */
	*blobp = blob;
	blob = ರಿಕ್ತ; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, ಪರಿಮಾಣ(buf));
	sshbuf_free(blob);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_load_file(ಧ್ರುವ ವರ್ಣ *path, ಸಂರಚನಾ sshbuf **bufp)
{
	ಪೂರ್ಣಾಙ್ಕ r, fd, oerrno;

	*bufp = ರಿಕ್ತ;
	ಯದಿ ((fd = open(path, O_RDONLY)) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	ಯದಿ ((r = sshbuf_load_fd(fd, bufp)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	ಯದಿ (r != 0)
		errno = oerrno;
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_write_file(ಧ್ರುವ ವರ್ಣ *path, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ fd, oerrno;

	ಯದಿ ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	ಯದಿ (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(path);
		errno = oerrno;
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

