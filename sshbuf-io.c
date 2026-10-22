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
ಪೂರ್ಣಾಂಕ
sshbuf_ತುಂಬು_fd(ಪೂರ್ಣಾಂಕ fd, ರಚನೆ sshbuf **blobp)
{
	u_char buf[4096];
	ಗಾತ್ರ_t len;
	ರಚನೆ stat st;
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ sshbuf *blob;

	*blobp = ಖಾಲಿ;

	ಆದರೆ (fstat(fd, &st) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	ಆದರೆ (S_ISREG(st.st_mode) && st.st_size > SSHBUF_ಗಾತ್ರ_MAX)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಆದರೆ ((blob = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಗಾಗಿ (;;) {
		ಆದರೆ ((len = atomicio(ಪಠ, fd, buf, ಗಾತ್ರ(buf))) == 0) {
			ಆದರೆ (errno == EPIPE)
				ನಿಲ್ಲಿಸು;
			r = SSH_ERR_SYSTEM_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_put(blob, buf, len)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ (sshbuf_len(blob) > SSHBUF_ಗಾತ್ರ_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ಆದರೆ (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_ಬದಲಾಯಿತು;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	*blobp = blob;
	blob = ಖಾಲಿ; /* transferred */
	r = 0;
 ಹೊರಹೋಗು:
	explicit_bzero(buf, ಗಾತ್ರ(buf));
	sshbuf_free(blob);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshbuf_ತುಂಬು_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ರಚನೆ sshbuf **bufp)
{
	ಪೂರ್ಣಾಂಕ r, fd, oerrno;

	*bufp = ಖಾಲಿ;
	ಆದರೆ ((fd = open(ಮಾರ್ಗ, O_RDONLY)) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	ಆದರೆ ((r = sshbuf_ತುಂಬು_fd(fd, bufp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	oerrno = errno;
	close(fd);
	ಆದರೆ (r != 0)
		errno = oerrno;
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshbuf_write_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ fd, oerrno;

	ಆದರೆ ((fd = open(ಮಾರ್ಗ, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	ಆದರೆ (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(ಮಾರ್ಗ);
		errno = oerrno;
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	}
	ಹಿಂತಿರುಗಿ 0;
}

