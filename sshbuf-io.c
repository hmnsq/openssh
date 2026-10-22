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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "atomicio.h"

/* Load a file from a fd into a buffer */
പൂർണ്ണസംഖ്യ
sshbuf_load_fd(പൂർണ്ണസംഖ്യ fd, ഘടന sshbuf **blobp)
{
	u_char buf[4096];
	size_t len;
	ഘടന stat st;
	പൂർണ്ണസംഖ്യ r;
	ഘടന sshbuf *blob;

	*blobp = ശൂന്യ;

	എങ്കിൽ (fstat(fd, &st) == -1)
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	എങ്കിൽ (S_ISREG(st.st_mode) && st.st_size > SSHBUF_SIZE_MAX)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	എങ്കിൽ ((blob = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	വേണ്ടി (;;) {
		എങ്കിൽ ((len = atomicio(പഠ, fd, buf, വലുപ്പം(buf))) == 0) {
			എങ്കിൽ (errno == EPIPE)
				നിർത്തുക;
			r = SSH_ERR_SYSTEM_ERROR;
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_put(blob, buf, len)) != 0)
			പോകുക out;
		എങ്കിൽ (sshbuf_len(blob) > SSHBUF_SIZE_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
	}
	എങ്കിൽ (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		പോകുക out;
	}
	/* success */
	*blobp = blob;
	blob = ശൂന്യ; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, വലുപ്പം(buf));
	sshbuf_free(blob);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshbuf_load_file(സ്ഥിരം അക്ഷരം *path, ഘടന sshbuf **bufp)
{
	പൂർണ്ണസംഖ്യ r, fd, oerrno;

	*bufp = ശൂന്യ;
	എങ്കിൽ ((fd = open(path, O_RDONLY)) == -1)
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	എങ്കിൽ ((r = sshbuf_load_fd(fd, bufp)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	എങ്കിൽ (r != 0)
		errno = oerrno;
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshbuf_write_file(സ്ഥിരം അക്ഷരം *path, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ fd, oerrno;

	എങ്കിൽ ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	എങ്കിൽ (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(path);
		errno = oerrno;
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	}
	തിരികെ 0;
}

