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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "atomicio.h"

/* Load a file from a fd into a buffer */
પૂર્ણાંક
sshbuf_load_fd(પૂર્ણાંક fd, સંરચના sshbuf **blobp)
{
	u_char buf[4096];
	size_t len;
	સંરચના stat st;
	પૂર્ણાંક r;
	સંરચના sshbuf *blob;

	*blobp = ખાલી;

	જો (fstat(fd, &st) == -1)
		પાછા SSH_ERR_SYSTEM_ERROR;
	જો (S_ISREG(st.st_mode) && st.st_size > SSHBUF_SIZE_MAX)
		પાછા SSH_ERR_INVALID_FORMAT;
	જો ((blob = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	માટે (;;) {
		જો ((len = atomicio(પઠ, fd, buf, કદ(buf))) == 0) {
			જો (errno == EPIPE)
				તોડો;
			r = SSH_ERR_SYSTEM_ERROR;
			જાઓ out;
		}
		જો ((r = sshbuf_put(blob, buf, len)) != 0)
			જાઓ out;
		જો (sshbuf_len(blob) > SSHBUF_SIZE_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
	}
	જો (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		જાઓ out;
	}
	/* success */
	*blobp = blob;
	blob = ખાલી; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, કદ(buf));
	sshbuf_free(blob);
	પાછા r;
}

પૂર્ણાંક
sshbuf_load_file(અચલ અક્ષર *path, સંરચના sshbuf **bufp)
{
	પૂર્ણાંક r, fd, oerrno;

	*bufp = ખાલી;
	જો ((fd = open(path, O_RDONLY)) == -1)
		પાછા SSH_ERR_SYSTEM_ERROR;
	જો ((r = sshbuf_load_fd(fd, bufp)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	જો (r != 0)
		errno = oerrno;
	પાછા r;
}

પૂર્ણાંક
sshbuf_write_file(અચલ અક્ષર *path, સંરચના sshbuf *buf)
{
	પૂર્ણાંક fd, oerrno;

	જો ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		પાછા SSH_ERR_SYSTEM_ERROR;
	જો (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(path);
		errno = oerrno;
		પાછા SSH_ERR_SYSTEM_ERROR;
	}
	પાછા 0;
}

