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
sshbuf_بھرو_fd(صحیح fd, ساخت sshbuf **blobp)
{
	u_char buf[4096];
	سائز_t len;
	ساخت stat st;
	صحیح r;
	ساخت sshbuf *blob;

	*blobp = تہی;

	اگر (fstat(fd, &st) == -1)
		واپس SSH_ERR_SYSTEM_ERROR;
	اگر (S_ISREG(st.st_mode) && st.st_size > SSHBUF_سائز_MAX)
		واپس SSH_ERR_INVALID_FORMAT;
	اگر ((blob = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	برائے (;;) {
		اگر ((len = atomicio(اقرأ, fd, buf, حجم(buf))) == 0) {
			اگر (errno == EPIPE)
				توڑو;
			r = SSH_ERR_SYSTEM_ERROR;
			جاؤ برآمد;
		}
		اگر ((r = sshbuf_put(blob, buf, len)) != 0)
			جاؤ برآمد;
		اگر (sshbuf_len(blob) > SSHBUF_سائز_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
	}
	اگر (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_بدلا;
		جاؤ برآمد;
	}
	/* success */
	*blobp = blob;
	blob = تہی; /* transferred */
	r = 0;
 برآمد:
	explicit_bzero(buf, حجم(buf));
	sshbuf_free(blob);
	واپس r;
}

صحیح
sshbuf_بھرو_file(ثابت حرف *راستہ, ساخت sshbuf **bufp)
{
	صحیح r, fd, oerrno;

	*bufp = تہی;
	اگر ((fd = open(راستہ, O_RDONLY)) == -1)
		واپس SSH_ERR_SYSTEM_ERROR;
	اگر ((r = sshbuf_بھرو_fd(fd, bufp)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	oerrno = errno;
	close(fd);
	اگر (r != 0)
		errno = oerrno;
	واپس r;
}

صحیح
sshbuf_write_file(ثابت حرف *راستہ, ساخت sshbuf *buf)
{
	صحیح fd, oerrno;

	اگر ((fd = open(راستہ, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		واپس SSH_ERR_SYSTEM_ERROR;
	اگر (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(راستہ);
		errno = oerrno;
		واپس SSH_ERR_SYSTEM_ERROR;
	}
	واپس 0;
}

