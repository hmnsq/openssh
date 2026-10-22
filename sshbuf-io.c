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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "atomicio.h"

/* Load a file from a fd into a buffer */
পূর্ণাঙ্ক
sshbuf_load_fd(পূর্ণাঙ্ক fd, সংরচনা sshbuf **blobp)
{
	u_char buf[4096];
	size_t len;
	সংরচনা stat st;
	পূর্ণাঙ্ক r;
	সংরচনা sshbuf *blob;

	*blobp = রিক্ত;

	যদি (fstat(fd, &st) == -1)
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	যদি (S_ISREG(st.st_mode) && st.st_size > SSHBUF_SIZE_MAX)
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	যদি ((blob = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	প্রতি (;;) {
		যদি ((len = atomicio(পঠ, fd, buf, পরিমাণ(buf))) == 0) {
			যদি (errno == EPIPE)
				ভঙ্গ;
			r = SSH_ERR_SYSTEM_ERROR;
			গচ্ছ out;
		}
		যদি ((r = sshbuf_put(blob, buf, len)) != 0)
			গচ্ছ out;
		যদি (sshbuf_len(blob) > SSHBUF_SIZE_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
	}
	যদি (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		গচ্ছ out;
	}
	/* success */
	*blobp = blob;
	blob = রিক্ত; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, পরিমাণ(buf));
	sshbuf_free(blob);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshbuf_load_file(ধ্রুব বর্ণ *path, সংরচনা sshbuf **bufp)
{
	পূর্ণাঙ্ক r, fd, oerrno;

	*bufp = রিক্ত;
	যদি ((fd = open(path, O_RDONLY)) == -1)
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	যদি ((r = sshbuf_load_fd(fd, bufp)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	যদি (r != 0)
		errno = oerrno;
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshbuf_write_file(ধ্রুব বর্ণ *path, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক fd, oerrno;

	যদি ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	যদি (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(path);
		errno = oerrno;
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	}
	প্রত্যাগম 0;
}

