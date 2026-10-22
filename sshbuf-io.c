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
পূর্ণসংখ্যা
sshbuf_load_fd(পূর্ণসংখ্যা fd, কাঠামো sshbuf **blobp)
{
	u_char buf[4096];
	আকার_t len;
	কাঠামো stat st;
	পূর্ণসংখ্যা r;
	কাঠামো sshbuf *blob;

	*blobp = ফাঁকা;

	যদি (fstat(fd, &st) == -1)
		ফেরত SSH_ERR_SYSTEM_ERROR;
	যদি (S_ISREG(st.st_mode) && st.st_size > SSHBUF_আকার_MAX)
		ফেরত SSH_ERR_INVALID_FORMAT;
	যদি ((blob = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	জন্য (;;) {
		যদি ((len = atomicio(পঠ, fd, buf, আকার(buf))) == 0) {
			যদি (errno == EPIPE)
				বিরতি;
			r = SSH_ERR_SYSTEM_ERROR;
			যাও out;
		}
		যদি ((r = sshbuf_put(blob, buf, len)) != 0)
			যাও out;
		যদি (sshbuf_len(blob) > SSHBUF_আকার_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
	}
	যদি (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		যাও out;
	}
	/* success */
	*blobp = blob;
	blob = ফাঁকা; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, আকার(buf));
	sshbuf_free(blob);
	ফেরত r;
}

পূর্ণসংখ্যা
sshbuf_load_file(ধ্রুবক অক্ষর *path, কাঠামো sshbuf **bufp)
{
	পূর্ণসংখ্যা r, fd, oerrno;

	*bufp = ফাঁকা;
	যদি ((fd = open(path, O_RDONLY)) == -1)
		ফেরত SSH_ERR_SYSTEM_ERROR;
	যদি ((r = sshbuf_load_fd(fd, bufp)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	যদি (r != 0)
		errno = oerrno;
	ফেরত r;
}

পূর্ণসংখ্যা
sshbuf_write_file(ধ্রুবক অক্ষর *path, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা fd, oerrno;

	যদি ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		ফেরত SSH_ERR_SYSTEM_ERROR;
	যদি (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(path);
		errno = oerrno;
		ফেরত SSH_ERR_SYSTEM_ERROR;
	}
	ফেরত 0;
}

