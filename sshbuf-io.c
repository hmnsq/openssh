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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"

/* Load a file from a fd into a buffer */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_load_fd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ସଂରଚନା sshbuf **blobp)
{
	u_char buf[4096];
	size_t len;
	ସଂରଚନା stat st;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା sshbuf *blob;

	*blobp = ଖାଲି;

	ଯଦି (fstat(fd, &st) == -1)
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	ଯଦି (S_ISREG(st.st_mode) && st.st_size > SSHBUF_SIZE_MAX)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଯଦି ((blob = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ପାଇଁ (;;) {
		ଯଦି ((len = atomicio(ପଠ, fd, buf, ଆକାର(buf))) == 0) {
			ଯଦି (errno == EPIPE)
				ଭାଙ୍ଗ;
			r = SSH_ERR_SYSTEM_ERROR;
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_put(blob, buf, len)) != 0)
			ଯାଅ out;
		ଯଦି (sshbuf_len(blob) > SSHBUF_SIZE_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
	}
	ଯଦି (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		ଯାଅ out;
	}
	/* success */
	*blobp = blob;
	blob = ଖାଲି; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, ଆକାର(buf));
	sshbuf_free(blob);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_load_file(ଅଚଳ ଅକ୍ଷର *path, ସଂରଚନା sshbuf **bufp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, fd, oerrno;

	*bufp = ଖାଲି;
	ଯଦି ((fd = open(path, O_RDONLY)) == -1)
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	ଯଦି ((r = sshbuf_load_fd(fd, bufp)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	ଯଦି (r != 0)
		errno = oerrno;
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_write_file(ଅଚଳ ଅକ୍ଷର *path, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, oerrno;

	ଯଦି ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	ଯଦି (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(path);
		errno = oerrno;
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	}
	ଫେରନ୍ତୁ 0;
}

