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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "atomicio.h"

/* Load a file from a fd into a buffer */
పూర్ణాంకం
sshbuf_ఎక్కించు_fd(పూర్ణాంకం fd, నిర్మాణం sshbuf **blobp)
{
	u_char buf[4096];
	కొలత_t len;
	నిర్మాణం stat st;
	పూర్ణాంకం r;
	నిర్మాణం sshbuf *blob;

	*blobp = ఖాళీ;

	ఒకవేళ (fstat(fd, &st) == -1)
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	ఒకవేళ (S_ISREG(st.st_mode) && st.st_size > SSHBUF_కొలత_MAX)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	ఒకవేళ ((blob = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	కొరకు (;;) {
		ఒకవేళ ((len = atomicio(పఠ, fd, buf, పరిమాణం(buf))) == 0) {
			ఒకవేళ (errno == EPIPE)
				ఆపు;
			r = SSH_ERR_SYSTEM_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_put(blob, buf, len)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ (sshbuf_len(blob) > SSHBUF_కొలత_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
	}
	ఒకవేళ (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_మారింది;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	*blobp = blob;
	blob = ఖాళీ; /* transferred */
	r = 0;
 బహిర్గతం:
	explicit_bzero(buf, పరిమాణం(buf));
	sshbuf_free(blob);
	తిరిగి r;
}

పూర్ణాంకం
sshbuf_ఎక్కించు_file(స్థిరరాశి అక్షరం *మార్గం, నిర్మాణం sshbuf **bufp)
{
	పూర్ణాంకం r, fd, oerrno;

	*bufp = ఖాళీ;
	ఒకవేళ ((fd = open(మార్గం, O_RDONLY)) == -1)
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	ఒకవేళ ((r = sshbuf_ఎక్కించు_fd(fd, bufp)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	oerrno = errno;
	close(fd);
	ఒకవేళ (r != 0)
		errno = oerrno;
	తిరిగి r;
}

పూర్ణాంకం
sshbuf_write_file(స్థిరరాశి అక్షరం *మార్గం, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం fd, oerrno;

	ఒకవేళ ((fd = open(మార్గం, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	ఒకవేళ (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(మార్గం);
		errno = oerrno;
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	}
	తిరిగి 0;
}

