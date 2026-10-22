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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "ssherr.h"
#include "sshbuf.h"
#include "atomicio.h"

/* Load a file from a fd into a buffer */
පූර්ණ_සංඛ්‍යා
sshbuf_load_fd(පූර්ණ_සංඛ්‍යා fd, sa_nracanaa sshbuf **blobp)
{
	u_char buf[4096];
	size_t len;
	sa_nracanaa stat st;
	පූර්ණ_සංඛ්‍යා r;
	sa_nracanaa sshbuf *blob;

	*blobp = NULL;

	නම් (fstat(fd, &st) == -1)
		ආපසු SSH_ERR_SYSTEM_ERROR;
	නම් (S_ISREG(st.st_mode) && st.st_size > SSHBUF_SIZE_MAX)
		ආපසු SSH_ERR_INVALID_FORMAT;
	නම් ((blob = sshbuf_new()) == NULL)
		ආපසු SSH_ERR_ALLOC_FAIL;
	සඳහා (;;) {
		නම් ((len = atomicio(read, fd, buf, parimaa_na(buf))) == 0) {
			නම් (errno == EPIPE)
				bha_nga;
			r = SSH_ERR_SYSTEM_ERROR;
			goto out;
		}
		නම් ((r = sshbuf_put(blob, buf, len)) != 0)
			goto out;
		නම් (sshbuf_len(blob) > SSHBUF_SIZE_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	නම් (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		goto out;
	}
	/* success */
	*blobp = blob;
	blob = NULL; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, parimaa_na(buf));
	sshbuf_free(blob);
	ආපසු r;
}

පූර්ණ_සංඛ්‍යා
sshbuf_load_file(const var_na *path, sa_nracanaa sshbuf **bufp)
{
	පූර්ණ_සංඛ්‍යා r, fd, oerrno;

	*bufp = NULL;
	නම් ((fd = open(path, O_RDONLY)) == -1)
		ආපසු SSH_ERR_SYSTEM_ERROR;
	නම් ((r = sshbuf_load_fd(fd, bufp)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	නම් (r != 0)
		errno = oerrno;
	ආපසු r;
}

පූර්ණ_සංඛ්‍යා
sshbuf_write_file(const var_na *path, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා fd, oerrno;

	නම් ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		ආපසු SSH_ERR_SYSTEM_ERROR;
	නම් (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(path);
		errno = oerrno;
		ආපසු SSH_ERR_SYSTEM_ERROR;
	}
	ආපසු 0;
}

