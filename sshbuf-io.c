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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "atomicio.h"

/* Load a file from a fd into a buffer */
पूर्णांक
sshbuf_load_fd(पूर्णांक fd, संरचना sshbuf **blobp)
{
	u_char buf[4096];
	माप_प्रकार len;
	संरचना stat st;
	पूर्णांक r;
	संरचना sshbuf *blob;

	*blobp = रिक्त;

	जर (ख_स्थिति(fd, &st) == -1)
		परत SSH_ERR_SYSTEM_ERROR;
	जर (S_ISREG(st.st_mode) && st.st_size > SSHBUF_SIZE_MAX)
		परत SSH_ERR_INVALID_FORMAT;
	जर ((blob = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	साठी (;;) {
		जर ((len = atomicio(पठ, fd, buf, आकार(buf))) == 0) {
			जर (त्रुटि_सं == EPIPE)
				थांबा;
			r = SSH_ERR_SYSTEM_ERROR;
			जा out;
		}
		जर ((r = sshbuf_put(blob, buf, len)) != 0)
			जा out;
		जर (sshbuf_len(blob) > SSHBUF_SIZE_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			जा out;
		}
	}
	जर (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		जा out;
	}
	/* success */
	*blobp = blob;
	blob = रिक्त; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, आकार(buf));
	sshbuf_free(blob);
	परत r;
}

पूर्णांक
sshbuf_load_file(स्थिरांक अक्षर *path, संरचना sshbuf **bufp)
{
	पूर्णांक r, fd, oerrno;

	*bufp = रिक्त;
	जर ((fd = खोलो(path, O_RDONLY)) == -1)
		परत SSH_ERR_SYSTEM_ERROR;
	जर ((r = sshbuf_load_fd(fd, bufp)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	oerrno = त्रुटि_सं;
	बंद(fd);
	जर (r != 0)
		त्रुटि_सं = oerrno;
	परत r;
}

पूर्णांक
sshbuf_write_file(स्थिरांक अक्षर *path, संरचना sshbuf *buf)
{
	पूर्णांक fd, oerrno;

	जर ((fd = खोलो(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		परत SSH_ERR_SYSTEM_ERROR;
	जर (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || बंद(fd) != 0) {
		oerrno = त्रुटि_सं;
		बंद(fd);
		unlink(path);
		त्रुटि_सं = oerrno;
		परत SSH_ERR_SYSTEM_ERROR;
	}
	परत 0;
}

