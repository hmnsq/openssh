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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <unistd.h>
#समावेश <string.h>

#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "atomicio.h"

/* Load a file from a fd into a buffer */
पूर्णांक
sshbuf_load_fd(पूर्णांक fd, काष्ठा sshbuf **blobp)
{
	u_char buf[4096];
	माप_प्रकार len;
	काष्ठा stat st;
	पूर्णांक r;
	काष्ठा sshbuf *blob;

	*blobp = शून्य;

	अगर (ख_स्थिति(fd, &st) == -1)
		वापस SSH_ERR_SYSTEM_ERROR;
	अगर (S_ISREG(st.st_mode) && st.st_size > SSHBUF_आकार_MAX)
		वापस SSH_ERR_INVALID_FORMAT;
	अगर ((blob = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	क्रम (;;) {
		अगर ((len = atomicio(पढ़ो, fd, buf, माप(buf))) == 0) {
			अगर (त्रुटि_सं == EPIPE)
				अवरोध;
			r = SSH_ERR_SYSTEM_ERROR;
			जाओ out;
		}
		अगर ((r = sshbuf_put(blob, buf, len)) != 0)
			जाओ out;
		अगर (sshbuf_len(blob) > SSHBUF_आकार_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
	}
	अगर (S_ISREG(st.st_mode) != 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		जाओ out;
	}
	/* success */
	*blobp = blob;
	blob = शून्य; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, माप(buf));
	sshbuf_free(blob);
	वापस r;
}

पूर्णांक
sshbuf_load_file(स्थिर अक्षर *path, काष्ठा sshbuf **bufp)
{
	पूर्णांक r, fd, oerrno;

	*bufp = शून्य;
	अगर ((fd = खोलो(path, O_RDONLY)) == -1)
		वापस SSH_ERR_SYSTEM_ERROR;
	अगर ((r = sshbuf_load_fd(fd, bufp)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	oerrno = त्रुटि_सं;
	बंद(fd);
	अगर (r != 0)
		त्रुटि_सं = oerrno;
	वापस r;
}

पूर्णांक
sshbuf_write_file(स्थिर अक्षर *path, काष्ठा sshbuf *buf)
{
	पूर्णांक fd, oerrno;

	अगर ((fd = खोलो(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		वापस SSH_ERR_SYSTEM_ERROR;
	अगर (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || बंद(fd) != 0) {
		oerrno = त्रुटि_सं;
		बंद(fd);
		unlink(path);
		त्रुटि_सं = oerrno;
		वापस SSH_ERR_SYSTEM_ERROR;
	}
	वापस 0;
}

