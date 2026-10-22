/*
 * Copyright (c) 2015 Joyent, Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
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

#अगर_घोषित SANDBOX_SOLARIS
#अगर_अघोषित USE_SOLARIS_PRIVS
# error "--with-solaris-privs must be used with the Solaris sandbox"
#पूर्ण_अगर

#समावेश <sys/types.h>

#समावेश <errno.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#अगर_घोषित HAVE_PRIV_H
# include <priv.h>
#पूर्ण_अगर

#समावेश "log.h"
#समावेश "ssh-sandbox.h"
#समावेश "xmalloc.h"

काष्ठा ssh_sandbox {
	priv_set_t *pset;
};

काष्ठा ssh_sandbox *
ssh_sandbox_init(काष्ठा monitor *monitor)
{
	काष्ठा ssh_sandbox *box = शून्य;

	box = xcalloc(1, माप(*box));

	/* Start with "basic" and drop everything we don't need. */
	box->pset = solaris_basic_privset();

	अगर (box->pset == शून्य) {
		मुक्त(box);
		वापस शून्य;
	}

	/* Drop everything except the ability to use already-opened files */
	अगर (priv_delset(box->pset, PRIV_FILE_LINK_ANY) != 0 ||
#अगर_घोषित PRIV_NET_ACCESS
	    priv_delset(box->pset, PRIV_NET_ACCESS) != 0 ||
#पूर्ण_अगर
#अगर_घोषित PRIV_DAX_ACCESS
	    priv_delset(box->pset, PRIV_DAX_ACCESS) != 0 ||
#पूर्ण_अगर
#अगर_घोषित PRIV_SYS_IB_INFO
	    priv_delset(box->pset, PRIV_SYS_IB_INFO) != 0 ||
#पूर्ण_अगर
	    priv_delset(box->pset, PRIV_PROC_EXEC) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_FORK) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_SESSION) != 0) {
		मुक्त(box);
		वापस शून्य;
	}

	/* These may not be available on older Solaris-es */
# अगर defined(PRIV_FILE_READ) && defined(PRIV_FILE_WRITE)
	अगर (priv_delset(box->pset, PRIV_FILE_READ) != 0 ||
	    priv_delset(box->pset, PRIV_FILE_WRITE) != 0) {
		मुक्त(box);
		वापस शून्य;
	}
# endif

	वापस box;
}

व्योम
ssh_sandbox_child(काष्ठा ssh_sandbox *box)
{
	अगर (setppriv(PRIV_SET, PRIV_PERMITTED, box->pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_LIMIT, box->pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_INHERITABLE, box->pset) != 0)
		fatal("setppriv: %s", म_त्रुटि(त्रुटि_सं));
}

#पूर्ण_अगर /* SANDBOX_SOLARIS */
