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

#അന്തര്ഭാവ "includes.h"

#ifdef SANDBOX_SOLARIS
#ifndef USE_SOLARIS_PRIVS
# error "--with-solaris-privs must be used with the Solaris sandbox"
#endif

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#ifdef HAVE_PRIV_H
# include <priv.h>
#endif

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "ssh-sandbox.h"
#അന്തര്ഭാവ "xmalloc.h"

ഘടന ssh_sandbox {
	priv_set_t *pset;
};

ഘടന ssh_sandbox *
ssh_sandbox_init(ഘടന monitor *monitor)
{
	ഘടന ssh_sandbox *box = ശൂന്യ;

	box = xcalloc(1, വലുപ്പം(*box));

	/* Start with "basic" and drop everything we don't need. */
	box->pset = solaris_basic_privset();

	എങ്കിൽ (box->pset == ശൂന്യ) {
		സ്വതന്ത്രം(box);
		തിരികെ ശൂന്യ;
	}

	/* Drop everything except the ability to use already-opened files */
	എങ്കിൽ (priv_delset(box->pset, PRIV_FILE_LINK_ANY) != 0 ||
#ifdef PRIV_NET_ACCESS
	    priv_delset(box->pset, PRIV_NET_ACCESS) != 0 ||
#endif
#ifdef PRIV_DAX_ACCESS
	    priv_delset(box->pset, PRIV_DAX_ACCESS) != 0 ||
#endif
#ifdef PRIV_SYS_IB_INFO
	    priv_delset(box->pset, PRIV_SYS_IB_INFO) != 0 ||
#endif
	    priv_delset(box->pset, PRIV_PROC_EXEC) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_FORK) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_SESSION) != 0) {
		സ്വതന്ത്രം(box);
		തിരികെ ശൂന്യ;
	}

	/* These may not be available on older Solaris-es */
# എങ്കിൽ defined(PRIV_FILE_READ) && defined(PRIV_FILE_WRITE)
	എങ്കിൽ (priv_delset(box->pset, PRIV_FILE_READ) != 0 ||
	    priv_delset(box->pset, PRIV_FILE_WRITE) != 0) {
		സ്വതന്ത്രം(box);
		തിരികെ ശൂന്യ;
	}
# endif

	തിരികെ box;
}

ശൂന്യം
ssh_sandbox_child(ഘടന ssh_sandbox *box)
{
	എങ്കിൽ (setppriv(PRIV_SET, PRIV_PERMITTED, box->pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_LIMIT, box->pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_INHERITABLE, box->pset) != 0)
		fatal("setppriv: %s", strerror(errno));
}

#endif /* SANDBOX_SOLARIS */
