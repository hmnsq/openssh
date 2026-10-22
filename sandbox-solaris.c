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

#அந்தர்பாவ "includes.h"

#ifdef SANDBOX_SOLARIS
#ifndef USE_SOLARIS_PRIVS
# error "--with-solaris-privs must be used with the Solaris sandbox"
#endif

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#ifdef HAVE_PRIV_H
# include <priv.h>
#endif

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "ssh-sandbox.h"
#அந்தர்பாவ "xmalloc.h"

கட்டமைப்பு ssh_sandbox {
	priv_set_t *pset;
};

கட்டமைப்பு ssh_sandbox *
ssh_sandbox_init(கட்டமைப்பு monitor *monitor)
{
	கட்டமைப்பு ssh_sandbox *box = வெற்று;

	box = xcalloc(1, அளவு(*box));

	/* Start with "basic" and drop everything we don't need. */
	box->pset = solaris_basic_privset();

	எனில் (box->pset == வெற்று) {
		விடுவி(box);
		திரும்பு வெற்று;
	}

	/* Drop everything except the ability to use already-opened files */
	எனில் (priv_delset(box->pset, PRIV_FILE_LINK_ANY) != 0 ||
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
		விடுவி(box);
		திரும்பு வெற்று;
	}

	/* These may not be available on older Solaris-es */
# எனில் defined(PRIV_FILE_READ) && defined(PRIV_FILE_WRITE)
	எனில் (priv_delset(box->pset, PRIV_FILE_READ) != 0 ||
	    priv_delset(box->pset, PRIV_FILE_WRITE) != 0) {
		விடுவி(box);
		திரும்பு வெற்று;
	}
# endif

	திரும்பு box;
}

வெறுமை
ssh_sandbox_child(கட்டமைப்பு ssh_sandbox *box)
{
	எனில் (setppriv(PRIV_SET, PRIV_PERMITTED, box->pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_LIMIT, box->pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_INHERITABLE, box->pset) != 0)
		fatal("setppriv: %s", strerror(errno));
}

#endif /* SANDBOX_SOLARIS */
