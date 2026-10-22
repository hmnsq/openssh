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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef SANDBOX_SOLARIS
#ifndef USE_SOLARIS_PRIVS
# error "--with-solaris-privs must be used with the Solaris sandbox"
#endif

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ifdef HAVE_PRIV_H
# include <priv.h>
#endif

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "ssh-sandbox.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

ಸಂರಚನಾ ssh_sandbox {
	priv_set_t *pset;
};

ಸಂರಚನಾ ssh_sandbox *
ssh_sandbox_init(ಸಂರಚನಾ monitor *monitor)
{
	ಸಂರಚನಾ ssh_sandbox *box = ರಿಕ್ತ;

	box = xcalloc(1, ಪರಿಮಾಣ(*box));

	/* Start with "basic" and drop everything we don't need. */
	box->pset = solaris_basic_privset();

	ಯದಿ (box->pset == ರಿಕ್ತ) {
		ಮುಕ್ತ(box);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	/* Drop everything except the ability to use already-opened files */
	ಯದಿ (priv_delset(box->pset, PRIV_FILE_LINK_ANY) != 0 ||
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
		ಮುಕ್ತ(box);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	/* These may not be available on older Solaris-es */
# ಯದಿ defined(PRIV_FILE_READ) && defined(PRIV_FILE_WRITE)
	ಯದಿ (priv_delset(box->pset, PRIV_FILE_READ) != 0 ||
	    priv_delset(box->pset, PRIV_FILE_WRITE) != 0) {
		ಮುಕ್ತ(box);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
# endif

	ಪ್ರತ್ಯಾಗಮ box;
}

ಶೂನ್ಯ
ssh_sandbox_child(ಸಂರಚನಾ ssh_sandbox *box)
{
	ಯದಿ (setppriv(PRIV_SET, PRIV_PERMITTED, box->pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_LIMIT, box->pset) != 0 ||
	    setppriv(PRIV_SET, PRIV_INHERITABLE, box->pset) != 0)
		fatal("setppriv: %s", strerror(errno));
}

#endif /* SANDBOX_SOLARIS */
