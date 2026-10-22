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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SANDBOX_SOLARIS
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ USE_SOLARIS_PRIVS
# error "--with-solaris-privs must be used with the Solaris sandbox"
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_PRIV_H
# include <priv.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-sandbox.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

ਬਣਤਰ ssh_sandbox {
	priv_ਸੈੱਟ_t *pset;
};

ਬਣਤਰ ssh_sandbox *
ssh_sandbox_init(ਬਣਤਰ monitor *monitor)
{
	ਬਣਤਰ ssh_sandbox *box = ਨਿਰਾ;

	box = xcalloc(1, ਆਕਾਰ(*box));

	/* Start with "basic" and drop everything we don't need. */
	box->pset = solaris_basic_privset();

	ਜੇ (box->pset == ਨਿਰਾ) {
		ਮੁਕਤ(box);
		ਵਾਪਸ ਨਿਰਾ;
	}

	/* Drop everything except the ability to use already-opened files */
	ਜੇ (priv_delset(box->pset, PRIV_FILE_LINK_ANY) != 0 ||
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PRIV_NET_ACCESS
	    priv_delset(box->pset, PRIV_NET_ACCESS) != 0 ||
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PRIV_DAX_ACCESS
	    priv_delset(box->pset, PRIV_DAX_ACCESS) != 0 ||
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PRIV_SYS_IB_INFO
	    priv_delset(box->pset, PRIV_SYS_IB_INFO) != 0 ||
#ਜੇ_ਅੰਤ
	    priv_delset(box->pset, PRIV_PROC_EXEC) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_FORK) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_SESSION) != 0) {
		ਮੁਕਤ(box);
		ਵਾਪਸ ਨਿਰਾ;
	}

	/* These may not be available on older Solaris-es */
# ਜੇ defined(PRIV_FILE_READ) && defined(PRIV_FILE_WRITE)
	ਜੇ (priv_delset(box->pset, PRIV_FILE_READ) != 0 ||
	    priv_delset(box->pset, PRIV_FILE_WRITE) != 0) {
		ਮੁਕਤ(box);
		ਵਾਪਸ ਨਿਰਾ;
	}
# endif

	ਵਾਪਸ box;
}

ਖਾਲੀ
ssh_sandbox_ਬੱਚਾ(ਬਣਤਰ ssh_sandbox *box)
{
	ਜੇ (setppriv(PRIV_ਸੈੱਟ, PRIV_PERMITTED, box->pset) != 0 ||
	    setppriv(PRIV_ਸੈੱਟ, PRIV_ਹੱਦਬੰਦੀ, box->pset) != 0 ||
	    setppriv(PRIV_ਸੈੱਟ, PRIV_INHERITABLE, box->pset) != 0)
		fatal("setppriv: %s", strerror(errno));
}

#ਜੇ_ਅੰਤ /* SANDBOX_SOLARIS */
