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

#شامل "includes.h"

#اگر_تعریف_شدہ SANDBOX_SOLARIS
#اگر_غیر_تعریف_شدہ USE_SOLARIS_PRIVS
# error "--with-solaris-privs must be used with the Solaris sandbox"
#اگر_ختم

#شامل <sys/types.h>

#شامل <errno.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#اگر_تعریف_شدہ HAVE_PRIV_H
# include <priv.h>
#اگر_ختم

#شامل "log.h"
#شامل "ssh-sandbox.h"
#شامل "xmalloc.h"

ساخت ssh_sandbox {
	priv_سیٹ_t *pset;
};

ساخت ssh_sandbox *
ssh_sandbox_init(ساخت monitor *monitor)
{
	ساخت ssh_sandbox *box = تہی;

	box = xcalloc(1, حجم(*box));

	/* Start with "basic" and drop everything we don't need. */
	box->pset = solaris_basic_privset();

	اگر (box->pset == تہی) {
		آزاد(box);
		واپس تہی;
	}

	/* Drop everything except the ability to use already-opened files */
	اگر (priv_delset(box->pset, PRIV_FILE_LINK_ANY) != 0 ||
#اگر_تعریف_شدہ PRIV_NET_ACCESS
	    priv_delset(box->pset, PRIV_NET_ACCESS) != 0 ||
#اگر_ختم
#اگر_تعریف_شدہ PRIV_DAX_ACCESS
	    priv_delset(box->pset, PRIV_DAX_ACCESS) != 0 ||
#اگر_ختم
#اگر_تعریف_شدہ PRIV_SYS_IB_INFO
	    priv_delset(box->pset, PRIV_SYS_IB_INFO) != 0 ||
#اگر_ختم
	    priv_delset(box->pset, PRIV_PROC_EXEC) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_FORK) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_SESSION) != 0) {
		آزاد(box);
		واپس تہی;
	}

	/* These may not be available on older Solaris-es */
# اگر defined(PRIV_FILE_READ) && defined(PRIV_FILE_WRITE)
	اگر (priv_delset(box->pset, PRIV_FILE_READ) != 0 ||
	    priv_delset(box->pset, PRIV_FILE_WRITE) != 0) {
		آزاد(box);
		واپس تہی;
	}
# endif

	واپس box;
}

خالی
ssh_sandbox_بچہ(ساخت ssh_sandbox *box)
{
	اگر (setppriv(PRIV_سیٹ, PRIV_PERMITTED, box->pset) != 0 ||
	    setppriv(PRIV_سیٹ, PRIV_حد_بندی, box->pset) != 0 ||
	    setppriv(PRIV_سیٹ, PRIV_INHERITABLE, box->pset) != 0)
		fatal("setppriv: %s", strerror(errno));
}

#اگر_ختم /* SANDBOX_SOLARIS */
