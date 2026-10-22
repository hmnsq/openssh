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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే SANDBOX_SOLARIS
#నిర్వచితం_కాకపోతే USE_SOLARIS_PRIVS
# error "--with-solaris-privs must be used with the Solaris sandbox"
#అయితే_ముగింపు

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#నిర్వచితమైతే HAVE_PRIV_H
# include <priv.h>
#అయితే_ముగింపు

#అన్తర్భావ "log.h"
#అన్తర్భావ "ssh-sandbox.h"
#అన్తర్భావ "xmalloc.h"

నిర్మాణం ssh_sandbox {
	priv_సమితి_t *pset;
};

నిర్మాణం ssh_sandbox *
ssh_sandbox_init(నిర్మాణం monitor *monitor)
{
	నిర్మాణం ssh_sandbox *box = ఖాళీ;

	box = xcalloc(1, పరిమాణం(*box));

	/* Start with "basic" and drop everything we don't need. */
	box->pset = solaris_basic_privset();

	ఒకవేళ (box->pset == ఖాళీ) {
		విడుదల(box);
		తిరిగి ఖాళీ;
	}

	/* Drop everything except the ability to use already-opened files */
	ఒకవేళ (priv_delset(box->pset, PRIV_FILE_LINK_ANY) != 0 ||
#నిర్వచితమైతే PRIV_NET_ACCESS
	    priv_delset(box->pset, PRIV_NET_ACCESS) != 0 ||
#అయితే_ముగింపు
#నిర్వచితమైతే PRIV_DAX_ACCESS
	    priv_delset(box->pset, PRIV_DAX_ACCESS) != 0 ||
#అయితే_ముగింపు
#నిర్వచితమైతే PRIV_SYS_IB_INFO
	    priv_delset(box->pset, PRIV_SYS_IB_INFO) != 0 ||
#అయితే_ముగింపు
	    priv_delset(box->pset, PRIV_PROC_EXEC) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_FORK) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_SESSION) != 0) {
		విడుదల(box);
		తిరిగి ఖాళీ;
	}

	/* These may not be available on older Solaris-es */
# ఒకవేళ defined(PRIV_FILE_READ) && defined(PRIV_FILE_WRITE)
	ఒకవేళ (priv_delset(box->pset, PRIV_FILE_READ) != 0 ||
	    priv_delset(box->pset, PRIV_FILE_WRITE) != 0) {
		విడుదల(box);
		తిరిగి ఖాళీ;
	}
# endif

	తిరిగి box;
}

శూన్య
ssh_sandbox_బిడ్డ(నిర్మాణం ssh_sandbox *box)
{
	ఒకవేళ (setppriv(PRIV_సమితి, PRIV_PERMITTED, box->pset) != 0 ||
	    setppriv(PRIV_సమితి, PRIV_హద్దు, box->pset) != 0 ||
	    setppriv(PRIV_సమితి, PRIV_INHERITABLE, box->pset) != 0)
		fatal("setppriv: %s", strerror(errno));
}

#అయితే_ముగింపు /* SANDBOX_SOLARIS */
