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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SANDBOX_SOLARIS
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ USE_SOLARIS_PRIVS
# error "--with-solaris-privs must be used with the Solaris sandbox"
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_PRIV_H
# include <priv.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "ssh-sandbox.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

ರಚನೆ ssh_sandbox {
	priv_ಗಣ_t *pset;
};

ರಚನೆ ssh_sandbox *
ssh_sandbox_init(ರಚನೆ monitor *monitor)
{
	ರಚನೆ ssh_sandbox *box = ಖಾಲಿ;

	box = xcalloc(1, ಗಾತ್ರ(*box));

	/* Start with "basic" and drop everything we don't need. */
	box->pset = solaris_basic_privset();

	ಆದರೆ (box->pset == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(box);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	/* Drop everything except the ability to use already-opened files */
	ಆದರೆ (priv_delset(box->pset, PRIV_FILE_LINK_ANY) != 0 ||
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PRIV_NET_ACCESS
	    priv_delset(box->pset, PRIV_NET_ACCESS) != 0 ||
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PRIV_DAX_ACCESS
	    priv_delset(box->pset, PRIV_DAX_ACCESS) != 0 ||
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PRIV_SYS_IB_INFO
	    priv_delset(box->pset, PRIV_SYS_IB_INFO) != 0 ||
#ಆದರೆ_ಅಂತ್ಯ
	    priv_delset(box->pset, PRIV_PROC_EXEC) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_FORK) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_INFO) != 0 ||
	    priv_delset(box->pset, PRIV_PROC_SESSION) != 0) {
		ಬಿಡುಗಡೆ(box);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	/* These may not be available on older Solaris-es */
# ಆದರೆ defined(PRIV_FILE_READ) && defined(PRIV_FILE_WRITE)
	ಆದರೆ (priv_delset(box->pset, PRIV_FILE_READ) != 0 ||
	    priv_delset(box->pset, PRIV_FILE_WRITE) != 0) {
		ಬಿಡುಗಡೆ(box);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
# endif

	ಹಿಂತಿರುಗಿ box;
}

ಶೂನ್ಯ
ssh_sandbox_ಮಗು(ರಚನೆ ssh_sandbox *box)
{
	ಆದರೆ (setppriv(PRIV_ಗಣ, PRIV_PERMITTED, box->pset) != 0 ||
	    setppriv(PRIV_ಗಣ, PRIV_ಎಲ್ಲೆ, box->pset) != 0 ||
	    setppriv(PRIV_ಗಣ, PRIV_INHERITABLE, box->pset) != 0)
		fatal("setppriv: %s", strerror(errno));
}

#ಆದರೆ_ಅಂತ್ಯ /* SANDBOX_SOLARIS */
