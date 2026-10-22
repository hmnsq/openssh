/* $OpenBSD$ */
/*
 * Copyright (c) 2011 Damien Miller <djm@mindrot.org>
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

#ifdef SANDBOX_NULL

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "ssh-sandbox.h"
#അന്തര്ഭാവ "xmalloc.h"

/* dummy sandbox */

ഘടന ssh_sandbox {
	പൂർണ്ണസംഖ്യ junk;
};

ഘടന ssh_sandbox *
ssh_sandbox_init(ഘടന monitor *monitor)
{
	ഘടന ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	box = xcalloc(1, വലുപ്പം(*box));
	തിരികെ box;
}

ശൂന്യം
ssh_sandbox_child(ഘടന ssh_sandbox *box)
{
	/* Nothing to do here */
}

#endif /* SANDBOX_NULL */
