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

#অন্তর্ভাব "includes.h"

#ifdef SANDBOX_NULL

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "ssh-sandbox.h"
#অন্তর্ভাব "xmalloc.h"

/* dummy sandbox */

সংরচনা ssh_sandbox {
	পূর্ণাঙ্ক junk;
};

সংরচনা ssh_sandbox *
ssh_sandbox_init(সংরচনা monitor *monitor)
{
	সংরচনা ssh_sandbox *box;

	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	box = xcalloc(1, পরিমাণ(*box));
	প্রত্যাগম box;
}

শূন্য
ssh_sandbox_child(সংরচনা ssh_sandbox *box)
{
	/* Nothing to do here */
}

#endif /* SANDBOX_NULL */
