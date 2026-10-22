/*
 * Copyright (c) 2006 Darren Tucker.  All rights reserved.
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

#అన్తర్భావ "openbsd-compat/openbsd-compat.h"

/*
 * return 1 if the specified uid is a uid that may own a system directory
 * otherwise 0.
 */
పూర్ణాంకం
platform_sys_dir_uid(uid_t uid)
{
	ఒకవేళ (uid == 0)
		తిరిగి 1;
#నిర్వచితమైతే PLATFORM_SYS_DIR_UID
	ఒకవేళ (uid == PLATFORM_SYS_DIR_UID)
		తిరిగి 1;
#అయితే_ముగింపు
	తిరిగి 0;
}
