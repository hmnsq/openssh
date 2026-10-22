/*
 * Copyright (c) 2005 Reyk Floeter <reyk@openbsd.org>
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

#ifndef _PORT_TUN_H
#define _PORT_TUN_H

ସଂରଚନା Channel;
ସଂରଚନା ssh;

#ଯଦି defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	  sys_tun_open(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର **);
#endif

#ଯଦି defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sys_tun_infilter(ସଂରଚନା ssh *, ସଂରଚନା Channel *, ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
u_char	*sys_tun_outfilter(ସଂରଚନା ssh *, ସଂରଚନା Channel *, u_char **, size_t *);
#endif

#ଯଦି defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_SET_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
ଅକ୍ଷର *sys_get_rdomain(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sys_set_rdomain(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅଚଳ ଅକ୍ଷର *name);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sys_valid_rdomain(ଅଚଳ ଅକ୍ଷର *name);
#endif

#ଯଦି defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_SET_PROCESS_RDOMAIN
ଶୂନ୍ୟ sys_set_process_rdomain(ଅଚଳ ଅକ୍ଷର *name);
#endif

#endif
