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

কাঠামো Channel;
কাঠামো ssh;

#যদি defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
পূর্ণসংখ্যা	  sys_tun_open(পূর্ণসংখ্যা, পূর্ণসংখ্যা, অক্ষর **);
#endif

#যদি defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
পূর্ণসংখ্যা	 sys_tun_infilter(কাঠামো ssh *, কাঠামো Channel *, অক্ষর *, পূর্ণসংখ্যা);
u_char	*sys_tun_outfilter(কাঠামো ssh *, কাঠামো Channel *, u_char **, আকার_t *);
#endif

#যদি defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_SET_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
অক্ষর *sys_get_rdomain(পূর্ণসংখ্যা fd);
পূর্ণসংখ্যা sys_set_rdomain(পূর্ণসংখ্যা fd, ধ্রুবক অক্ষর *name);
পূর্ণসংখ্যা sys_valid_rdomain(ধ্রুবক অক্ষর *name);
#endif

#যদি defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_SET_PROCESS_RDOMAIN
শূন্য sys_set_process_rdomain(ধ্রুবক অক্ষর *name);
#endif

#endif
