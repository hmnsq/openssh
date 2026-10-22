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

সংরচনা Channel;
সংরচনা ssh;

#যদি defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
পূর্ণাঙ্ক	  sys_tun_open(পূর্ণাঙ্ক, পূর্ণাঙ্ক, বর্ণ **);
#endif

#যদি defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
পূর্ণাঙ্ক	 sys_tun_infilter(সংরচনা ssh *, সংরচনা Channel *, বর্ণ *, পূর্ণাঙ্ক);
u_char	*sys_tun_outfilter(সংরচনা ssh *, সংরচনা Channel *, u_char **, size_t *);
#endif

#যদি defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_SET_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
বর্ণ *sys_get_rdomain(পূর্ণাঙ্ক fd);
পূর্ণাঙ্ক sys_set_rdomain(পূর্ণাঙ্ক fd, ধ্রুব বর্ণ *name);
পূর্ণাঙ্ক sys_valid_rdomain(ধ্রুব বর্ণ *name);
#endif

#যদি defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_SET_PROCESS_RDOMAIN
শূন্য sys_set_process_rdomain(ধ্রুব বর্ণ *name);
#endif

#endif
