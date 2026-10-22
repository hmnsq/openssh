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

ساختار Channel;
ساختار ssh;

#اگر defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
صحیح	  sys_tun_open(صحیح, صحیح, نویسه **);
#endif

#اگر defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
صحیح	 sys_tun_infilter(ساختار ssh *, ساختار Channel *, نویسه *, صحیح);
u_char	*sys_tun_outfilter(ساختار ssh *, ساختار Channel *, u_char **, size_t *);
#endif

#اگر defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_SET_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
نویسه *sys_get_rdomain(صحیح fd);
صحیح sys_set_rdomain(صحیح fd, ثابت نویسه *name);
صحیح sys_valid_rdomain(ثابت نویسه *name);
#endif

#اگر defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_SET_PROCESS_RDOMAIN
تهی sys_set_process_rdomain(ثابت نویسه *name);
#endif

#endif
