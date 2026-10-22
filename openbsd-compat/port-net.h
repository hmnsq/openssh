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

#که_نه_تعریف_شوی پورټ_TUN_H
#تعریف_کړه پورټ_TUN_H

بنية Channel;
بنية ssh;

#إذا defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
صحيح	  sys_tun_open(صحيح, صحيح, حرف **);
#د_که_پای

#إذا defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
صحيح	 sys_tun_infilter(بنية ssh *, بنية Channel *, حرف *, صحيح);
u_char	*sys_tun_outfilter(بنية ssh *, بنية Channel *, u_char **, اندازه_t *);
#د_که_پای

#إذا defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_سېټ_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
حرف *sys_get_rdomain(صحيح fd);
صحيح sys_سېټ_rdomain(صحيح fd, ثابت حرف *name);
صحيح sys_valid_rdomain(ثابت حرف *name);
#د_که_پای

#إذا defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_سېټ_PROCESS_RDOMAIN
فراغ sys_سېټ_process_rdomain(ثابت حرف *name);
#د_که_پای

#د_که_پای
