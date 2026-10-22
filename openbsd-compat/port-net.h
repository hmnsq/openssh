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

#جيڪڏهن_وصف_نه_ٿيل پورٽ_TUN_H
#وصف_ڪريو پورٽ_TUN_H

بنية Channel;
بنية ssh;

#إذا defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
صحيح	  sys_tun_open(صحيح, صحيح, حرف **);
#جيڪڏهن_پورو

#إذا defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
صحيح	 sys_tun_infilter(بنية ssh *, بنية Channel *, حرف *, صحيح);
u_char	*sys_tun_outfilter(بنية ssh *, بنية Channel *, u_char **, سائيز_t *);
#جيڪڏهن_پورو

#إذا defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_سيٽ_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
حرف *sys_get_rdomain(صحيح fd);
صحيح sys_سيٽ_rdomain(صحيح fd, ثابت حرف *name);
صحيح sys_valid_rdomain(ثابت حرف *name);
#جيڪڏهن_پورو

#إذا defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_سيٽ_PROCESS_RDOMAIN
فراغ sys_سيٽ_process_rdomain(ثابت حرف *name);
#جيڪڏهن_پورو

#جيڪڏهن_پورو
