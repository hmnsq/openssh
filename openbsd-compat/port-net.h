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

#اگر_غیر_تعریف_شدہ پورٹ_TUN_H
#تعریف_کرو پورٹ_TUN_H

ساخت Channel;
ساخت ssh;

#اگر defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
صحیح	  sys_tun_open(صحیح, صحیح, حرف **);
#اگر_ختم

#اگر defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
صحیح	 sys_tun_infilter(ساخت ssh *, ساخت Channel *, حرف *, صحیح);
u_char	*sys_tun_outfilter(ساخت ssh *, ساخت Channel *, u_char **, سائز_t *);
#اگر_ختم

#اگر defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_سیٹ_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
حرف *sys_get_rdomain(صحیح fd);
صحیح sys_سیٹ_rdomain(صحیح fd, ثابت حرف *name);
صحیح sys_valid_rdomain(ثابت حرف *name);
#اگر_ختم

#اگر defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_سیٹ_PROCESS_RDOMAIN
خالی sys_سیٹ_process_rdomain(ثابت حرف *name);
#اگر_ختم

#اگر_ختم
