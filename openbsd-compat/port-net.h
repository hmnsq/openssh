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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਪੋਰਟ_TUN_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਪੋਰਟ_TUN_H

ਬਣਤਰ Channel;
ਬਣਤਰ ssh;

#ਜੇ defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
ਪੂਰਨ	  sys_tun_open(ਪੂਰਨ, ਪੂਰਨ, ਅੱਖਰ **);
#ਜੇ_ਅੰਤ

#ਜੇ defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
ਪੂਰਨ	 sys_tun_infilter(ਬਣਤਰ ssh *, ਬਣਤਰ Channel *, ਅੱਖਰ *, ਪੂਰਨ);
u_char	*sys_tun_outfilter(ਬਣਤਰ ssh *, ਬਣਤਰ Channel *, u_char **, ਮਾਪ_t *);
#ਜੇ_ਅੰਤ

#ਜੇ defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_ਸੈੱਟ_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
ਅੱਖਰ *sys_get_rdomain(ਪੂਰਨ fd);
ਪੂਰਨ sys_ਸੈੱਟ_rdomain(ਪੂਰਨ fd, ਅਚਲ ਅੱਖਰ *name);
ਪੂਰਨ sys_valid_rdomain(ਅਚਲ ਅੱਖਰ *name);
#ਜੇ_ਅੰਤ

#ਜੇ defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_ਸੈੱਟ_PROCESS_RDOMAIN
ਖਾਲੀ sys_ਸੈੱਟ_process_rdomain(ਅਚਲ ਅੱਖਰ *name);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ
