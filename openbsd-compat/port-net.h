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

கட்டமைப்பு Channel;
கட்டமைப்பு ssh;

#எனில் defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
முழு	  sys_tun_open(முழு, முழு, எழுத்து **);
#endif

#எனில் defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
முழு	 sys_tun_infilter(கட்டமைப்பு ssh *, கட்டமைப்பு Channel *, எழுத்து *, முழு);
u_char	*sys_tun_outfilter(கட்டமைப்பு ssh *, கட்டமைப்பு Channel *, u_char **, size_t *);
#endif

#எனில் defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_SET_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
எழுத்து *sys_get_rdomain(முழு fd);
முழு sys_set_rdomain(முழு fd, மாறிலி எழுத்து *name);
முழு sys_valid_rdomain(மாறிலி எழுத்து *name);
#endif

#எனில் defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_SET_PROCESS_RDOMAIN
வெறுமை sys_set_process_rdomain(மாறிலி எழுத்து *name);
#endif

#endif
