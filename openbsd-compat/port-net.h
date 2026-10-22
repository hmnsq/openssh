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

संरचना Channel;
संरचना ssh;

#जइ defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
पूर्णाङ्क	  sys_tun_open(पूर्णाङ्क, पूर्णाङ्क, वर्ण **);
#endif

#जइ defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
पूर्णाङ्क	 sys_tun_infilter(संरचना ssh *, संरचना Channel *, वर्ण *, पूर्णाङ्क);
u_char	*sys_tun_outfilter(संरचना ssh *, संरचना Channel *, u_char **, size_t *);
#endif

#जइ defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_SET_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
वर्ण *sys_get_rdomain(पूर्णाङ्क fd);
पूर्णाङ्क sys_set_rdomain(पूर्णाङ्क fd, ध्रुव वर्ण *name);
पूर्णाङ्क sys_valid_rdomain(ध्रुव वर्ण *name);
#endif

#जइ defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_SET_PROCESS_RDOMAIN
शून्य sys_set_process_rdomain(ध्रुव वर्ण *name);
#endif

#endif
