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

સંરચના Channel;
સંરચના ssh;

#જો defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
પૂર્ણાંક	  sys_tun_open(પૂર્ણાંક, પૂર્ણાંક, અક્ષર **);
#endif

#જો defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
પૂર્ણાંક	 sys_tun_infilter(સંરચના ssh *, સંરચના Channel *, અક્ષર *, પૂર્ણાંક);
u_char	*sys_tun_outfilter(સંરચના ssh *, સંરચના Channel *, u_char **, size_t *);
#endif

#જો defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_SET_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
અક્ષર *sys_get_rdomain(પૂર્ણાંક fd);
પૂર્ણાંક sys_set_rdomain(પૂર્ણાંક fd, અચલ અક્ષર *name);
પૂર્ણાંક sys_valid_rdomain(અચલ અક્ષર *name);
#endif

#જો defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_SET_PROCESS_RDOMAIN
શૂન્ય sys_set_process_rdomain(અચલ અક્ષર *name);
#endif

#endif
