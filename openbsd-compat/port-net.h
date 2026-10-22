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

#నిర్వచితం_కాకపోతే పోర్టు_TUN_H
#నిర్వచించు పోర్టు_TUN_H

నిర్మాణం Channel;
నిర్మాణం ssh;

#ఒకవేళ defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
పూర్ణాంకం	  sys_tun_open(పూర్ణాంకం, పూర్ణాంకం, అక్షరం **);
#అయితే_ముగింపు

#ఒకవేళ defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
పూర్ణాంకం	 sys_tun_infilter(నిర్మాణం ssh *, నిర్మాణం Channel *, అక్షరం *, పూర్ణాంకం);
u_char	*sys_tun_outfilter(నిర్మాణం ssh *, నిర్మాణం Channel *, u_char **, కొలత_t *);
#అయితే_ముగింపు

#ఒకవేళ defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_సమితి_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
అక్షరం *sys_get_rdomain(పూర్ణాంకం fd);
పూర్ణాంకం sys_సమితి_rdomain(పూర్ణాంకం fd, స్థిరరాశి అక్షరం *name);
పూర్ణాంకం sys_valid_rdomain(స్థిరరాశి అక్షరం *name);
#అయితే_ముగింపు

#ఒకవేళ defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_సమితి_PROCESS_RDOMAIN
శూన్య sys_సమితి_process_rdomain(స్థిరరాశి అక్షరం *name);
#అయితే_ముగింపు

#అయితే_ముగింపు
