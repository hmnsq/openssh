/*
 * Copyright (c) 2006 Damien Miller <djm@openbsd.org>
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

#నిర్వచితం_కాకపోతే పోర్టు_LINUX_H
#నిర్వచించు పోర్టు_LINUX_H

#నిర్వచితమైతే WITH_SELINUX
పూర్ణాంకం ssh_selinux_enabled(శూన్య);
శూన్య ssh_selinux_అమరిక_pty(అక్షరం *, స్థిరరాశి అక్షరం *);
శూన్య ssh_selinux_అమరిక_exec_context(అక్షరం *);
శూన్య ssh_selinux_change_context(స్థిరరాశి అక్షరం *);
శూన్య ssh_selinux_setfscreatecon(స్థిరరాశి అక్షరం *);
#అయితే_ముగింపు

#నిర్వచితమైతే LINUX_OOM_ADJUST
శూన్య oom_adjust_restore(శూన్య);
శూన్య oom_adjust_అమరిక(శూన్య);
#అయితే_ముగింపు

#నిర్వచితమైతే LINUX_MEMLOCK_ONFAULT
శూన్య memlock_onfault_అమరిక(శూన్య);
#అయితే_ముగింపు

#నిర్వచితమైతే SYSTEMD_NOTIFY
శూన్య ssh_systemd_notify_ready(శూన్య);
శూన్య ssh_systemd_notify_reload(శూన్య);
#అయితే_ముగింపు

#అయితే_ముగింపు /* ! _PORT_LINUX_H */
