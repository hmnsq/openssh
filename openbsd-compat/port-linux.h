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

#यदि_अपरिभाषितम् पत्तनम्_LINUX_H
#परिभाषय पत्तनम्_LINUX_H

#यदि_परिभाषितम् WITH_SELINUX
पूर्णाङ्क ssh_selinux_enabled(शून्य);
शून्य ssh_selinux_सज्जता_pty(वर्ण *, ध्रुव वर्ण *);
शून्य ssh_selinux_सज्जता_exec_context(वर्ण *);
शून्य ssh_selinux_change_context(ध्रुव वर्ण *);
शून्य ssh_selinux_setfscreatecon(ध्रुव वर्ण *);
#यदि_अन्तः

#यदि_परिभाषितम् LINUX_OOM_ADJUST
शून्य oom_adjust_restore(शून्य);
शून्य oom_adjust_सज्जता(शून्य);
#यदि_अन्तः

#यदि_परिभाषितम् LINUX_MEMLOCK_ONFAULT
शून्य memlock_onfault_सज्जता(शून्य);
#यदि_अन्तः

#यदि_परिभाषितम् SYSTEMD_NOTIFY
शून्य ssh_systemd_notify_ready(शून्य);
शून्य ssh_systemd_notify_reload(शून्य);
#यदि_अन्तः

#यदि_अन्तः /* ! _PORT_LINUX_H */
