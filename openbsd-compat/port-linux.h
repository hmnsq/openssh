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

#अगर_अघोषित _PORT_LINUX_H
#घोषणा _PORT_LINUX_H

#अगर_घोषित WITH_SELINUX
पूर्णांक ssh_selinux_enabled(व्योम);
व्योम ssh_selinux_setup_pty(अक्षर *, स्थिर अक्षर *);
व्योम ssh_selinux_setup_exec_context(अक्षर *);
व्योम ssh_selinux_change_context(स्थिर अक्षर *);
व्योम ssh_selinux_setfscreatecon(स्थिर अक्षर *);
#पूर्ण_अगर

#अगर_घोषित LINUX_OOM_ADJUST
व्योम oom_adjust_restore(व्योम);
व्योम oom_adjust_setup(व्योम);
#पूर्ण_अगर

#अगर_घोषित LINUX_MEMLOCK_ONFAULT
व्योम memlock_onfault_setup(व्योम);
#पूर्ण_अगर

#अगर_घोषित SYSTEMD_NOTIFY
व्योम ssh_systemd_notify_ready(व्योम);
व्योम ssh_systemd_notify_reload(व्योम);
#पूर्ण_अगर

#पूर्ण_अगर /* ! _PORT_LINUX_H */
