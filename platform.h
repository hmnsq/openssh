/*
 * Copyright (c) 2006 Darren Tucker.  All rights reserved.
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

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <pwd.h>

शून्य platform_pre_listen(शून्य);
शून्य platform_pre_fork(शून्य);
शून्य platform_pre_restart(शून्य);
शून्य platform_post_listen(शून्य);
शून्य platform_post_fork_parent(pid_t child_pid);
शून्य platform_post_fork_child(शून्य);
शून्य platform_pre_session_start(शून्य);
पूर्णाङ्क  platform_privileged_uidswap(शून्य);
शून्य platform_setusercontext(संरचना passwd *);
शून्य platform_setusercontext_post_groups(संरचना passwd *);
वर्ण *platform_get_krb5_client(ध्रुव वर्ण *);
वर्ण *platform_krb5_get_principal_name(ध्रुव वर्ण *);
पूर्णाङ्क platform_locked_account(संरचना passwd *);
पूर्णाङ्क platform_sys_dir_uid(uid_t);
शून्य platform_disable_tracing(पूर्णाङ्क);

/* in platform-pledge.c */
शून्य platform_pledge_agent(शून्य);
शून्य platform_pledge_sftp_server(शून्य);
शून्य platform_pledge_mux(शून्य);
