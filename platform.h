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

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <pwd.h>

శూన్య platform_pre_listen(శూన్య);
శూన్య platform_pre_fork(శూన్య);
శూన్య platform_pre_restart(శూన్య);
శూన్య platform_post_listen(శూన్య);
శూన్య platform_post_fork_మాతృ(pid_t బిడ్డ_pid);
శూన్య platform_post_fork_బిడ్డ(శూన్య);
శూన్య platform_pre_session_ప్రారంభం(శూన్య);
పూర్ణాంకం  platform_privileged_uidswap(శూన్య);
శూన్య platform_setusercontext(నిర్మాణం passwd *);
శూన్య platform_setusercontext_post_groups(నిర్మాణం passwd *);
అక్షరం *platform_get_krb5_client(స్థిరరాశి అక్షరం *);
అక్షరం *platform_krb5_get_principal_name(స్థిరరాశి అక్షరం *);
పూర్ణాంకం platform_locked_account(నిర్మాణం passwd *);
పూర్ణాంకం platform_sys_dir_uid(uid_t);
శూన్య platform_disable_tracing(పూర్ణాంకం);

/* in platform-pledge.c */
శూన్య platform_pledge_agent(శూన్య);
శూన్య platform_pledge_sftp_server(శూన్య);
శూన్య platform_pledge_mux(శూన్య);
