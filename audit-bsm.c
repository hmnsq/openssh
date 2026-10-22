/*
 * TODO
 *
 * - deal with overlap between this and sys_auth_allowed_user
 *   sys_auth_record_login and record_failed_login.
 */

/*
 * Copyright 1988-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/* #pragma ident	"@(#)bsmaudit.c	1.1	01/09/17 SMI" */

#include "includes.h"
#якщо defined(USE_BSM_AUDIT)

#include <sys/types.h>

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#ifdef BROKEN_BSM_API
#include <libscf.h>
#endif

#include "ssh.h"
#include "log.h"
#include "hostfile.h"
#include "auth.h"
#include "xmalloc.h"

#ifndef AUE_openssh
# define AUE_openssh     32800
#endif
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_uevents.h>
#include <bsm/audit_record.h>
#include <locale.h>

#якщо defined(HAVE_GETAUDIT_ADDR)
#define	AuditInfoStruct		auditinfo_addr
#define AuditInfoTermID		au_tid_addr_t
#define SetAuditFunc(a,b)	setaudit_addr((a),(b))
#define SetAuditFuncText	"setaudit_addr"
#define AUToSubjectFunc		au_to_subject_ex
#define AUToReturnFunc(a,b)	au_to_return32((a), (int32_t)(b))
#інакше
#define	AuditInfoStruct		auditinfo
#define AuditInfoTermID		au_tid_t
#define SetAuditFunc(a,b)	setaudit(a)
#define SetAuditFuncText	"setaudit"
#define AUToSubjectFunc		au_to_subject
#define AUToReturnFunc(a,b)	au_to_return((a), (u_int)(b))
#endif

#ifndef cannot_audit
extern ціле	cannot_audit(ціле);
#endif
extern void	aug_init(void);
extern void	aug_save_auid(au_id_t);
extern void	aug_save_uid(uid_t);
extern void	aug_save_euid(uid_t);
extern void	aug_save_gid(gid_t);
extern void	aug_save_egid(gid_t);
extern void	aug_save_pid(pid_t);
extern void	aug_save_asid(au_asid_t);
extern void	aug_save_tid(dev_t, unsigned ціле);
extern void	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
extern ціле	aug_save_me(void);
extern ціле	aug_save_namask(void);
extern void	aug_save_event(au_event_t);
extern void	aug_save_sorf(ціле);
extern void	aug_save_text(char *);
extern void	aug_save_text1(char *);
extern void	aug_save_text2(char *);
extern void	aug_save_na(ціле);
extern void	aug_save_user(char *);
extern void	aug_save_path(char *);
extern ціле	aug_save_policy(void);
extern void	aug_save_afunc(ціле (*)(ціле));
extern ціле	aug_audit(void);
extern ціле	aug_na_selected(void);
extern ціле	aug_selected(void);
extern ціле	aug_daemon_session(void);

#ifndef HAVE_GETTEXT
# define gettext(a)	(a)
#endif

extern Authctxt *the_authctxt;
static AuditInfoTermID ssh_bsm_tid;

#ifdef BROKEN_BSM_API
/* For some reason this constant is no longer defined
   in Solaris 11. */
#define BSM_TEXTBUFSZ 256
#endif

/* Below is the low-level BSM interface code */

/*
 * aug_get_machine is only required on IPv6 capable machines, we use a
 * different mechanism in audit_connection_from() for IPv4-only machines.
 * getaudit_addr() is only present on IPv6 capable machines.
 */
#якщо defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
extern ціле aug_get_machine(char *, uint32_t *, uint32_t *);
#інакше
static ціле
aug_get_machine(char *host, uint32_t *addr, uint32_t *type)
{
	struct addrinfo *ai; 
	struct sockaddr_in *in4;
	struct sockaddr_in6 *in6;
	ціле ret = 0, r;

	якщо ((r = getaddrinfo(host, NULL, NULL, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		повернути -1;
	}
	
	switch (ai->ai_family) {
	case AF_INET:
		in4 = (struct sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		memcpy(addr, &in4->sin_addr, sizeof(struct in_addr));
		break;
#ifdef AU_IPv6
	case AF_INET6: 
		in6 = (struct sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		memcpy(addr, &in6->sin6_addr, sizeof(struct in6_addr));
		break;
#endif
	default:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	повернути ret;
}
#endif

#ifdef BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
ціле
getacna(char *auditstring, ціле len)
{
	scf_handle_t *handle = NULL;
	scf_property_t *property = NULL;
	scf_value_t *value = NULL;
	ціле ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_VERSION);
	якщо (handle == NULL) 
		повернути -2;

	ret = scf_handle_bind(handle);
	якщо (ret == -1) 
		повернути -2;

	property = scf_property_create(handle);
	якщо (property == NULL) 
		повернути -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    NULL, NULL, NULL, NULL, property, 0);
	якщо (ret == -1) 
		повернути -2;

	value = scf_value_create(handle);
	якщо (value == NULL) 
		повернути -2;

	ret = scf_property_get_value(property, value);
	якщо (ret == -1) 
		повернути -2;

	ret = scf_value_get_astring(value, auditstring, len);
	якщо (ret == -1) 
		повернути -2;

	scf_value_destroy(value);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	повернути 0;
}
#endif

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
static ціле
selected(char *username, uid_t uid, au_event_t event, ціле sf)
{
	ціле rc, sorf;
	char naflags[512];
	struct au_mask mask;

	mask.am_success = mask.am_failure = 0;
	якщо (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, sizeof(naflags));
		якщо (rc == 0)
			(void) getauditflagsbin(naflags, &mask);
	} інакше
		rc = au_user_mask(username, &mask);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	повернути(au_preselect(event, &mask, sorf, AU_PRS_REREAD));
}

static void
bsm_audit_record(ціле typ, char *string, au_event_t event_no)
{
	ціле		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	AuditInfoTermID	tid = ssh_bsm_tid;

	якщо (the_authctxt != NULL && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	якщо (!sel)
		повернути;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(void) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(void) au_write(ad, au_to_text(string));
	(void) au_write(ad, AUToReturnFunc(typ, rc));

#ifdef BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_TO_WRITE, event_no, 0);
#інакше
	rc = au_close(ad, AU_TO_WRITE, event_no);
#endif

	якщо (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

static void
bsm_audit_session_setup(void)
{
	ціле rc;
	struct AuditInfoStruct info;
	au_mask_t mask;

	якщо (the_authctxt == NULL) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		повернути;
	}

	якщо (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	інакше
		info.ai_auid = -1;
	info.ai_asid = getpid();
	mask.am_success = 0;
	mask.am_failure = 0;

	(void) au_user_mask(the_authctxt->user, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = SetAuditFunc(&info, sizeof(info));
	якщо (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    SetAuditFuncText, strerror(errno));
}

static void
bsm_audit_bad_login(const char *what)
{
	char textbuf[BSM_TEXTBUFSZ];

	якщо (the_authctxt->valid) {
		(void) snprintf(textbuf, sizeof (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_record(4, textbuf, AUE_openssh);
	} інакше {
		(void) snprintf(textbuf, sizeof (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_record(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

void
audit_connection_from(const char *host, ціле port)
{
	AuditInfoTermID *tid = &ssh_bsm_tid;
	char buf[1024];

	якщо (cannot_audit(0))
		повернути;
	debug3("BSM audit: connection from %.100s port %d", host, port);

	/* populate our terminal id structure */
#якщо defined(HAVE_GETAUDIT_ADDR)
	tid->at_port = (dev_t)port;
	aug_get_machine((char *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, sizeof(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (ціле)tid->at_type, buf);
#інакше
	/* this is used on IPv4-only machines */
	tid->port = (dev_t)port;
	tid->machine = inet_addr(host);
	snprintf(buf, sizeof(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#endif
}

void
audit_run_command(const char *command)
{
	/* not implemented */
}

void
audit_session_open(struct logininfo *li)
{
	/* not implemented */
}

void
audit_session_close(struct logininfo *li)
{
	/* not implemented */
}

void
audit_event(struct ssh *ssh, ssh_audit_event_t event)
{
	char    textbuf[BSM_TEXTBUFSZ];
	static ціле logged_in = 0;
	const char *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	якщо (cannot_audit(0))
		повернути;

	switch(event) {
	case SSH_AUTH_SUCCESS:
		logged_in = 1;
		bsm_audit_session_setup();
		snprintf(textbuf, sizeof(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_record(0, textbuf, AUE_openssh);
		break;

	case SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		якщо (logged_in) {
			snprintf(textbuf, sizeof(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_record(0, textbuf, AUE_logout);
		} інакше {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		break;

	case SSH_NOLOGIN:
		bsm_audit_record(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		break;

	case SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, sizeof(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_record(1, textbuf, AUE_openssh);
		break;

	case SSH_LOGIN_ROOT_DENIED:
		bsm_audit_record(2, gettext("not_console"), AUE_openssh);
		break;

	case SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		break;

	case SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		break;

	default:
		debug_f("unhandled event %d", event);
	}
}
#endif /* BSM */
