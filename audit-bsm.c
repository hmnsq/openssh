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

#અન્તર્ભાવ "includes.h"
#જો defined(USE_BSM_AUDIT)

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#ifdef BROKEN_BSM_API
#અન્તર્ભાવ <libscf.h>
#endif

#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "xmalloc.h"

#ifndef AUE_openssh
# define AUE_openssh     32800
#endif
#અન્તર્ભાવ <bsm/audit.h>
#અન્તર્ભાવ <bsm/libbsm.h>
#અન્તર્ભાવ <bsm/audit_uevents.h>
#અન્તર્ભાવ <bsm/audit_record.h>
#અન્તર્ભાવ <locale.h>

#જો defined(HAVE_GETAUDIT_ADDR)
#define	AuditInfoStruct		auditinfo_addr
#define AuditInfoTermID		au_tid_addr_t
#define SetAuditFunc(a,b)	setaudit_addr((a),(b))
#define SetAuditFuncText	"setaudit_addr"
#define AUToSubjectFunc		au_to_subject_ex
#define AUToReturnFunc(a,b)	au_to_return32((a), (int32_t)(b))
#નહીંતર
#define	AuditInfoStruct		auditinfo
#define AuditInfoTermID		au_tid_t
#define SetAuditFunc(a,b)	setaudit(a)
#define SetAuditFuncText	"setaudit"
#define AUToSubjectFunc		au_to_subject
#define AUToReturnFunc(a,b)	au_to_return((a), (u_int)(b))
#endif

#ifndef cannot_audit
બાહ્ય પૂર્ણાંક	cannot_audit(પૂર્ણાંક);
#endif
બાહ્ય શૂન્ય	aug_init(શૂન્ય);
બાહ્ય શૂન્ય	aug_save_auid(au_id_t);
બાહ્ય શૂન્ય	aug_save_uid(uid_t);
બાહ્ય શૂન્ય	aug_save_euid(uid_t);
બાહ્ય શૂન્ય	aug_save_gid(gid_t);
બાહ્ય શૂન્ય	aug_save_egid(gid_t);
બાહ્ય શૂન્ય	aug_save_pid(pid_t);
બાહ્ય શૂન્ય	aug_save_asid(au_asid_t);
બાહ્ય શૂન્ય	aug_save_tid(dev_t, unsigned પૂર્ણાંક);
બાહ્ય શૂન્ય	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
બાહ્ય પૂર્ણાંક	aug_save_me(શૂન્ય);
બાહ્ય પૂર્ણાંક	aug_save_namask(શૂન્ય);
બાહ્ય શૂન્ય	aug_save_event(au_event_t);
બાહ્ય શૂન્ય	aug_save_sorf(પૂર્ણાંક);
બાહ્ય શૂન્ય	aug_save_text(અક્ષર *);
બાહ્ય શૂન્ય	aug_save_text1(અક્ષર *);
બાહ્ય શૂન્ય	aug_save_text2(અક્ષર *);
બાહ્ય શૂન્ય	aug_save_na(પૂર્ણાંક);
બાહ્ય શૂન્ય	aug_save_user(અક્ષર *);
બાહ્ય શૂન્ય	aug_save_path(અક્ષર *);
બાહ્ય પૂર્ણાંક	aug_save_policy(શૂન્ય);
બાહ્ય શૂન્ય	aug_save_afunc(પૂર્ણાંક (*)(પૂર્ણાંક));
બાહ્ય પૂર્ણાંક	aug_audit(શૂન્ય);
બાહ્ય પૂર્ણાંક	aug_na_selected(શૂન્ય);
બાહ્ય પૂર્ણાંક	aug_selected(શૂન્ય);
બાહ્ય પૂર્ણાંક	aug_daemon_session(શૂન્ય);

#ifndef HAVE_GETTEXT
# define gettext(a)	(a)
#endif

બાહ્ય Authctxt *the_authctxt;
સ્થિર AuditInfoTermID ssh_bsm_tid;

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
#જો defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
બાહ્ય પૂર્ણાંક aug_get_machine(અક્ષર *, uint32_t *, uint32_t *);
#નહીંતર
સ્થિર પૂર્ણાંક
aug_get_machine(અક્ષર *host, uint32_t *addr, uint32_t *type)
{
	સંરચના addrinfo *ai; 
	સંરચના sockaddr_in *in4;
	સંરચના sockaddr_in6 *in6;
	પૂર્ણાંક ret = 0, r;

	જો ((r = getaddrinfo(host, ખાલી, ખાલી, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		પાછા -1;
	}
	
	પસંદગી (ai->ai_family) {
	સ્થિતિ AF_INET:
		in4 = (સંરચના sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		memcpy(addr, &in4->sin_addr, કદ(સંરચના in_addr));
		તોડો;
#ifdef AU_IPv6
	સ્થિતિ AF_INET6: 
		in6 = (સંરચના sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		memcpy(addr, &in6->sin6_addr, કદ(સંરચના in6_addr));
		તોડો;
#endif
	મૂળભૂત:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	પાછા ret;
}
#endif

#ifdef BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
પૂર્ણાંક
getacna(અક્ષર *auditstring, પૂર્ણાંક len)
{
	scf_handle_t *handle = ખાલી;
	scf_property_t *property = ખાલી;
	scf_કિંમત_t *કિંમત = ખાલી;
	પૂર્ણાંક ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_VERSION);
	જો (handle == ખાલી) 
		પાછા -2;

	ret = scf_handle_bind(handle);
	જો (ret == -1) 
		પાછા -2;

	property = scf_property_create(handle);
	જો (property == ખાલી) 
		પાછા -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    ખાલી, ખાલી, ખાલી, ખાલી, property, 0);
	જો (ret == -1) 
		પાછા -2;

	કિંમત = scf_કિંમત_create(handle);
	જો (કિંમત == ખાલી) 
		પાછા -2;

	ret = scf_property_get_કિંમત(property, કિંમત);
	જો (ret == -1) 
		પાછા -2;

	ret = scf_કિંમત_get_astring(કિંમત, auditstring, len);
	જો (ret == -1) 
		પાછા -2;

	scf_કિંમત_destroy(કિંમત);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	પાછા 0;
}
#endif

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
સ્થિર પૂર્ણાંક
selected(અક્ષર *username, uid_t uid, au_event_t event, પૂર્ણાંક sf)
{
	પૂર્ણાંક rc, sorf;
	અક્ષર naflags[512];
	સંરચના au_mask mask;

	mask.am_success = mask.am_failure = 0;
	જો (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, કદ(naflags));
		જો (rc == 0)
			(શૂન્ય) getauditflagsbin(naflags, &mask);
	} નહીંતર
		rc = au_user_mask(username, &mask);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	પાછા(au_preselect(event, &mask, sorf, AU_PRS_REREAD));
}

સ્થિર શૂન્ય
bsm_audit_record(પૂર્ણાંક typ, અક્ષર *string, au_event_t event_no)
{
	પૂર્ણાંક		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	AuditInfoTermID	tid = ssh_bsm_tid;

	જો (the_authctxt != ખાલી && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	જો (!sel)
		પાછા;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(શૂન્ય) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(શૂન્ય) au_write(ad, au_to_text(string));
	(શૂન્ય) au_write(ad, AUToReturnFunc(typ, rc));

#ifdef BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_TO_WRITE, event_no, 0);
#નહીંતર
	rc = au_close(ad, AU_TO_WRITE, event_no);
#endif

	જો (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

સ્થિર શૂન્ય
bsm_audit_session_setup(શૂન્ય)
{
	પૂર્ણાંક rc;
	સંરચના AuditInfoStruct info;
	au_mask_t mask;

	જો (the_authctxt == ખાલી) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		પાછા;
	}

	જો (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	નહીંતર
		info.ai_auid = -1;
	info.ai_asid = getpid();
	mask.am_success = 0;
	mask.am_failure = 0;

	(શૂન્ય) au_user_mask(the_authctxt->user, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = SetAuditFunc(&info, કદ(info));
	જો (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    SetAuditFuncText, strerror(errno));
}

સ્થિર શૂન્ય
bsm_audit_bad_login(અચલ અક્ષર *what)
{
	અક્ષર textbuf[BSM_TEXTBUFSZ];

	જો (the_authctxt->valid) {
		(શૂન્ય) snprintf(textbuf, કદ (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_record(4, textbuf, AUE_openssh);
	} નહીંતર {
		(શૂન્ય) snprintf(textbuf, કદ (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_record(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

શૂન્ય
audit_connection_from(અચલ અક્ષર *host, પૂર્ણાંક port)
{
	AuditInfoTermID *tid = &ssh_bsm_tid;
	અક્ષર buf[1024];

	જો (cannot_audit(0))
		પાછા;
	debug3("BSM audit: connection from %.100s port %d", host, port);

	/* populate our terminal id structure */
#જો defined(HAVE_GETAUDIT_ADDR)
	tid->at_port = (dev_t)port;
	aug_get_machine((અક્ષર *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, કદ(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (પૂર્ણાંક)tid->at_type, buf);
#નહીંતર
	/* this is used on IPv4-only machines */
	tid->port = (dev_t)port;
	tid->machine = inet_addr(host);
	snprintf(buf, કદ(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#endif
}

શૂન્ય
audit_run_command(અચલ અક્ષર *command)
{
	/* not implemented */
}

શૂન્ય
audit_session_open(સંરચના logininfo *li)
{
	/* not implemented */
}

શૂન્ય
audit_session_close(સંરચના logininfo *li)
{
	/* not implemented */
}

શૂન્ય
audit_event(સંરચના ssh *ssh, ssh_audit_event_t event)
{
	અક્ષર    textbuf[BSM_TEXTBUFSZ];
	સ્થિર પૂર્ણાંક logged_in = 0;
	અચલ અક્ષર *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	જો (cannot_audit(0))
		પાછા;

	પસંદગી(event) {
	સ્થિતિ SSH_AUTH_SUCCESS:
		logged_in = 1;
		bsm_audit_session_setup();
		snprintf(textbuf, કદ(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_record(0, textbuf, AUE_openssh);
		તોડો;

	સ્થિતિ SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		જો (logged_in) {
			snprintf(textbuf, કદ(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_record(0, textbuf, AUE_logout);
		} નહીંતર {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		તોડો;

	સ્થિતિ SSH_NOLOGIN:
		bsm_audit_record(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		તોડો;

	સ્થિતિ SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, કદ(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_record(1, textbuf, AUE_openssh);
		તોડો;

	સ્થિતિ SSH_LOGIN_મૂળ_DENIED:
		bsm_audit_record(2, gettext("not_console"), AUE_openssh);
		તોડો;

	સ્થિતિ SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		તોડો;

	સ્થિતિ SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		તોડો;

	મૂળભૂત:
		debug_f("unhandled event %d", event);
	}
}
#endif /* BSM */
