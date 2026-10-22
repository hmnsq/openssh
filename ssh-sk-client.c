/* $OpenBSD: ssh-sk-client.c,v 1.18 2026/03/11 09:10:59 dtucker Exp $ */
/*
 * Copyright (c) 2019 Google LLC
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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/wait.h>

#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <fcntl.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "msg.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "ssh-sk.h"
#અન્તર્ભાવ "misc.h"

/* #define DEBUG_SK 1 */

સ્થિર પૂર્ણાંક
start_helper(પૂર્ણાંક *fdp, pid_t *pidp, શૂન્ય (**osigchldp)(પૂર્ણાંક))
{
	શૂન્ય (*osigchld)(પૂર્ણાંક);
	પૂર્ણાંક oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	અક્ષર execbuf[100], *helper, *verbosity = ખાલી;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	જો (helper == ખાલી || strlen(helper) == 0)
		helper = _PATH_SSH_SK_HELPER;
#ifdef DEBUG_SK
	verbosity = "-vvv";
#endif

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	જો (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		પાછા SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	જો (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		પાછા SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	જો ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		પાછા SSH_ERR_SYSTEM_ERROR;
	}
	જો (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		જો ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, કદ execbuf,
			    "dup2: %s", strerror(errno));
			લિખ(execpipe[1], execbuf, strlen(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == ખાલી ? "" : verbosity);
		execlp(helper, helper, verbosity, (અક્ષર *)ખાલી);
		snprintf(execbuf, કદ execbuf,
		    "execlp: %s", strerror(errno));
		લિખ(execpipe[1], execbuf, strlen(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = પઠ(execpipe[0], execbuf, કદ execbuf);
	close(execpipe[0]);
	જો (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		પાછા SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (long)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
reap_helper(pid_t pid)
{
	પૂર્ણાંક status, oerrno;

	debug3_f("pid=%ld", (long)pid);

	errno = 0;
	જ્યારે (waitpid(pid, &status, 0) == -1) {
		જો (errno == EINTR) {
			errno = 0;
			ચાલુ;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		પાછા SSH_ERR_SYSTEM_ERROR;
	}
	જો (!WIFEXITED(status)) {
		error_f("helper exited abnormally");
		પાછા SSH_ERR_AGENT_FAILURE;
	} નહીંતર જો (WEXITSTATUS(status) != 0) {
		error_f("helper exited with non-zero exit status");
		પાછા SSH_ERR_AGENT_FAILURE;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
client_converse(સંરચના sshbuf *સંદેશ, સંરચના sshbuf **respp, u_int type)
{
	પૂર્ણાંક oerrno, fd, r2, ll, r = SSH_ERR_INTERNAL_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char version;
	શૂન્ય (*osigchld)(પૂર્ણાંક);
	સંરચના sshbuf *req = ખાલી, *resp = ખાલી;
	*respp = ખાલી;

	જો ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		પાછા r;

	જો ((req = sshbuf_new()) == ખાલી || (resp = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	જો ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, સંદેશ)) != 0) {
		error_fr(r, "compose");
		જાઓ out;
	}
	જો ((r = ssh_સંદેશ_send(fd, SSH_SK_HELPER_VERSION, req)) != 0) {
		error_fr(r, "send");
		જાઓ out;
	}
	જો ((r = ssh_સંદેશ_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		જાઓ out;
	}
	જો ((r = sshbuf_get_u8(resp, &version)) != 0) {
		error_fr(r, "parse version");
		જાઓ out;
	}
	જો (version != SSH_SK_HELPER_VERSION) {
		error_f("unsupported version: got %u, expected %u",
		    version, SSH_SK_HELPER_VERSION);
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		જાઓ out;
	}
	જો (rtype == SSH_SK_HELPER_ERROR) {
		જો ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			જાઓ out;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		જો (rerr == 0 || rerr >= INT_MAX)
			r = SSH_ERR_INTERNAL_ERROR;
		નહીંતર
			r = -(પૂર્ણાંક)rerr;
		જાઓ out;
	} નહીંતર જો (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_INTERNAL_ERROR;
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	જો ((r2 = reap_helper(pid)) != 0) {
		જો (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	જો (r == 0) {
		*respp = resp;
		resp = ખાલી;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	પાછા r;

}

પૂર્ણાંક
sshsk_sign(અચલ અક્ષર *provider, સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp, અચલ u_char *data, size_t datalen,
    u_int compat, અચલ અક્ષર *pin)
{
	પૂર્ણાંક oerrno, r = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshbuf *kbuf = ખાલી, *req = ખાલી, *resp = ખાલી;

	*sigp = ખાલી;
	*lenp = 0;

#ifndef ENABLE_SK
	પાછા SSH_ERR_ચાવી_TYPE_UNKNOWN;
#endif

	જો ((kbuf = sshbuf_new()) == ખાલી ||
	    (req = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}

	જો ((r = sshkey_private_serialize(ચાવી, kbuf)) != 0) {
		error_fr(r, "encode key");
		જાઓ out;
	}
	જો ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, ખાલી)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		જાઓ out;
	}

	જો ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		જાઓ out;

	જો ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	જો (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = ખાલી;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	પાછા r;
}

પૂર્ણાંક
sshsk_enroll(પૂર્ણાંક type, અચલ અક્ષર *provider_path, અચલ અક્ષર *device,
    અચલ અક્ષર *application, અચલ અક્ષર *userid, uint8_t flags,
    અચલ અક્ષર *pin, સંરચના sshbuf *challenge_buf,
    સંરચના sshkey **keyp, સંરચના sshbuf *attest)
{
	પૂર્ણાંક oerrno, r = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshbuf *kbuf = ખાલી, *abuf = ખાલી, *req = ખાલી, *resp = ખાલી;
	સંરચના sshkey *ચાવી = ખાલી;

	*keyp = ખાલી;
	જો (attest != ખાલી)
		sshbuf_reset(attest);

#ifndef ENABLE_SK
	પાછા SSH_ERR_ચાવી_TYPE_UNKNOWN;
#endif

	જો (type < 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	જો ((abuf = sshbuf_new()) == ખાલી ||
	    (kbuf = sshbuf_new()) == ખાલી ||
	    (req = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}

	જો ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		જાઓ out;
	}

	જો ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		જાઓ out;

	જો ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો ((r = sshkey_private_deserialize(kbuf, &ચાવી)) != 0) {
		error_fr(r, "encode");
		જાઓ out;
	}
	જો (attest != ખાલી && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		જાઓ out;
	}

	/* success */
	r = 0;
	*keyp = ચાવી;
	ચાવી = ખાલી;
 out:
	oerrno = errno;
	sshkey_free(ચાવી);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	પાછા r;
}

સ્થિર શૂન્ય
sshsk_free_resident_ચાવી(સંરચના sshsk_resident_ચાવી *srk)
{
	જો (srk == ખાલી)
		પાછા;
	sshkey_free(srk->ચાવી);
	freezero(srk->user_id, srk->user_id_len);
	મુક્ત(srk);
}


શૂન્ય
sshsk_free_resident_ચાવીઓ(સંરચના sshsk_resident_ચાવી **srks, size_t nsrks)
{
	size_t i;

	જો (srks == ખાલી || nsrks == 0)
		પાછા;

	માટે (i = 0; i < nsrks; i++)
		sshsk_free_resident_ચાવી(srks[i]);
	મુક્ત(srks);
}

પૂર્ણાંક
sshsk_load_resident(અચલ અક્ષર *provider_path, અચલ અક્ષર *device,
    અચલ અક્ષર *pin, u_int flags, સંરચના sshsk_resident_ચાવી ***srksp,
    size_t *nsrksp)
{
	પૂર્ણાંક oerrno, r = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshbuf *kbuf = ખાલી, *req = ખાલી, *resp = ખાલી;
	સંરચના sshkey *ચાવી = ખાલી;
	સંરચના sshsk_resident_ચાવી *srk = ખાલી, **srks = ખાલી, **tmp;
	u_char *userid = ખાલી;
	size_t userid_len = 0, nsrks = 0;

	*srksp = ખાલી;
	*nsrksp = 0;

	જો ((kbuf = sshbuf_new()) == ખાલી ||
	    (req = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}

	જો ((r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		જાઓ out;
	}

	જો ((r = client_converse(req, &resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		જાઓ out;

	જ્યારે (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		જો ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, ખાલી, ખાલી)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		જો ((r = sshkey_private_deserialize(kbuf, &ચાવી)) != 0) {
			error_fr(r, "decode key");
			જાઓ out;
		}
		જો ((srk = calloc(1, કદ(*srk))) == ખાલી) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		srk->ચાવી = ચાવી;
		ચાવી = ખાલી;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = ખાલી;
		userid_len = 0;
		જો ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    કદ(*srks))) == ખાલી) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->ચાવી), srk->ચાવી->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ખાલી;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ખાલી;
	nsrks = 0;
 out:
	oerrno = errno;
	sshsk_free_resident_ચાવી(srk);
	sshsk_free_resident_ચાવીઓ(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(ચાવી);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	પાછા r;
}
