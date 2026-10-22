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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "msg.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-sk.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

/* #define DEBUG_SK 1 */

ਸਥਿਰ ਪੂਰਨ
ਸ਼ੁਰੂ_helper(ਪੂਰਨ *fdp, pid_t *pidp, ਖਾਲੀ (**osigchldp)(ਪੂਰਨ))
{
	ਖਾਲੀ (*osigchld)(ਪੂਰਨ);
	ਪੂਰਨ oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	ਅੱਖਰ execbuf[100], *helper, *verbosity = ਨਿਰਾ;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	ਜੇ (helper == ਨਿਰਾ || ਲੜੀ_ਲੰਬਾਈ(helper) == 0)
		helper = ਰਸਤਾ_SSH_SK_HELPER;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	verbosity = "-vvv";
#ਜੇ_ਅੰਤ

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	ਜੇ (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	ਜੇ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ਜੇ ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	}
	ਜੇ (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		ਜੇ ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, ਆਕਾਰ execbuf,
			    "dup2: %s", strerror(errno));
			ਲਿਖ(execpipe[1], execbuf, ਲੜੀ_ਲੰਬਾਈ(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == ਨਿਰਾ ? "" : verbosity);
		execlp(helper, helper, verbosity, (ਅੱਖਰ *)ਨਿਰਾ);
		snprintf(execbuf, ਆਕਾਰ execbuf,
		    "execlp: %s", strerror(errno));
		ਲਿਖ(execpipe[1], execbuf, ਲੜੀ_ਲੰਬਾਈ(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = ਪਠ(execpipe[0], execbuf, ਆਕਾਰ execbuf);
	close(execpipe[0]);
	ਜੇ (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		ਵਾਪਸ SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (ਲੰਮਾ)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
reap_helper(pid_t pid)
{
	ਪੂਰਨ ਸਥਿਤੀ, oerrno;

	debug3_f("pid=%ld", (ਲੰਮਾ)pid);

	errno = 0;
	ਜਦੋਂ (waitpid(pid, &ਸਥਿਤੀ, 0) == -1) {
		ਜੇ (errno == EINTR) {
			errno = 0;
			ਜਾਰੀ;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	}
	ਜੇ (!WIFEXITED(ਸਥਿਤੀ)) {
		error_f("helper exited abnormally");
		ਵਾਪਸ SSH_ERR_AGENT_FAILURE;
	} ਨਹੀਂਤਾਂ ਜੇ (WEXITSTATUS(ਸਥਿਤੀ) != 0) {
		error_f("helper exited with non-zero exit status");
		ਵਾਪਸ SSH_ERR_AGENT_FAILURE;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
client_converse(ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ, ਬਣਤਰ sshbuf **respp, u_int type)
{
	ਪੂਰਨ oerrno, fd, r2, ll, r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char ਸੰਸਕਰਣ;
	ਖਾਲੀ (*osigchld)(ਪੂਰਨ);
	ਬਣਤਰ sshbuf *req = ਨਿਰਾ, *resp = ਨਿਰਾ;
	*respp = ਨਿਰਾ;

	ਜੇ ((r = ਸ਼ੁਰੂ_helper(&fd, &pid, &osigchld)) != 0)
		ਵਾਪਸ r;

	ਜੇ ((req = sshbuf_new()) == ਨਿਰਾ || (resp = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	ਜੇ ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, ਸੁਨੇਹਾ)) != 0) {
		error_fr(r, "compose");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = ssh_ਸੁਨੇਹਾ_send(fd, SSH_SK_HELPER_ਸੰਸਕਰਣ, req)) != 0) {
		error_fr(r, "send");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = ssh_ਸੁਨੇਹਾ_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_get_u8(resp, &ਸੰਸਕਰਣ)) != 0) {
		error_fr(r, "parse version");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (ਸੰਸਕਰਣ != SSH_SK_HELPER_ਸੰਸਕਰਣ) {
		error_f("unsupported version: got %u, expected %u",
		    ਸੰਸਕਰਣ, SSH_SK_HELPER_ਸੰਸਕਰਣ);
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (rtype == SSH_SK_HELPER_ERROR) {
		ਜੇ ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		ਜੇ (rerr == 0 || rerr >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
			r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਨਹੀਂਤਾਂ
			r = -(ਪੂਰਨ)rerr;
		ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	oerrno = errno;
	close(fd);
	ਜੇ ((r2 = reap_helper(pid)) != 0) {
		ਜੇ (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	ਜੇ (r == 0) {
		*respp = resp;
		resp = ਨਿਰਾ;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	ਵਾਪਸ r;

}

ਪੂਰਨ
sshsk_sign(ਅਚਲ ਅੱਖਰ *provider, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp, ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    u_int compat, ਅਚਲ ਅੱਖਰ *pin)
{
	ਪੂਰਨ oerrno, r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshbuf *kbuf = ਨਿਰਾ, *req = ਨਿਰਾ, *resp = ਨਿਰਾ;

	*sigp = ਨਿਰਾ;
	*lenp = 0;

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ENABLE_SK
	ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN;
#ਜੇ_ਅੰਤ

	ਜੇ ((kbuf = sshbuf_new()) == ਨਿਰਾ ||
	    (req = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = sshkey_ਨਿੱਜੀ_serialize(ਕੁੰਜੀ, kbuf)) != 0) {
		error_fr(r, "encode key");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, ਅੰਕੜੇ, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, ਨਿਰਾ)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	oerrno = errno;
	ਜੇ (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = ਨਿਰਾ;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshsk_enroll(ਪੂਰਨ type, ਅਚਲ ਅੱਖਰ *provider_ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *device,
    ਅਚਲ ਅੱਖਰ *application, ਅਚਲ ਅੱਖਰ *userid, uint8_t flags,
    ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sshbuf *challenge_buf,
    ਬਣਤਰ sshkey **keyp, ਬਣਤਰ sshbuf *attest)
{
	ਪੂਰਨ oerrno, r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshbuf *kbuf = ਨਿਰਾ, *abuf = ਨਿਰਾ, *req = ਨਿਰਾ, *resp = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;

	*keyp = ਨਿਰਾ;
	ਜੇ (attest != ਨਿਰਾ)
		sshbuf_reset(attest);

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ENABLE_SK
	ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN;
#ਜੇ_ਅੰਤ

	ਜੇ (type < 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ਜੇ ((abuf = sshbuf_new()) == ਨਿਰਾ ||
	    (kbuf = sshbuf_new()) == ਨਿਰਾ ||
	    (req = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_ਰਸਤਾ)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshkey_ਨਿੱਜੀ_deserialize(kbuf, &ਕੁੰਜੀ)) != 0) {
		error_fr(r, "encode");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (attest != ਨਿਰਾ && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* success */
	r = 0;
	*keyp = ਕੁੰਜੀ;
	ਕੁੰਜੀ = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	oerrno = errno;
	sshkey_free(ਕੁੰਜੀ);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ਵਾਪਸ r;
}

ਸਥਿਰ ਖਾਲੀ
sshsk_free_resident_ਕੁੰਜੀ(ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ *srk)
{
	ਜੇ (srk == ਨਿਰਾ)
		ਵਾਪਸ;
	sshkey_free(srk->ਕੁੰਜੀ);
	freezero(srk->user_id, srk->user_id_len);
	ਮੁਕਤ(srk);
}


ਖਾਲੀ
sshsk_free_resident_ਕੁੰਜੀਆਂ(ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ **srks, ਮਾਪ_t nsrks)
{
	ਮਾਪ_t i;

	ਜੇ (srks == ਨਿਰਾ || nsrks == 0)
		ਵਾਪਸ;

	ਲਈ (i = 0; i < nsrks; i++)
		sshsk_free_resident_ਕੁੰਜੀ(srks[i]);
	ਮੁਕਤ(srks);
}

ਪੂਰਨ
sshsk_ਲੱਦੋ_resident(ਅਚਲ ਅੱਖਰ *provider_ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *device,
    ਅਚਲ ਅੱਖਰ *pin, u_int flags, ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ ***srksp,
    ਮਾਪ_t *nsrksp)
{
	ਪੂਰਨ oerrno, r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshbuf *kbuf = ਨਿਰਾ, *req = ਨਿਰਾ, *resp = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ *srk = ਨਿਰਾ, **srks = ਨਿਰਾ, **tmp;
	u_char *userid = ਨਿਰਾ;
	ਮਾਪ_t userid_len = 0, nsrks = 0;

	*srksp = ਨਿਰਾ;
	*nsrksp = 0;

	ਜੇ ((kbuf = sshbuf_new()) == ਨਿਰਾ ||
	    (req = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = sshbuf_put_cstring(req, provider_ਰਸਤਾ)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = client_converse(req, &resp, SSH_SK_HELPER_ਲੱਦੋ_RESIDENT)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜਦੋਂ (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		ਜੇ ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, ਨਿਰਾ, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshkey_ਨਿੱਜੀ_deserialize(kbuf, &ਕੁੰਜੀ)) != 0) {
			error_fr(r, "decode key");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((srk = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*srk))) == ਨਿਰਾ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		srk->ਕੁੰਜੀ = ਕੁੰਜੀ;
		ਕੁੰਜੀ = ਨਿਰਾ;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = ਨਿਰਾ;
		userid_len = 0;
		ਜੇ ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    ਆਕਾਰ(*srks))) == ਨਿਰਾ) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->ਕੁੰਜੀ), srk->ਕੁੰਜੀ->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ਨਿਰਾ;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ਨਿਰਾ;
	nsrks = 0;
 ਬਾਹਰਲਾ:
	oerrno = errno;
	sshsk_free_resident_ਕੁੰਜੀ(srk);
	sshsk_free_resident_ਕੁੰਜੀਆਂ(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(ਕੁੰਜੀ);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ਵਾਪਸ r;
}
