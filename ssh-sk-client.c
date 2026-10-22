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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/wait.h>

#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <fcntl.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "msg.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "ssh-sk.h"
#അന്തര്ഭാവ "misc.h"

/* #define DEBUG_SK 1 */

സ്ഥിതം പൂർണ്ണസംഖ്യ
start_helper(പൂർണ്ണസംഖ്യ *fdp, pid_t *pidp, ശൂന്യം (**osigchldp)(പൂർണ്ണസംഖ്യ))
{
	ശൂന്യം (*osigchld)(പൂർണ്ണസംഖ്യ);
	പൂർണ്ണസംഖ്യ oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	അക്ഷരം execbuf[100], *helper, *verbosity = ശൂന്യ;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	എങ്കിൽ (helper == ശൂന്യ || strlen(helper) == 0)
		helper = _PATH_SSH_SK_HELPER;
#ifdef DEBUG_SK
	verbosity = "-vvv";
#endif

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	എങ്കിൽ (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	എങ്കിൽ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	എങ്കിൽ ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	}
	എങ്കിൽ (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		എങ്കിൽ ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, വലുപ്പം execbuf,
			    "dup2: %s", strerror(errno));
			ലിഖ(execpipe[1], execbuf, strlen(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == ശൂന്യ ? "" : verbosity);
		execlp(helper, helper, verbosity, (അക്ഷരം *)ശൂന്യ);
		snprintf(execbuf, വലുപ്പം execbuf,
		    "execlp: %s", strerror(errno));
		ലിഖ(execpipe[1], execbuf, strlen(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = പഠ(execpipe[0], execbuf, വലുപ്പം execbuf);
	close(execpipe[0]);
	എങ്കിൽ (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		തിരികെ SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (long)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
reap_helper(pid_t pid)
{
	പൂർണ്ണസംഖ്യ status, oerrno;

	debug3_f("pid=%ld", (long)pid);

	errno = 0;
	ആകുമ്പോൾ (waitpid(pid, &status, 0) == -1) {
		എങ്കിൽ (errno == EINTR) {
			errno = 0;
			തുടരുക;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	}
	എങ്കിൽ (!WIFEXITED(status)) {
		error_f("helper exited abnormally");
		തിരികെ SSH_ERR_AGENT_FAILURE;
	} അല്ലെങ്കിൽ എങ്കിൽ (WEXITSTATUS(status) != 0) {
		error_f("helper exited with non-zero exit status");
		തിരികെ SSH_ERR_AGENT_FAILURE;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
client_converse(ഘടന sshbuf *സന്ദേശം, ഘടന sshbuf **respp, u_int type)
{
	പൂർണ്ണസംഖ്യ oerrno, fd, r2, ll, r = SSH_ERR_INTERNAL_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char version;
	ശൂന്യം (*osigchld)(പൂർണ്ണസംഖ്യ);
	ഘടന sshbuf *req = ശൂന്യ, *resp = ശൂന്യ;
	*respp = ശൂന്യ;

	എങ്കിൽ ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		തിരികെ r;

	എങ്കിൽ ((req = sshbuf_new()) == ശൂന്യ || (resp = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	എങ്കിൽ ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, സന്ദേശം)) != 0) {
		error_fr(r, "compose");
		പോകുക out;
	}
	എങ്കിൽ ((r = ssh_സന്ദേശം_send(fd, SSH_SK_HELPER_VERSION, req)) != 0) {
		error_fr(r, "send");
		പോകുക out;
	}
	എങ്കിൽ ((r = ssh_സന്ദേശം_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_get_u8(resp, &version)) != 0) {
		error_fr(r, "parse version");
		പോകുക out;
	}
	എങ്കിൽ (version != SSH_SK_HELPER_VERSION) {
		error_f("unsupported version: got %u, expected %u",
		    version, SSH_SK_HELPER_VERSION);
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		പോകുക out;
	}
	എങ്കിൽ (rtype == SSH_SK_HELPER_ERROR) {
		എങ്കിൽ ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			പോകുക out;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		എങ്കിൽ (rerr == 0 || rerr >= INT_MAX)
			r = SSH_ERR_INTERNAL_ERROR;
		അല്ലെങ്കിൽ
			r = -(പൂർണ്ണസംഖ്യ)rerr;
		പോകുക out;
	} അല്ലെങ്കിൽ എങ്കിൽ (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_INTERNAL_ERROR;
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	എങ്കിൽ ((r2 = reap_helper(pid)) != 0) {
		എങ്കിൽ (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	എങ്കിൽ (r == 0) {
		*respp = resp;
		resp = ശൂന്യ;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	തിരികെ r;

}

പൂർണ്ണസംഖ്യ
sshsk_sign(സ്ഥിരം അക്ഷരം *provider, ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp, സ്ഥിരം u_char *data, size_t datalen,
    u_int compat, സ്ഥിരം അക്ഷരം *pin)
{
	പൂർണ്ണസംഖ്യ oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshbuf *kbuf = ശൂന്യ, *req = ശൂന്യ, *resp = ശൂന്യ;

	*sigp = ശൂന്യ;
	*lenp = 0;

#ifndef ENABLE_SK
	തിരികെ SSH_ERR_താക്കോൽ_TYPE_UNKNOWN;
#endif

	എങ്കിൽ ((kbuf = sshbuf_new()) == ശൂന്യ ||
	    (req = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}

	എങ്കിൽ ((r = sshkey_private_serialize(താക്കോൽ, kbuf)) != 0) {
		error_fr(r, "encode key");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, ശൂന്യ)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		പോകുക out;
	}

	എങ്കിൽ ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		പോകുക out;

	എങ്കിൽ ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	എങ്കിൽ (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = ശൂന്യ;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshsk_enroll(പൂർണ്ണസംഖ്യ type, സ്ഥിരം അക്ഷരം *provider_path, സ്ഥിരം അക്ഷരം *device,
    സ്ഥിരം അക്ഷരം *application, സ്ഥിരം അക്ഷരം *userid, uint8_t flags,
    സ്ഥിരം അക്ഷരം *pin, ഘടന sshbuf *challenge_buf,
    ഘടന sshkey **keyp, ഘടന sshbuf *attest)
{
	പൂർണ്ണസംഖ്യ oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshbuf *kbuf = ശൂന്യ, *abuf = ശൂന്യ, *req = ശൂന്യ, *resp = ശൂന്യ;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;

	*keyp = ശൂന്യ;
	എങ്കിൽ (attest != ശൂന്യ)
		sshbuf_reset(attest);

#ifndef ENABLE_SK
	തിരികെ SSH_ERR_താക്കോൽ_TYPE_UNKNOWN;
#endif

	എങ്കിൽ (type < 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	എങ്കിൽ ((abuf = sshbuf_new()) == ശൂന്യ ||
	    (kbuf = sshbuf_new()) == ശൂന്യ ||
	    (req = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}

	എങ്കിൽ ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		പോകുക out;
	}

	എങ്കിൽ ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		പോകുക out;

	എങ്കിൽ ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshkey_private_deserialize(kbuf, &താക്കോൽ)) != 0) {
		error_fr(r, "encode");
		പോകുക out;
	}
	എങ്കിൽ (attest != ശൂന്യ && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		പോകുക out;
	}

	/* success */
	r = 0;
	*keyp = താക്കോൽ;
	താക്കോൽ = ശൂന്യ;
 out:
	oerrno = errno;
	sshkey_free(താക്കോൽ);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	തിരികെ r;
}

സ്ഥിതം ശൂന്യം
sshsk_free_resident_താക്കോൽ(ഘടന sshsk_resident_താക്കോൽ *srk)
{
	എങ്കിൽ (srk == ശൂന്യ)
		തിരികെ;
	sshkey_free(srk->താക്കോൽ);
	freezero(srk->user_id, srk->user_id_len);
	സ്വതന്ത്രം(srk);
}


ശൂന്യം
sshsk_free_resident_താക്കോലുകൾ(ഘടന sshsk_resident_താക്കോൽ **srks, size_t nsrks)
{
	size_t i;

	എങ്കിൽ (srks == ശൂന്യ || nsrks == 0)
		തിരികെ;

	വേണ്ടി (i = 0; i < nsrks; i++)
		sshsk_free_resident_താക്കോൽ(srks[i]);
	സ്വതന്ത്രം(srks);
}

പൂർണ്ണസംഖ്യ
sshsk_load_resident(സ്ഥിരം അക്ഷരം *provider_path, സ്ഥിരം അക്ഷരം *device,
    സ്ഥിരം അക്ഷരം *pin, u_int flags, ഘടന sshsk_resident_താക്കോൽ ***srksp,
    size_t *nsrksp)
{
	പൂർണ്ണസംഖ്യ oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshbuf *kbuf = ശൂന്യ, *req = ശൂന്യ, *resp = ശൂന്യ;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	ഘടന sshsk_resident_താക്കോൽ *srk = ശൂന്യ, **srks = ശൂന്യ, **tmp;
	u_char *userid = ശൂന്യ;
	size_t userid_len = 0, nsrks = 0;

	*srksp = ശൂന്യ;
	*nsrksp = 0;

	എങ്കിൽ ((kbuf = sshbuf_new()) == ശൂന്യ ||
	    (req = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}

	എങ്കിൽ ((r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		പോകുക out;
	}

	എങ്കിൽ ((r = client_converse(req, &resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		പോകുക out;

	ആകുമ്പോൾ (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		എങ്കിൽ ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, ശൂന്യ, ശൂന്യ)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		എങ്കിൽ ((r = sshkey_private_deserialize(kbuf, &താക്കോൽ)) != 0) {
			error_fr(r, "decode key");
			പോകുക out;
		}
		എങ്കിൽ ((srk = calloc(1, വലുപ്പം(*srk))) == ശൂന്യ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		srk->താക്കോൽ = താക്കോൽ;
		താക്കോൽ = ശൂന്യ;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = ശൂന്യ;
		userid_len = 0;
		എങ്കിൽ ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    വലുപ്പം(*srks))) == ശൂന്യ) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->താക്കോൽ), srk->താക്കോൽ->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ശൂന്യ;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ശൂന്യ;
	nsrks = 0;
 out:
	oerrno = errno;
	sshsk_free_resident_താക്കോൽ(srk);
	sshsk_free_resident_താക്കോലുകൾ(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(താക്കോൽ);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	തിരികെ r;
}
