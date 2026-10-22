/* 	$OpenBSD: tests.c,v 1.1 2026/05/31 11:39:44 djm Exp $ */
/*
 * Regress tests for servconf.h server configuration API
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

ਬਣਤਰ sshbuf *cfg;

/* stub */
ਪੂਰਨ auth2_methods_valid(ਅਚਲ ਅੱਖਰ *methods, ਪੂਰਨ need_enable);
ਪੂਰਨ
auth2_methods_valid(ਅਚਲ ਅੱਖਰ *methods, ਪੂਰਨ need_enable)
{
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਖਾਲੀ
onerror(ਖਾਲੀ *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((ਬਣਤਰ fuzz *)fuzz);
}

ਸਥਿਰ ਖਾਲੀ
ਸੈੱਟ_string(ਅੱਖਰ **dst, ਅਚਲ ਅੱਖਰ *s)
{
	*dst = s == ਨਿਰਾ ? ਨਿਰਾ : xstrdup(s);
}

ਸਥਿਰ ਅੱਖਰ **
new_string_array(u_int n)
{
	ਵਾਪਸ xcalloc(n, ਆਕਾਰ(ਅੱਖਰ *));
}

ਸਥਿਰ ਖਾਲੀ
ਸੈੱਟ_test_options(ServerOptions *o)
{
	initialize_server_options(o);

	o->ਅੰਕ_ports = 2;
	o->ports[0] = 22;
	o->ports[1] = 2022;
	o->ip_qos_interactive = 0x10;
	o->ip_qos_bulk = 0x08;
	o->log_facility = SYSLOG_FACILITY_AUTH;
	o->log_level = SYSLOG_LEVEL_DEBUG3;
	o->fwd_opts.gateway_ports = 1;
	o->fwd_opts.streamlocal_bind_ਨਕਾਬ = 0177;
	o->fwd_opts.streamlocal_bind_unlink = 1;
	o->permit_user_env = 1;
	ਸੈੱਟ_string(&o->permit_user_env_allowlist, "");
	o->rekey_ਹੱਦਬੰਦੀ = 123456789;
	o->rekey_interval = 600;
	o->timing_secret = 0x0102030405060708ULL;

	ਸੈੱਟ_string(&o->routing_domain, "");
	ਸੈੱਟ_string(&o->banner, ਨਿਰਾ);
	ਸੈੱਟ_string(&o->adm_forced_command, "internal-sftp");
	ਸੈੱਟ_string(&o->chroot_directory, "");
	ਸੈੱਟ_string(&o->host_ਕੁੰਜੀ_agent, ਨਿਰਾ);
	ਸੈੱਟ_string(&o->authorized_ਕੁੰਜੀਆਂ_command, "/bin/echo");
	ਸੈੱਟ_string(&o->authorized_ਕੁੰਜੀਆਂ_command_user, "");
	ਸੈੱਟ_string(&o->authorized_principals_file, ਨਿਰਾ);

	o->ਅੰਕ_authkeys_files = 3;
	o->authorized_ਕੁੰਜੀਆਂ_files = new_string_array(o->ਅੰਕ_authkeys_files);
	ਸੈੱਟ_string(&o->authorized_ਕੁੰਜੀਆਂ_files[0], ਨਿਰਾ);
	ਸੈੱਟ_string(&o->authorized_ਕੁੰਜੀਆਂ_files[1], "");
	ਸੈੱਟ_string(&o->authorized_ਕੁੰਜੀਆਂ_files[2], ".ssh/authorized_keys");

	o->ਅੰਕ_log_verbose = 2;
	o->log_verbose = new_string_array(o->ਅੰਕ_log_verbose);
	ਸੈੱਟ_string(&o->log_verbose[0], ਨਿਰਾ);
	ਸੈੱਟ_string(&o->log_verbose[1], "kex.c:*");

	o->ਅੰਕ_host_ਕੁੰਜੀ_files = 3;
	o->host_ਕੁੰਜੀ_file_userprovided =
	    xcalloc(o->ਅੰਕ_host_ਕੁੰਜੀ_files,
	    ਆਕਾਰ(*o->host_ਕੁੰਜੀ_file_userprovided));
	o->host_ਕੁੰਜੀ_files = new_string_array(o->ਅੰਕ_host_ਕੁੰਜੀ_files);
	o->host_ਕੁੰਜੀ_file_userprovided[0] = 0;
	o->host_ਕੁੰਜੀ_file_userprovided[1] = 1;
	o->host_ਕੁੰਜੀ_file_userprovided[2] = -1;
	ਸੈੱਟ_string(&o->host_ਕੁੰਜੀ_files[0], ਨਿਰਾ);
	ਸੈੱਟ_string(&o->host_ਕੁੰਜੀ_files[1], "");
	ਸੈੱਟ_string(&o->host_ਕੁੰਜੀ_files[2], "/tmp/ssh_host_ed25519_key");

	o->ਅੰਕ_queued_listens = 2;
	o->queued_listen_addrs = xcalloc(o->ਅੰਕ_queued_listens,
	    ਆਕਾਰ(*o->queued_listen_addrs));
	ਸੈੱਟ_string(&o->queued_listen_addrs[0].addr, "127.0.0.1");
	o->queued_listen_addrs[0].ਪੋਰਟ = 2222;
	ਸੈੱਟ_string(&o->queued_listen_addrs[0].rdomain, ਨਿਰਾ);
	ਸੈੱਟ_string(&o->queued_listen_addrs[1].addr, "::1");
	o->queued_listen_addrs[1].ਪੋਰਟ = -1;
	ਸੈੱਟ_string(&o->queued_listen_addrs[1].rdomain, "");

	o->ਅੰਕ_subsystems = 2;
	o->subsystem_name = new_string_array(o->ਅੰਕ_subsystems);
	o->subsystem_command = new_string_array(o->ਅੰਕ_subsystems);
	o->subsystem_ਦਲੀਲਾਂ = new_string_array(o->ਅੰਕ_subsystems);
	ਸੈੱਟ_string(&o->subsystem_name[0], "sftp");
	ਸੈੱਟ_string(&o->subsystem_command[0], "internal-sftp");
	ਸੈੱਟ_string(&o->subsystem_ਦਲੀਲਾਂ[0], "internal-sftp -f AUTH");
	ਸੈੱਟ_string(&o->subsystem_name[1], "echo");
	ਸੈੱਟ_string(&o->subsystem_command[1], "/bin/echo");
	ਸੈੱਟ_string(&o->subsystem_ਦਲੀਲਾਂ[1], "/bin/echo hello");
}

ਸਥਿਰ ਖਾਲੀ
check_roundtrip(ਅਚਲ ServerOptions *o)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ServerOptions ਬਾਹਰਲਾ;

	initialize_server_options(&ਬਾਹਰਲਾ);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ਨਿਰਾ);
	ASSERT_INT_EQ(deserialise_server_options(buf, &ਬਾਹਰਲਾ), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(buf), 0);

	ASSERT_U_INT_EQ(ਬਾਹਰਲਾ.ਅੰਕ_ports, 2);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.ports[0], 22);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.ports[1], 2022);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.ip_qos_interactive, 0x10);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.ip_qos_bulk, 0x08);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.log_facility, SYSLOG_FACILITY_AUTH);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.log_level, SYSLOG_LEVEL_DEBUG3);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.fwd_opts.gateway_ports, 1);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.fwd_opts.streamlocal_bind_ਨਕਾਬ, 0177);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.fwd_opts.streamlocal_bind_unlink, 1);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.permit_user_env, 1);
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.permit_user_env_allowlist, "");
	ASSERT_LONG_LONG_EQ(ਬਾਹਰਲਾ.rekey_ਹੱਦਬੰਦੀ, 123456789);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.rekey_interval, 600);
	ASSERT_U64_EQ(ਬਾਹਰਲਾ.timing_secret, 0x0102030405060708ULL);

	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.routing_domain, "");
	ASSERT_PTR_EQ(ਬਾਹਰਲਾ.banner, ਨਿਰਾ);
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.adm_forced_command, "internal-sftp");
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.chroot_directory, "");
	ASSERT_PTR_EQ(ਬਾਹਰਲਾ.host_ਕੁੰਜੀ_agent, ਨਿਰਾ);
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.authorized_ਕੁੰਜੀਆਂ_command, "/bin/echo");
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.authorized_ਕੁੰਜੀਆਂ_command_user, "");
	ASSERT_PTR_EQ(ਬਾਹਰਲਾ.authorized_principals_file, ਨਿਰਾ);

	ASSERT_U_INT_EQ(ਬਾਹਰਲਾ.ਅੰਕ_authkeys_files, 3);
	ASSERT_PTR_EQ(ਬਾਹਰਲਾ.authorized_ਕੁੰਜੀਆਂ_files[0], ਨਿਰਾ);
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.authorized_ਕੁੰਜੀਆਂ_files[1], "");
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.authorized_ਕੁੰਜੀਆਂ_files[2], ".ssh/authorized_keys");

	ASSERT_U_INT_EQ(ਬਾਹਰਲਾ.ਅੰਕ_log_verbose, 2);
	ASSERT_PTR_EQ(ਬਾਹਰਲਾ.log_verbose[0], ਨਿਰਾ);
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.log_verbose[1], "kex.c:*");

	ASSERT_U_INT_EQ(ਬਾਹਰਲਾ.ਅੰਕ_host_ਕੁੰਜੀ_files, 3);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.host_ਕੁੰਜੀ_file_userprovided[0], 0);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.host_ਕੁੰਜੀ_file_userprovided[1], 1);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.host_ਕੁੰਜੀ_file_userprovided[2], -1);
	ASSERT_PTR_EQ(ਬਾਹਰਲਾ.host_ਕੁੰਜੀ_files[0], ਨਿਰਾ);
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.host_ਕੁੰਜੀ_files[1], "");
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.host_ਕੁੰਜੀ_files[2], "/tmp/ssh_host_ed25519_key");

	ASSERT_U_INT_EQ(ਬਾਹਰਲਾ.ਅੰਕ_queued_listens, 2);
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.queued_listen_addrs[0].addr, "127.0.0.1");
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.queued_listen_addrs[0].ਪੋਰਟ, 2222);
	ASSERT_PTR_EQ(ਬਾਹਰਲਾ.queued_listen_addrs[0].rdomain, ਨਿਰਾ);
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.queued_listen_addrs[1].addr, "::1");
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.queued_listen_addrs[1].ਪੋਰਟ, -1);
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.queued_listen_addrs[1].rdomain, "");

	ASSERT_U_INT_EQ(ਬਾਹਰਲਾ.ਅੰਕ_subsystems, 2);
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.subsystem_name[0], "sftp");
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.subsystem_command[0], "internal-sftp");
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.subsystem_ਦਲੀਲਾਂ[0], "internal-sftp -f AUTH");
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.subsystem_name[1], "echo");
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.subsystem_command[1], "/bin/echo");
	ASSERT_STRING_EQ(ਬਾਹਰਲਾ.subsystem_ਦਲੀਲਾਂ[1], "/bin/echo hello");

	free_server_options(&ਬਾਹਰਲਾ);
	sshbuf_free(buf);
}

ਸਥਿਰ ਖਾਲੀ
check_rejects_trailing_ਅੰਕੜੇ(ਅਚਲ ServerOptions *o)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ServerOptions ਬਾਹਰਲਾ;
	ਪੂਰਨ r;

	initialize_server_options(&ਬਾਹਰਲਾ);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_u8(buf, 0), 0);
	r = deserialise_server_options(buf, &ਬਾਹਰਲਾ);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&ਬਾਹਰਲਾ);
	sshbuf_free(buf);
}

ਸਥਿਰ ਖਾਲੀ
check_rejects_bad_ਸੰਸਕਰਣ(ਅਚਲ ServerOptions *o)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ServerOptions ਬਾਹਰਲਾ;
	ਪੂਰਨ r;

	initialize_server_options(&ਬਾਹਰਲਾ);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ਨਿਰਾ);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), ਨਿਰਾ);
	POKE_U32(sshbuf_mutable_ptr(buf), 2);
	r = deserialise_server_options(buf, &ਬਾਹਰਲਾ);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&ਬਾਹਰਲਾ);
	sshbuf_free(buf);
}

ਸਥਿਰ ਖਾਲੀ
check_rejects_bad_ਪੋਰਟ_ਗਿਣਤੀ(ਅਚਲ ServerOptions *o)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ServerOptions ਬਾਹਰਲਾ;
	ਪੂਰਨ r;

	initialize_server_options(&ਬਾਹਰਲਾ);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ਨਿਰਾ);
	ASSERT_ਮਾਪ_T_GT(sshbuf_len(buf), 8);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), ਨਿਰਾ);
	POKE_U32(sshbuf_mutable_ptr(buf) + 4, MAX_PORTS + 1);
	r = deserialise_server_options(buf, &ਬਾਹਰਲਾ);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&ਬਾਹਰਲਾ);
	sshbuf_free(buf);
}

ਸਥਿਰ ਖਾਲੀ
check_roundtrip_signed_limits(ਅਚਲ ServerOptions *o)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ServerOptions ਬਾਹਰਲਾ, ਵਿੱਚ;

	initialize_server_options(&ਬਾਹਰਲਾ);
	ਵਿੱਚ = *o;
	ਵਿੱਚ.fwd_opts.streamlocal_bind_ਨਕਾਬ = (ਬਹੁਲਕ_t)-1;
	ਵਿੱਚ.ip_qos_bulk = INT_MIN;
	ਵਿੱਚ.rekey_ਹੱਦਬੰਦੀ = INT64_MIN;
	ASSERT_INT_EQ(serialise_server_options(&ਵਿੱਚ, &buf), 0);
	ASSERT_PTR_NE(buf, ਨਿਰਾ);
	ASSERT_INT_EQ(deserialise_server_options(buf, &ਬਾਹਰਲਾ), 0);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.fwd_opts.streamlocal_bind_ਨਕਾਬ == (ਬਹੁਲਕ_t)-1, 1);
	ASSERT_INT_EQ(ਬਾਹਰਲਾ.ip_qos_bulk, INT_MIN);
	ASSERT_LONG_LONG_EQ(ਬਾਹਰਲਾ.rekey_ਹੱਦਬੰਦੀ, INT64_MIN);
	free_server_options(&ਬਾਹਰਲਾ);
	sshbuf_free(buf);
}

ਸਥਿਰ ਖਾਲੀ
attempt_deserialise_blob(ਅਚਲ u_char *p, ਮਾਪ_t len)
{
	ਬਣਤਰ sshbuf *buf;
	ServerOptions ਬਾਹਰਲਾ;

	initialize_server_options(&ਬਾਹਰਲਾ);
	ASSERT_PTR_NE(buf = sshbuf_from(p, len), ਨਿਰਾ);
	(ਖਾਲੀ)deserialise_server_options(buf, &ਬਾਹਰਲਾ);
	free_server_options(&ਬਾਹਰਲਾ);
	sshbuf_free(buf);
}

ਸਥਿਰ ਖਾਲੀ
check_fuzz_deserialise(ਅਚਲ ServerOptions *o)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਬਣਤਰ fuzz *fuzz;
	u_int fuzzers = FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_ਸ਼ੁਰੂ | FUZZ_TRUNCATE_ਸਿਰਾ;

	ਜੇ (test_is_fast())
		fuzzers &= ~FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP;
	ਜੇ (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP;

	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ਨਿਰਾ);
	fuzz = fuzz_begin(fuzzers, sshbuf_ptr(buf), sshbuf_len(buf));
	TEST_ONERROR(onerror, fuzz);
	ਲਈ (; !fuzz_ਪੂਰਾ(fuzz); fuzz_ਅਗਲਾ(fuzz))
		attempt_deserialise_blob(fuzz_ptr(fuzz), fuzz_len(fuzz));
	TEST_ONERROR(ਨਿਰਾ, ਨਿਰਾ);
	fuzz_cleanup(fuzz);
	sshbuf_free(buf);
}

ਖਾਲੀ
tests(ਖਾਲੀ)
{
	ServerOptions o;

	log_init("test_servconf", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 1);

	TEST_ਸ਼ੁਰੂ("server options round trip preserves nullable state");
	ਸੈੱਟ_test_options(&o);
	check_roundtrip(&o);
	free_server_options(&o);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("server options reject trailing data");
	ਸੈੱਟ_test_options(&o);
	check_rejects_trailing_ਅੰਕੜੇ(&o);
	free_server_options(&o);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("server options reject unsupported version");
	ਸੈੱਟ_test_options(&o);
	check_rejects_bad_ਸੰਸਕਰਣ(&o);
	free_server_options(&o);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("server options reject bad port count");
	ਸੈੱਟ_test_options(&o);
	check_rejects_bad_ਪੋਰਟ_ਗਿਣਤੀ(&o);
	free_server_options(&o);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("server options round trip signed limits");
	ਸੈੱਟ_test_options(&o);
	check_roundtrip_signed_limits(&o);
	free_server_options(&o);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("server options deserialise fuzz");
	ਸੈੱਟ_test_options(&o);
	check_fuzz_deserialise(&o);
	free_server_options(&o);
	TEST_ਪੂਰਾ();
}

ਖਾਲੀ
benchmarks(ਖਾਲੀ)
{
	ਲਿਖੋ("no benchmarks\n");
}
