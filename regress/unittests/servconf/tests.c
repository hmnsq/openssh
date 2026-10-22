/* 	$OpenBSD: tests.c,v 1.1 2026/05/31 11:39:44 djm Exp $ */
/*
 * Regress tests for servconf.h server configuration API
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "xmalloc.h"

ഘടന sshbuf *cfg;

/* stub */
പൂർണ്ണസംഖ്യ auth2_methods_valid(സ്ഥിരം അക്ഷരം *methods, പൂർണ്ണസംഖ്യ need_enable);
പൂർണ്ണസംഖ്യ
auth2_methods_valid(സ്ഥിരം അക്ഷരം *methods, പൂർണ്ണസംഖ്യ need_enable)
{
	തിരികെ 1;
}

സ്ഥിതം ശൂന്യം
onerror(ശൂന്യം *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((ഘടന fuzz *)fuzz);
}

സ്ഥിതം ശൂന്യം
set_string(അക്ഷരം **dst, സ്ഥിരം അക്ഷരം *s)
{
	*dst = s == ശൂന്യ ? ശൂന്യ : xstrdup(s);
}

സ്ഥിതം അക്ഷരം **
new_string_array(u_int n)
{
	തിരികെ xcalloc(n, വലുപ്പം(അക്ഷരം *));
}

സ്ഥിതം ശൂന്യം
set_test_options(ServerOptions *o)
{
	initialize_server_options(o);

	o->അക്കം_ports = 2;
	o->ports[0] = 22;
	o->ports[1] = 2022;
	o->ip_qos_interactive = 0x10;
	o->ip_qos_bulk = 0x08;
	o->log_facility = SYSLOG_FACILITY_AUTH;
	o->log_level = SYSLOG_LEVEL_DEBUG3;
	o->fwd_opts.gateway_ports = 1;
	o->fwd_opts.streamlocal_bind_mask = 0177;
	o->fwd_opts.streamlocal_bind_unlink = 1;
	o->permit_user_env = 1;
	set_string(&o->permit_user_env_allowlist, "");
	o->rekey_limit = 123456789;
	o->rekey_interval = 600;
	o->timing_secret = 0x0102030405060708ULL;

	set_string(&o->routing_domain, "");
	set_string(&o->banner, ശൂന്യ);
	set_string(&o->adm_forced_command, "internal-sftp");
	set_string(&o->chroot_directory, "");
	set_string(&o->host_താക്കോൽ_agent, ശൂന്യ);
	set_string(&o->authorized_താക്കോലുകൾ_command, "/bin/echo");
	set_string(&o->authorized_താക്കോലുകൾ_command_user, "");
	set_string(&o->authorized_principals_file, ശൂന്യ);

	o->അക്കം_authkeys_files = 3;
	o->authorized_താക്കോലുകൾ_files = new_string_array(o->അക്കം_authkeys_files);
	set_string(&o->authorized_താക്കോലുകൾ_files[0], ശൂന്യ);
	set_string(&o->authorized_താക്കോലുകൾ_files[1], "");
	set_string(&o->authorized_താക്കോലുകൾ_files[2], ".ssh/authorized_keys");

	o->അക്കം_log_verbose = 2;
	o->log_verbose = new_string_array(o->അക്കം_log_verbose);
	set_string(&o->log_verbose[0], ശൂന്യ);
	set_string(&o->log_verbose[1], "kex.c:*");

	o->അക്കം_host_താക്കോൽ_files = 3;
	o->host_താക്കോൽ_file_userprovided =
	    xcalloc(o->അക്കം_host_താക്കോൽ_files,
	    വലുപ്പം(*o->host_താക്കോൽ_file_userprovided));
	o->host_താക്കോൽ_files = new_string_array(o->അക്കം_host_താക്കോൽ_files);
	o->host_താക്കോൽ_file_userprovided[0] = 0;
	o->host_താക്കോൽ_file_userprovided[1] = 1;
	o->host_താക്കോൽ_file_userprovided[2] = -1;
	set_string(&o->host_താക്കോൽ_files[0], ശൂന്യ);
	set_string(&o->host_താക്കോൽ_files[1], "");
	set_string(&o->host_താക്കോൽ_files[2], "/tmp/ssh_host_ed25519_key");

	o->അക്കം_queued_listens = 2;
	o->queued_listen_addrs = xcalloc(o->അക്കം_queued_listens,
	    വലുപ്പം(*o->queued_listen_addrs));
	set_string(&o->queued_listen_addrs[0].addr, "127.0.0.1");
	o->queued_listen_addrs[0].port = 2222;
	set_string(&o->queued_listen_addrs[0].rdomain, ശൂന്യ);
	set_string(&o->queued_listen_addrs[1].addr, "::1");
	o->queued_listen_addrs[1].port = -1;
	set_string(&o->queued_listen_addrs[1].rdomain, "");

	o->അക്കം_subsystems = 2;
	o->subsystem_name = new_string_array(o->അക്കം_subsystems);
	o->subsystem_command = new_string_array(o->അക്കം_subsystems);
	o->subsystem_args = new_string_array(o->അക്കം_subsystems);
	set_string(&o->subsystem_name[0], "sftp");
	set_string(&o->subsystem_command[0], "internal-sftp");
	set_string(&o->subsystem_args[0], "internal-sftp -f AUTH");
	set_string(&o->subsystem_name[1], "echo");
	set_string(&o->subsystem_command[1], "/bin/echo");
	set_string(&o->subsystem_args[1], "/bin/echo hello");
}

സ്ഥിതം ശൂന്യം
check_roundtrip(സ്ഥിരം ServerOptions *o)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	ServerOptions out;

	initialize_server_options(&out);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ശൂന്യ);
	ASSERT_INT_EQ(deserialise_server_options(buf, &out), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(buf), 0);

	ASSERT_U_INT_EQ(out.അക്കം_ports, 2);
	ASSERT_INT_EQ(out.ports[0], 22);
	ASSERT_INT_EQ(out.ports[1], 2022);
	ASSERT_INT_EQ(out.ip_qos_interactive, 0x10);
	ASSERT_INT_EQ(out.ip_qos_bulk, 0x08);
	ASSERT_INT_EQ(out.log_facility, SYSLOG_FACILITY_AUTH);
	ASSERT_INT_EQ(out.log_level, SYSLOG_LEVEL_DEBUG3);
	ASSERT_INT_EQ(out.fwd_opts.gateway_ports, 1);
	ASSERT_INT_EQ(out.fwd_opts.streamlocal_bind_mask, 0177);
	ASSERT_INT_EQ(out.fwd_opts.streamlocal_bind_unlink, 1);
	ASSERT_INT_EQ(out.permit_user_env, 1);
	ASSERT_STRING_EQ(out.permit_user_env_allowlist, "");
	ASSERT_LONG_LONG_EQ(out.rekey_limit, 123456789);
	ASSERT_INT_EQ(out.rekey_interval, 600);
	ASSERT_U64_EQ(out.timing_secret, 0x0102030405060708ULL);

	ASSERT_STRING_EQ(out.routing_domain, "");
	ASSERT_PTR_EQ(out.banner, ശൂന്യ);
	ASSERT_STRING_EQ(out.adm_forced_command, "internal-sftp");
	ASSERT_STRING_EQ(out.chroot_directory, "");
	ASSERT_PTR_EQ(out.host_താക്കോൽ_agent, ശൂന്യ);
	ASSERT_STRING_EQ(out.authorized_താക്കോലുകൾ_command, "/bin/echo");
	ASSERT_STRING_EQ(out.authorized_താക്കോലുകൾ_command_user, "");
	ASSERT_PTR_EQ(out.authorized_principals_file, ശൂന്യ);

	ASSERT_U_INT_EQ(out.അക്കം_authkeys_files, 3);
	ASSERT_PTR_EQ(out.authorized_താക്കോലുകൾ_files[0], ശൂന്യ);
	ASSERT_STRING_EQ(out.authorized_താക്കോലുകൾ_files[1], "");
	ASSERT_STRING_EQ(out.authorized_താക്കോലുകൾ_files[2], ".ssh/authorized_keys");

	ASSERT_U_INT_EQ(out.അക്കം_log_verbose, 2);
	ASSERT_PTR_EQ(out.log_verbose[0], ശൂന്യ);
	ASSERT_STRING_EQ(out.log_verbose[1], "kex.c:*");

	ASSERT_U_INT_EQ(out.അക്കം_host_താക്കോൽ_files, 3);
	ASSERT_INT_EQ(out.host_താക്കോൽ_file_userprovided[0], 0);
	ASSERT_INT_EQ(out.host_താക്കോൽ_file_userprovided[1], 1);
	ASSERT_INT_EQ(out.host_താക്കോൽ_file_userprovided[2], -1);
	ASSERT_PTR_EQ(out.host_താക്കോൽ_files[0], ശൂന്യ);
	ASSERT_STRING_EQ(out.host_താക്കോൽ_files[1], "");
	ASSERT_STRING_EQ(out.host_താക്കോൽ_files[2], "/tmp/ssh_host_ed25519_key");

	ASSERT_U_INT_EQ(out.അക്കം_queued_listens, 2);
	ASSERT_STRING_EQ(out.queued_listen_addrs[0].addr, "127.0.0.1");
	ASSERT_INT_EQ(out.queued_listen_addrs[0].port, 2222);
	ASSERT_PTR_EQ(out.queued_listen_addrs[0].rdomain, ശൂന്യ);
	ASSERT_STRING_EQ(out.queued_listen_addrs[1].addr, "::1");
	ASSERT_INT_EQ(out.queued_listen_addrs[1].port, -1);
	ASSERT_STRING_EQ(out.queued_listen_addrs[1].rdomain, "");

	ASSERT_U_INT_EQ(out.അക്കം_subsystems, 2);
	ASSERT_STRING_EQ(out.subsystem_name[0], "sftp");
	ASSERT_STRING_EQ(out.subsystem_command[0], "internal-sftp");
	ASSERT_STRING_EQ(out.subsystem_args[0], "internal-sftp -f AUTH");
	ASSERT_STRING_EQ(out.subsystem_name[1], "echo");
	ASSERT_STRING_EQ(out.subsystem_command[1], "/bin/echo");
	ASSERT_STRING_EQ(out.subsystem_args[1], "/bin/echo hello");

	free_server_options(&out);
	sshbuf_free(buf);
}

സ്ഥിതം ശൂന്യം
check_rejects_trailing_data(സ്ഥിരം ServerOptions *o)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	ServerOptions out;
	പൂർണ്ണസംഖ്യ r;

	initialize_server_options(&out);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ശൂന്യ);
	ASSERT_INT_EQ(sshbuf_put_u8(buf, 0), 0);
	r = deserialise_server_options(buf, &out);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&out);
	sshbuf_free(buf);
}

സ്ഥിതം ശൂന്യം
check_rejects_bad_version(സ്ഥിരം ServerOptions *o)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	ServerOptions out;
	പൂർണ്ണസംഖ്യ r;

	initialize_server_options(&out);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ശൂന്യ);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), ശൂന്യ);
	POKE_U32(sshbuf_mutable_ptr(buf), 2);
	r = deserialise_server_options(buf, &out);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&out);
	sshbuf_free(buf);
}

സ്ഥിതം ശൂന്യം
check_rejects_bad_port_എണ്ണം(സ്ഥിരം ServerOptions *o)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	ServerOptions out;
	പൂർണ്ണസംഖ്യ r;

	initialize_server_options(&out);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ശൂന്യ);
	ASSERT_SIZE_T_GT(sshbuf_len(buf), 8);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), ശൂന്യ);
	POKE_U32(sshbuf_mutable_ptr(buf) + 4, MAX_PORTS + 1);
	r = deserialise_server_options(buf, &out);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&out);
	sshbuf_free(buf);
}

സ്ഥിതം ശൂന്യം
check_roundtrip_signed_limits(സ്ഥിരം ServerOptions *o)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	ServerOptions out, in;

	initialize_server_options(&out);
	in = *o;
	in.fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	in.ip_qos_bulk = INT_MIN;
	in.rekey_limit = INT64_MIN;
	ASSERT_INT_EQ(serialise_server_options(&in, &buf), 0);
	ASSERT_PTR_NE(buf, ശൂന്യ);
	ASSERT_INT_EQ(deserialise_server_options(buf, &out), 0);
	ASSERT_INT_EQ(out.fwd_opts.streamlocal_bind_mask == (mode_t)-1, 1);
	ASSERT_INT_EQ(out.ip_qos_bulk, INT_MIN);
	ASSERT_LONG_LONG_EQ(out.rekey_limit, INT64_MIN);
	free_server_options(&out);
	sshbuf_free(buf);
}

സ്ഥിതം ശൂന്യം
attempt_deserialise_blob(സ്ഥിരം u_char *p, size_t len)
{
	ഘടന sshbuf *buf;
	ServerOptions out;

	initialize_server_options(&out);
	ASSERT_PTR_NE(buf = sshbuf_from(p, len), ശൂന്യ);
	(ശൂന്യം)deserialise_server_options(buf, &out);
	free_server_options(&out);
	sshbuf_free(buf);
}

സ്ഥിതം ശൂന്യം
check_fuzz_deserialise(സ്ഥിരം ServerOptions *o)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	ഘടന fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	എങ്കിൽ (test_is_fast())
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	എങ്കിൽ (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP;

	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ശൂന്യ);
	fuzz = fuzz_begin(fuzzers, sshbuf_ptr(buf), sshbuf_len(buf));
	TEST_ONERROR(onerror, fuzz);
	വേണ്ടി (; !fuzz_done(fuzz); fuzz_next(fuzz))
		attempt_deserialise_blob(fuzz_ptr(fuzz), fuzz_len(fuzz));
	TEST_ONERROR(ശൂന്യ, ശൂന്യ);
	fuzz_cleanup(fuzz);
	sshbuf_free(buf);
}

ശൂന്യം
tests(ശൂന്യം)
{
	ServerOptions o;

	log_init("test_servconf", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 1);

	TEST_START("server options round trip preserves nullable state");
	set_test_options(&o);
	check_roundtrip(&o);
	free_server_options(&o);
	TEST_DONE();

	TEST_START("server options reject trailing data");
	set_test_options(&o);
	check_rejects_trailing_data(&o);
	free_server_options(&o);
	TEST_DONE();

	TEST_START("server options reject unsupported version");
	set_test_options(&o);
	check_rejects_bad_version(&o);
	free_server_options(&o);
	TEST_DONE();

	TEST_START("server options reject bad port count");
	set_test_options(&o);
	check_rejects_bad_port_എണ്ണം(&o);
	free_server_options(&o);
	TEST_DONE();

	TEST_START("server options round trip signed limits");
	set_test_options(&o);
	check_roundtrip_signed_limits(&o);
	free_server_options(&o);
	TEST_DONE();

	TEST_START("server options deserialise fuzz");
	set_test_options(&o);
	check_fuzz_deserialise(&o);
	free_server_options(&o);
	TEST_DONE();
}

ശൂന്യം
benchmarks(ശൂന്യം)
{
	printf("no benchmarks\n");
}
