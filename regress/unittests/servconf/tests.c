/* 	$OpenBSD: tests.c,v 1.1 2026/05/31 11:39:44 djm Exp $ */
/*
 * Regress tests for servconf.h server configuration API
 *
 * Placed in the public domain
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "../test_helper/test_helper.h"

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "xmalloc.h"

কাঠামো sshbuf *cfg;

/* stub */
পূর্ণসংখ্যা auth2_methods_valid(ধ্রুবক অক্ষর *methods, পূর্ণসংখ্যা need_enable);
পূর্ণসংখ্যা
auth2_methods_valid(ধ্রুবক অক্ষর *methods, পূর্ণসংখ্যা need_enable)
{
	ফেরত 1;
}

স্থির শূন্য
onerror(শূন্য *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((কাঠামো fuzz *)fuzz);
}

স্থির শূন্য
set_string(অক্ষর **dst, ধ্রুবক অক্ষর *s)
{
	*dst = s == ফাঁকা ? ফাঁকা : xstrdup(s);
}

স্থির অক্ষর **
new_string_array(u_int n)
{
	ফেরত xcalloc(n, আকার(অক্ষর *));
}

স্থির শূন্য
set_test_options(ServerOptions *o)
{
	initialize_server_options(o);

	o->অঙ্ক_ports = 2;
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
	set_string(&o->banner, ফাঁকা);
	set_string(&o->adm_forced_command, "internal-sftp");
	set_string(&o->chroot_directory, "");
	set_string(&o->host_চাবি_agent, ফাঁকা);
	set_string(&o->authorized_চাবিগুলি_command, "/bin/echo");
	set_string(&o->authorized_চাবিগুলি_command_user, "");
	set_string(&o->authorized_principals_file, ফাঁকা);

	o->অঙ্ক_authkeys_files = 3;
	o->authorized_চাবিগুলি_files = new_string_array(o->অঙ্ক_authkeys_files);
	set_string(&o->authorized_চাবিগুলি_files[0], ফাঁকা);
	set_string(&o->authorized_চাবিগুলি_files[1], "");
	set_string(&o->authorized_চাবিগুলি_files[2], ".ssh/authorized_keys");

	o->অঙ্ক_log_verbose = 2;
	o->log_verbose = new_string_array(o->অঙ্ক_log_verbose);
	set_string(&o->log_verbose[0], ফাঁকা);
	set_string(&o->log_verbose[1], "kex.c:*");

	o->অঙ্ক_host_চাবি_files = 3;
	o->host_চাবি_file_userprovided =
	    xcalloc(o->অঙ্ক_host_চাবি_files,
	    আকার(*o->host_চাবি_file_userprovided));
	o->host_চাবি_files = new_string_array(o->অঙ্ক_host_চাবি_files);
	o->host_চাবি_file_userprovided[0] = 0;
	o->host_চাবি_file_userprovided[1] = 1;
	o->host_চাবি_file_userprovided[2] = -1;
	set_string(&o->host_চাবি_files[0], ফাঁকা);
	set_string(&o->host_চাবি_files[1], "");
	set_string(&o->host_চাবি_files[2], "/tmp/ssh_host_ed25519_key");

	o->অঙ্ক_queued_listens = 2;
	o->queued_listen_addrs = xcalloc(o->অঙ্ক_queued_listens,
	    আকার(*o->queued_listen_addrs));
	set_string(&o->queued_listen_addrs[0].addr, "127.0.0.1");
	o->queued_listen_addrs[0].port = 2222;
	set_string(&o->queued_listen_addrs[0].rdomain, ফাঁকা);
	set_string(&o->queued_listen_addrs[1].addr, "::1");
	o->queued_listen_addrs[1].port = -1;
	set_string(&o->queued_listen_addrs[1].rdomain, "");

	o->অঙ্ক_subsystems = 2;
	o->subsystem_name = new_string_array(o->অঙ্ক_subsystems);
	o->subsystem_command = new_string_array(o->অঙ্ক_subsystems);
	o->subsystem_args = new_string_array(o->অঙ্ক_subsystems);
	set_string(&o->subsystem_name[0], "sftp");
	set_string(&o->subsystem_command[0], "internal-sftp");
	set_string(&o->subsystem_args[0], "internal-sftp -f AUTH");
	set_string(&o->subsystem_name[1], "echo");
	set_string(&o->subsystem_command[1], "/bin/echo");
	set_string(&o->subsystem_args[1], "/bin/echo hello");
}

স্থির শূন্য
check_roundtrip(ধ্রুবক ServerOptions *o)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	ServerOptions out;

	initialize_server_options(&out);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ফাঁকা);
	ASSERT_INT_EQ(deserialise_server_options(buf, &out), 0);
	ASSERT_আকার_T_EQ(sshbuf_len(buf), 0);

	ASSERT_U_INT_EQ(out.অঙ্ক_ports, 2);
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
	ASSERT_PTR_EQ(out.banner, ফাঁকা);
	ASSERT_STRING_EQ(out.adm_forced_command, "internal-sftp");
	ASSERT_STRING_EQ(out.chroot_directory, "");
	ASSERT_PTR_EQ(out.host_চাবি_agent, ফাঁকা);
	ASSERT_STRING_EQ(out.authorized_চাবিগুলি_command, "/bin/echo");
	ASSERT_STRING_EQ(out.authorized_চাবিগুলি_command_user, "");
	ASSERT_PTR_EQ(out.authorized_principals_file, ফাঁকা);

	ASSERT_U_INT_EQ(out.অঙ্ক_authkeys_files, 3);
	ASSERT_PTR_EQ(out.authorized_চাবিগুলি_files[0], ফাঁকা);
	ASSERT_STRING_EQ(out.authorized_চাবিগুলি_files[1], "");
	ASSERT_STRING_EQ(out.authorized_চাবিগুলি_files[2], ".ssh/authorized_keys");

	ASSERT_U_INT_EQ(out.অঙ্ক_log_verbose, 2);
	ASSERT_PTR_EQ(out.log_verbose[0], ফাঁকা);
	ASSERT_STRING_EQ(out.log_verbose[1], "kex.c:*");

	ASSERT_U_INT_EQ(out.অঙ্ক_host_চাবি_files, 3);
	ASSERT_INT_EQ(out.host_চাবি_file_userprovided[0], 0);
	ASSERT_INT_EQ(out.host_চাবি_file_userprovided[1], 1);
	ASSERT_INT_EQ(out.host_চাবি_file_userprovided[2], -1);
	ASSERT_PTR_EQ(out.host_চাবি_files[0], ফাঁকা);
	ASSERT_STRING_EQ(out.host_চাবি_files[1], "");
	ASSERT_STRING_EQ(out.host_চাবি_files[2], "/tmp/ssh_host_ed25519_key");

	ASSERT_U_INT_EQ(out.অঙ্ক_queued_listens, 2);
	ASSERT_STRING_EQ(out.queued_listen_addrs[0].addr, "127.0.0.1");
	ASSERT_INT_EQ(out.queued_listen_addrs[0].port, 2222);
	ASSERT_PTR_EQ(out.queued_listen_addrs[0].rdomain, ফাঁকা);
	ASSERT_STRING_EQ(out.queued_listen_addrs[1].addr, "::1");
	ASSERT_INT_EQ(out.queued_listen_addrs[1].port, -1);
	ASSERT_STRING_EQ(out.queued_listen_addrs[1].rdomain, "");

	ASSERT_U_INT_EQ(out.অঙ্ক_subsystems, 2);
	ASSERT_STRING_EQ(out.subsystem_name[0], "sftp");
	ASSERT_STRING_EQ(out.subsystem_command[0], "internal-sftp");
	ASSERT_STRING_EQ(out.subsystem_args[0], "internal-sftp -f AUTH");
	ASSERT_STRING_EQ(out.subsystem_name[1], "echo");
	ASSERT_STRING_EQ(out.subsystem_command[1], "/bin/echo");
	ASSERT_STRING_EQ(out.subsystem_args[1], "/bin/echo hello");

	free_server_options(&out);
	sshbuf_free(buf);
}

স্থির শূন্য
check_rejects_trailing_তথ্য(ধ্রুবক ServerOptions *o)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	ServerOptions out;
	পূর্ণসংখ্যা r;

	initialize_server_options(&out);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ফাঁকা);
	ASSERT_INT_EQ(sshbuf_put_u8(buf, 0), 0);
	r = deserialise_server_options(buf, &out);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&out);
	sshbuf_free(buf);
}

স্থির শূন্য
check_rejects_bad_version(ধ্রুবক ServerOptions *o)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	ServerOptions out;
	পূর্ণসংখ্যা r;

	initialize_server_options(&out);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ফাঁকা);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), ফাঁকা);
	POKE_U32(sshbuf_mutable_ptr(buf), 2);
	r = deserialise_server_options(buf, &out);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&out);
	sshbuf_free(buf);
}

স্থির শূন্য
check_rejects_bad_port_গুনতি(ধ্রুবক ServerOptions *o)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	ServerOptions out;
	পূর্ণসংখ্যা r;

	initialize_server_options(&out);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ফাঁকা);
	ASSERT_আকার_T_GT(sshbuf_len(buf), 8);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), ফাঁকা);
	POKE_U32(sshbuf_mutable_ptr(buf) + 4, MAX_PORTS + 1);
	r = deserialise_server_options(buf, &out);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&out);
	sshbuf_free(buf);
}

স্থির শূন্য
check_roundtrip_signed_limits(ধ্রুবক ServerOptions *o)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	ServerOptions out, in;

	initialize_server_options(&out);
	in = *o;
	in.fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	in.ip_qos_bulk = INT_MIN;
	in.rekey_limit = INT64_MIN;
	ASSERT_INT_EQ(serialise_server_options(&in, &buf), 0);
	ASSERT_PTR_NE(buf, ফাঁকা);
	ASSERT_INT_EQ(deserialise_server_options(buf, &out), 0);
	ASSERT_INT_EQ(out.fwd_opts.streamlocal_bind_mask == (mode_t)-1, 1);
	ASSERT_INT_EQ(out.ip_qos_bulk, INT_MIN);
	ASSERT_LONG_LONG_EQ(out.rekey_limit, INT64_MIN);
	free_server_options(&out);
	sshbuf_free(buf);
}

স্থির শূন্য
attempt_deserialise_blob(ধ্রুবক u_char *p, আকার_t len)
{
	কাঠামো sshbuf *buf;
	ServerOptions out;

	initialize_server_options(&out);
	ASSERT_PTR_NE(buf = sshbuf_from(p, len), ফাঁকা);
	(শূন্য)deserialise_server_options(buf, &out);
	free_server_options(&out);
	sshbuf_free(buf);
}

স্থির শূন্য
check_fuzz_deserialise(ধ্রুবক ServerOptions *o)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	কাঠামো fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	যদি (test_is_fast())
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	যদি (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP;

	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ফাঁকা);
	fuzz = fuzz_begin(fuzzers, sshbuf_ptr(buf), sshbuf_len(buf));
	TEST_ONERROR(onerror, fuzz);
	জন্য (; !fuzz_done(fuzz); fuzz_পরবর্তী(fuzz))
		attempt_deserialise_blob(fuzz_ptr(fuzz), fuzz_len(fuzz));
	TEST_ONERROR(ফাঁকা, ফাঁকা);
	fuzz_cleanup(fuzz);
	sshbuf_free(buf);
}

শূন্য
tests(শূন্য)
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
	check_rejects_trailing_তথ্য(&o);
	free_server_options(&o);
	TEST_DONE();

	TEST_START("server options reject unsupported version");
	set_test_options(&o);
	check_rejects_bad_version(&o);
	free_server_options(&o);
	TEST_DONE();

	TEST_START("server options reject bad port count");
	set_test_options(&o);
	check_rejects_bad_port_গুনতি(&o);
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

শূন্য
benchmarks(শূন্য)
{
	printf("no benchmarks\n");
}
