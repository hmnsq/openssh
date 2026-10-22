/* 	$OpenBSD: tests.c,v 1.1 2026/05/31 11:39:44 djm Exp $ */
/*
 * Regress tests for servconf.h server configuration API
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <limits.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"

#ضمن "log.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "xmalloc.h"

بنية sshbuf *cfg;

/* stub */
صحيح auth2_methods_valid(ثابت حرف *methods, صحيح need_enable);
صحيح
auth2_methods_valid(ثابت حرف *methods, صحيح need_enable)
{
	أرجع 1;
}

ساكن فراغ
onerror(فراغ *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((بنية fuzz *)fuzz);
}

ساكن فراغ
سيٽ_string(حرف **dst, ثابت حرف *s)
{
	*dst = s == عدم ? عدم : xstrdup(s);
}

ساكن حرف **
new_string_array(u_int n)
{
	أرجع xcalloc(n, حجم(حرف *));
}

ساكن فراغ
سيٽ_test_options(ServerOptions *o)
{
	initialize_server_options(o);

	o->انگ_ports = 2;
	o->ports[0] = 22;
	o->ports[1] = 2022;
	o->ip_qos_interactive = 0x10;
	o->ip_qos_bulk = 0x08;
	o->log_facility = SYSLOG_FACILITY_AUTH;
	o->log_level = SYSLOG_LEVEL_DEBUG3;
	o->fwd_opts.gateway_ports = 1;
	o->fwd_opts.streamlocal_bind_نقاب = 0177;
	o->fwd_opts.streamlocal_bind_unlink = 1;
	o->permit_user_env = 1;
	سيٽ_string(&o->permit_user_env_allowlist, "");
	o->rekey_حد_بندي = 123456789;
	o->rekey_interval = 600;
	o->timing_secret = 0x0102030405060708ULL;

	سيٽ_string(&o->routing_domain, "");
	سيٽ_string(&o->banner, عدم);
	سيٽ_string(&o->adm_forced_command, "internal-sftp");
	سيٽ_string(&o->chroot_directory, "");
	سيٽ_string(&o->host_ڪنجي_agent, عدم);
	سيٽ_string(&o->authorized_ڪنجيون_command, "/bin/echo");
	سيٽ_string(&o->authorized_ڪنجيون_command_user, "");
	سيٽ_string(&o->authorized_principals_file, عدم);

	o->انگ_authkeys_files = 3;
	o->authorized_ڪنجيون_files = new_string_array(o->انگ_authkeys_files);
	سيٽ_string(&o->authorized_ڪنجيون_files[0], عدم);
	سيٽ_string(&o->authorized_ڪنجيون_files[1], "");
	سيٽ_string(&o->authorized_ڪنجيون_files[2], ".ssh/authorized_keys");

	o->انگ_log_verbose = 2;
	o->log_verbose = new_string_array(o->انگ_log_verbose);
	سيٽ_string(&o->log_verbose[0], عدم);
	سيٽ_string(&o->log_verbose[1], "kex.c:*");

	o->انگ_host_ڪنجي_files = 3;
	o->host_ڪنجي_file_userprovided =
	    xcalloc(o->انگ_host_ڪنجي_files,
	    حجم(*o->host_ڪنجي_file_userprovided));
	o->host_ڪنجي_files = new_string_array(o->انگ_host_ڪنجي_files);
	o->host_ڪنجي_file_userprovided[0] = 0;
	o->host_ڪنجي_file_userprovided[1] = 1;
	o->host_ڪنجي_file_userprovided[2] = -1;
	سيٽ_string(&o->host_ڪنجي_files[0], عدم);
	سيٽ_string(&o->host_ڪنجي_files[1], "");
	سيٽ_string(&o->host_ڪنجي_files[2], "/tmp/ssh_host_ed25519_key");

	o->انگ_queued_listens = 2;
	o->queued_listen_addrs = xcalloc(o->انگ_queued_listens,
	    حجم(*o->queued_listen_addrs));
	سيٽ_string(&o->queued_listen_addrs[0].addr, "127.0.0.1");
	o->queued_listen_addrs[0].پورٽ = 2222;
	سيٽ_string(&o->queued_listen_addrs[0].rdomain, عدم);
	سيٽ_string(&o->queued_listen_addrs[1].addr, "::1");
	o->queued_listen_addrs[1].پورٽ = -1;
	سيٽ_string(&o->queued_listen_addrs[1].rdomain, "");

	o->انگ_subsystems = 2;
	o->subsystem_name = new_string_array(o->انگ_subsystems);
	o->subsystem_command = new_string_array(o->انگ_subsystems);
	o->subsystem_دليلون = new_string_array(o->انگ_subsystems);
	سيٽ_string(&o->subsystem_name[0], "sftp");
	سيٽ_string(&o->subsystem_command[0], "internal-sftp");
	سيٽ_string(&o->subsystem_دليلون[0], "internal-sftp -f AUTH");
	سيٽ_string(&o->subsystem_name[1], "echo");
	سيٽ_string(&o->subsystem_command[1], "/bin/echo");
	سيٽ_string(&o->subsystem_دليلون[1], "/bin/echo hello");
}

ساكن فراغ
check_roundtrip(ثابت ServerOptions *o)
{
	بنية sshbuf *buf = عدم;
	ServerOptions ٻاهريون;

	initialize_server_options(&ٻاهريون);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, عدم);
	ASSERT_INT_EQ(deserialise_server_options(buf, &ٻاهريون), 0);
	ASSERT_سائيز_T_EQ(sshbuf_len(buf), 0);

	ASSERT_U_INT_EQ(ٻاهريون.انگ_ports, 2);
	ASSERT_INT_EQ(ٻاهريون.ports[0], 22);
	ASSERT_INT_EQ(ٻاهريون.ports[1], 2022);
	ASSERT_INT_EQ(ٻاهريون.ip_qos_interactive, 0x10);
	ASSERT_INT_EQ(ٻاهريون.ip_qos_bulk, 0x08);
	ASSERT_INT_EQ(ٻاهريون.log_facility, SYSLOG_FACILITY_AUTH);
	ASSERT_INT_EQ(ٻاهريون.log_level, SYSLOG_LEVEL_DEBUG3);
	ASSERT_INT_EQ(ٻاهريون.fwd_opts.gateway_ports, 1);
	ASSERT_INT_EQ(ٻاهريون.fwd_opts.streamlocal_bind_نقاب, 0177);
	ASSERT_INT_EQ(ٻاهريون.fwd_opts.streamlocal_bind_unlink, 1);
	ASSERT_INT_EQ(ٻاهريون.permit_user_env, 1);
	ASSERT_STRING_EQ(ٻاهريون.permit_user_env_allowlist, "");
	ASSERT_LONG_LONG_EQ(ٻاهريون.rekey_حد_بندي, 123456789);
	ASSERT_INT_EQ(ٻاهريون.rekey_interval, 600);
	ASSERT_U64_EQ(ٻاهريون.timing_secret, 0x0102030405060708ULL);

	ASSERT_STRING_EQ(ٻاهريون.routing_domain, "");
	ASSERT_PTR_EQ(ٻاهريون.banner, عدم);
	ASSERT_STRING_EQ(ٻاهريون.adm_forced_command, "internal-sftp");
	ASSERT_STRING_EQ(ٻاهريون.chroot_directory, "");
	ASSERT_PTR_EQ(ٻاهريون.host_ڪنجي_agent, عدم);
	ASSERT_STRING_EQ(ٻاهريون.authorized_ڪنجيون_command, "/bin/echo");
	ASSERT_STRING_EQ(ٻاهريون.authorized_ڪنجيون_command_user, "");
	ASSERT_PTR_EQ(ٻاهريون.authorized_principals_file, عدم);

	ASSERT_U_INT_EQ(ٻاهريون.انگ_authkeys_files, 3);
	ASSERT_PTR_EQ(ٻاهريون.authorized_ڪنجيون_files[0], عدم);
	ASSERT_STRING_EQ(ٻاهريون.authorized_ڪنجيون_files[1], "");
	ASSERT_STRING_EQ(ٻاهريون.authorized_ڪنجيون_files[2], ".ssh/authorized_keys");

	ASSERT_U_INT_EQ(ٻاهريون.انگ_log_verbose, 2);
	ASSERT_PTR_EQ(ٻاهريون.log_verbose[0], عدم);
	ASSERT_STRING_EQ(ٻاهريون.log_verbose[1], "kex.c:*");

	ASSERT_U_INT_EQ(ٻاهريون.انگ_host_ڪنجي_files, 3);
	ASSERT_INT_EQ(ٻاهريون.host_ڪنجي_file_userprovided[0], 0);
	ASSERT_INT_EQ(ٻاهريون.host_ڪنجي_file_userprovided[1], 1);
	ASSERT_INT_EQ(ٻاهريون.host_ڪنجي_file_userprovided[2], -1);
	ASSERT_PTR_EQ(ٻاهريون.host_ڪنجي_files[0], عدم);
	ASSERT_STRING_EQ(ٻاهريون.host_ڪنجي_files[1], "");
	ASSERT_STRING_EQ(ٻاهريون.host_ڪنجي_files[2], "/tmp/ssh_host_ed25519_key");

	ASSERT_U_INT_EQ(ٻاهريون.انگ_queued_listens, 2);
	ASSERT_STRING_EQ(ٻاهريون.queued_listen_addrs[0].addr, "127.0.0.1");
	ASSERT_INT_EQ(ٻاهريون.queued_listen_addrs[0].پورٽ, 2222);
	ASSERT_PTR_EQ(ٻاهريون.queued_listen_addrs[0].rdomain, عدم);
	ASSERT_STRING_EQ(ٻاهريون.queued_listen_addrs[1].addr, "::1");
	ASSERT_INT_EQ(ٻاهريون.queued_listen_addrs[1].پورٽ, -1);
	ASSERT_STRING_EQ(ٻاهريون.queued_listen_addrs[1].rdomain, "");

	ASSERT_U_INT_EQ(ٻاهريون.انگ_subsystems, 2);
	ASSERT_STRING_EQ(ٻاهريون.subsystem_name[0], "sftp");
	ASSERT_STRING_EQ(ٻاهريون.subsystem_command[0], "internal-sftp");
	ASSERT_STRING_EQ(ٻاهريون.subsystem_دليلون[0], "internal-sftp -f AUTH");
	ASSERT_STRING_EQ(ٻاهريون.subsystem_name[1], "echo");
	ASSERT_STRING_EQ(ٻاهريون.subsystem_command[1], "/bin/echo");
	ASSERT_STRING_EQ(ٻاهريون.subsystem_دليلون[1], "/bin/echo hello");

	free_server_options(&ٻاهريون);
	sshbuf_free(buf);
}

ساكن فراغ
check_rejects_trailing_معلومات(ثابت ServerOptions *o)
{
	بنية sshbuf *buf = عدم;
	ServerOptions ٻاهريون;
	صحيح r;

	initialize_server_options(&ٻاهريون);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, عدم);
	ASSERT_INT_EQ(sshbuf_put_u8(buf, 0), 0);
	r = deserialise_server_options(buf, &ٻاهريون);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&ٻاهريون);
	sshbuf_free(buf);
}

ساكن فراغ
check_rejects_bad_نسخو(ثابت ServerOptions *o)
{
	بنية sshbuf *buf = عدم;
	ServerOptions ٻاهريون;
	صحيح r;

	initialize_server_options(&ٻاهريون);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, عدم);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), عدم);
	POKE_U32(sshbuf_mutable_ptr(buf), 2);
	r = deserialise_server_options(buf, &ٻاهريون);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&ٻاهريون);
	sshbuf_free(buf);
}

ساكن فراغ
check_rejects_bad_پورٽ_ڳڻپ(ثابت ServerOptions *o)
{
	بنية sshbuf *buf = عدم;
	ServerOptions ٻاهريون;
	صحيح r;

	initialize_server_options(&ٻاهريون);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, عدم);
	ASSERT_سائيز_T_GT(sshbuf_len(buf), 8);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), عدم);
	POKE_U32(sshbuf_mutable_ptr(buf) + 4, MAX_PORTS + 1);
	r = deserialise_server_options(buf, &ٻاهريون);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&ٻاهريون);
	sshbuf_free(buf);
}

ساكن فراغ
check_roundtrip_signed_limits(ثابت ServerOptions *o)
{
	بنية sshbuf *buf = عدم;
	ServerOptions ٻاهريون, اندريون;

	initialize_server_options(&ٻاهريون);
	اندريون = *o;
	اندريون.fwd_opts.streamlocal_bind_نقاب = (گهڻائي_t)-1;
	اندريون.ip_qos_bulk = INT_MIN;
	اندريون.rekey_حد_بندي = INT64_MIN;
	ASSERT_INT_EQ(serialise_server_options(&اندريون, &buf), 0);
	ASSERT_PTR_NE(buf, عدم);
	ASSERT_INT_EQ(deserialise_server_options(buf, &ٻاهريون), 0);
	ASSERT_INT_EQ(ٻاهريون.fwd_opts.streamlocal_bind_نقاب == (گهڻائي_t)-1, 1);
	ASSERT_INT_EQ(ٻاهريون.ip_qos_bulk, INT_MIN);
	ASSERT_LONG_LONG_EQ(ٻاهريون.rekey_حد_بندي, INT64_MIN);
	free_server_options(&ٻاهريون);
	sshbuf_free(buf);
}

ساكن فراغ
attempt_deserialise_blob(ثابت u_char *p, سائيز_t len)
{
	بنية sshbuf *buf;
	ServerOptions ٻاهريون;

	initialize_server_options(&ٻاهريون);
	ASSERT_PTR_NE(buf = sshbuf_from(p, len), عدم);
	(فراغ)deserialise_server_options(buf, &ٻاهريون);
	free_server_options(&ٻاهريون);
	sshbuf_free(buf);
}

ساكن فراغ
check_fuzz_deserialise(ثابت ServerOptions *o)
{
	بنية sshbuf *buf = عدم;
	بنية fuzz *fuzz;
	u_int fuzzers = FUZZ_1_ٻٽو_انگ_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_شروعات | FUZZ_TRUNCATE_پڇاڙي;

	إذا (test_is_fast())
		fuzzers &= ~FUZZ_1_ٻٽو_انگ_FLIP;
	إذا (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP;

	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, عدم);
	fuzz = fuzz_begin(fuzzers, sshbuf_ptr(buf), sshbuf_len(buf));
	TEST_ONERROR(onerror, fuzz);
	لكل (; !fuzz_پورو(fuzz); fuzz_ايندڙ(fuzz))
		attempt_deserialise_blob(fuzz_ptr(fuzz), fuzz_len(fuzz));
	TEST_ONERROR(عدم, عدم);
	fuzz_cleanup(fuzz);
	sshbuf_free(buf);
}

فراغ
tests(فراغ)
{
	ServerOptions o;

	log_init("test_servconf", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 1);

	TEST_شروعات("server options round trip preserves nullable state");
	سيٽ_test_options(&o);
	check_roundtrip(&o);
	free_server_options(&o);
	TEST_پورو();

	TEST_شروعات("server options reject trailing data");
	سيٽ_test_options(&o);
	check_rejects_trailing_معلومات(&o);
	free_server_options(&o);
	TEST_پورو();

	TEST_شروعات("server options reject unsupported version");
	سيٽ_test_options(&o);
	check_rejects_bad_نسخو(&o);
	free_server_options(&o);
	TEST_پورو();

	TEST_شروعات("server options reject bad port count");
	سيٽ_test_options(&o);
	check_rejects_bad_پورٽ_ڳڻپ(&o);
	free_server_options(&o);
	TEST_پورو();

	TEST_شروعات("server options round trip signed limits");
	سيٽ_test_options(&o);
	check_roundtrip_signed_limits(&o);
	free_server_options(&o);
	TEST_پورو();

	TEST_شروعات("server options deserialise fuzz");
	سيٽ_test_options(&o);
	check_fuzz_deserialise(&o);
	free_server_options(&o);
	TEST_پورو();
}

فراغ
benchmarks(فراغ)
{
	لکو("no benchmarks\n");
}
