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
مجموعه_string(حرف **dst, ثابت حرف *s)
{
	*dst = s == عدم ? عدم : xstrdup(s);
}

ساكن حرف **
new_string_array(u_int n)
{
	أرجع xcalloc(n, حجم(حرف *));
}

ساكن فراغ
مجموعه_test_options(ServerOptions *o)
{
	initialize_server_options(o);

	o->رقم_ports = 2;
	o->ports[0] = 22;
	o->ports[1] = 2022;
	o->ip_qos_interactive = 0x10;
	o->ip_qos_bulk = 0x08;
	o->log_facility = SYSLOG_FACILITY_AUTH;
	o->log_level = SYSLOG_LEVEL_DEBUG3;
	o->fwd_opts.gateway_ports = 1;
	o->fwd_opts.streamlocal_bind_ماسک = 0177;
	o->fwd_opts.streamlocal_bind_unlink = 1;
	o->permit_user_env = 1;
	مجموعه_string(&o->permit_user_env_allowlist, "");
	o->rekey_حد = 123456789;
	o->rekey_interval = 600;
	o->timing_secret = 0x0102030405060708ULL;

	مجموعه_string(&o->routing_domain, "");
	مجموعه_string(&o->banner, عدم);
	مجموعه_string(&o->adm_forced_command, "internal-sftp");
	مجموعه_string(&o->chroot_directory, "");
	مجموعه_string(&o->host_کلید_agent, عدم);
	مجموعه_string(&o->authorized_کلیدها_command, "/bin/echo");
	مجموعه_string(&o->authorized_کلیدها_command_user, "");
	مجموعه_string(&o->authorized_principals_file, عدم);

	o->رقم_authkeys_files = 3;
	o->authorized_کلیدها_files = new_string_array(o->رقم_authkeys_files);
	مجموعه_string(&o->authorized_کلیدها_files[0], عدم);
	مجموعه_string(&o->authorized_کلیدها_files[1], "");
	مجموعه_string(&o->authorized_کلیدها_files[2], ".ssh/authorized_keys");

	o->رقم_log_verbose = 2;
	o->log_verbose = new_string_array(o->رقم_log_verbose);
	مجموعه_string(&o->log_verbose[0], عدم);
	مجموعه_string(&o->log_verbose[1], "kex.c:*");

	o->رقم_host_کلید_files = 3;
	o->host_کلید_file_userprovided =
	    xcalloc(o->رقم_host_کلید_files,
	    حجم(*o->host_کلید_file_userprovided));
	o->host_کلید_files = new_string_array(o->رقم_host_کلید_files);
	o->host_کلید_file_userprovided[0] = 0;
	o->host_کلید_file_userprovided[1] = 1;
	o->host_کلید_file_userprovided[2] = -1;
	مجموعه_string(&o->host_کلید_files[0], عدم);
	مجموعه_string(&o->host_کلید_files[1], "");
	مجموعه_string(&o->host_کلید_files[2], "/tmp/ssh_host_ed25519_key");

	o->رقم_queued_listens = 2;
	o->queued_listen_addrs = xcalloc(o->رقم_queued_listens,
	    حجم(*o->queued_listen_addrs));
	مجموعه_string(&o->queued_listen_addrs[0].addr, "127.0.0.1");
	o->queued_listen_addrs[0].پورت = 2222;
	مجموعه_string(&o->queued_listen_addrs[0].rdomain, عدم);
	مجموعه_string(&o->queued_listen_addrs[1].addr, "::1");
	o->queued_listen_addrs[1].پورت = -1;
	مجموعه_string(&o->queued_listen_addrs[1].rdomain, "");

	o->رقم_subsystems = 2;
	o->subsystem_name = new_string_array(o->رقم_subsystems);
	o->subsystem_command = new_string_array(o->رقم_subsystems);
	o->subsystem_آرگومانها = new_string_array(o->رقم_subsystems);
	مجموعه_string(&o->subsystem_name[0], "sftp");
	مجموعه_string(&o->subsystem_command[0], "internal-sftp");
	مجموعه_string(&o->subsystem_آرگومانها[0], "internal-sftp -f AUTH");
	مجموعه_string(&o->subsystem_name[1], "echo");
	مجموعه_string(&o->subsystem_command[1], "/bin/echo");
	مجموعه_string(&o->subsystem_آرگومانها[1], "/bin/echo hello");
}

ساكن فراغ
check_roundtrip(ثابت ServerOptions *o)
{
	بنية sshbuf *buf = عدم;
	ServerOptions بیرون;

	initialize_server_options(&بیرون);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, عدم);
	ASSERT_INT_EQ(deserialise_server_options(buf, &بیرون), 0);
	ASSERT_اندازه_T_EQ(sshbuf_len(buf), 0);

	ASSERT_U_INT_EQ(بیرون.رقم_ports, 2);
	ASSERT_INT_EQ(بیرون.ports[0], 22);
	ASSERT_INT_EQ(بیرون.ports[1], 2022);
	ASSERT_INT_EQ(بیرون.ip_qos_interactive, 0x10);
	ASSERT_INT_EQ(بیرون.ip_qos_bulk, 0x08);
	ASSERT_INT_EQ(بیرون.log_facility, SYSLOG_FACILITY_AUTH);
	ASSERT_INT_EQ(بیرون.log_level, SYSLOG_LEVEL_DEBUG3);
	ASSERT_INT_EQ(بیرون.fwd_opts.gateway_ports, 1);
	ASSERT_INT_EQ(بیرون.fwd_opts.streamlocal_bind_ماسک, 0177);
	ASSERT_INT_EQ(بیرون.fwd_opts.streamlocal_bind_unlink, 1);
	ASSERT_INT_EQ(بیرون.permit_user_env, 1);
	ASSERT_STRING_EQ(بیرون.permit_user_env_allowlist, "");
	ASSERT_LONG_LONG_EQ(بیرون.rekey_حد, 123456789);
	ASSERT_INT_EQ(بیرون.rekey_interval, 600);
	ASSERT_U64_EQ(بیرون.timing_secret, 0x0102030405060708ULL);

	ASSERT_STRING_EQ(بیرون.routing_domain, "");
	ASSERT_PTR_EQ(بیرون.banner, عدم);
	ASSERT_STRING_EQ(بیرون.adm_forced_command, "internal-sftp");
	ASSERT_STRING_EQ(بیرون.chroot_directory, "");
	ASSERT_PTR_EQ(بیرون.host_کلید_agent, عدم);
	ASSERT_STRING_EQ(بیرون.authorized_کلیدها_command, "/bin/echo");
	ASSERT_STRING_EQ(بیرون.authorized_کلیدها_command_user, "");
	ASSERT_PTR_EQ(بیرون.authorized_principals_file, عدم);

	ASSERT_U_INT_EQ(بیرون.رقم_authkeys_files, 3);
	ASSERT_PTR_EQ(بیرون.authorized_کلیدها_files[0], عدم);
	ASSERT_STRING_EQ(بیرون.authorized_کلیدها_files[1], "");
	ASSERT_STRING_EQ(بیرون.authorized_کلیدها_files[2], ".ssh/authorized_keys");

	ASSERT_U_INT_EQ(بیرون.رقم_log_verbose, 2);
	ASSERT_PTR_EQ(بیرون.log_verbose[0], عدم);
	ASSERT_STRING_EQ(بیرون.log_verbose[1], "kex.c:*");

	ASSERT_U_INT_EQ(بیرون.رقم_host_کلید_files, 3);
	ASSERT_INT_EQ(بیرون.host_کلید_file_userprovided[0], 0);
	ASSERT_INT_EQ(بیرون.host_کلید_file_userprovided[1], 1);
	ASSERT_INT_EQ(بیرون.host_کلید_file_userprovided[2], -1);
	ASSERT_PTR_EQ(بیرون.host_کلید_files[0], عدم);
	ASSERT_STRING_EQ(بیرون.host_کلید_files[1], "");
	ASSERT_STRING_EQ(بیرون.host_کلید_files[2], "/tmp/ssh_host_ed25519_key");

	ASSERT_U_INT_EQ(بیرون.رقم_queued_listens, 2);
	ASSERT_STRING_EQ(بیرون.queued_listen_addrs[0].addr, "127.0.0.1");
	ASSERT_INT_EQ(بیرون.queued_listen_addrs[0].پورت, 2222);
	ASSERT_PTR_EQ(بیرون.queued_listen_addrs[0].rdomain, عدم);
	ASSERT_STRING_EQ(بیرون.queued_listen_addrs[1].addr, "::1");
	ASSERT_INT_EQ(بیرون.queued_listen_addrs[1].پورت, -1);
	ASSERT_STRING_EQ(بیرون.queued_listen_addrs[1].rdomain, "");

	ASSERT_U_INT_EQ(بیرون.رقم_subsystems, 2);
	ASSERT_STRING_EQ(بیرون.subsystem_name[0], "sftp");
	ASSERT_STRING_EQ(بیرون.subsystem_command[0], "internal-sftp");
	ASSERT_STRING_EQ(بیرون.subsystem_آرگومانها[0], "internal-sftp -f AUTH");
	ASSERT_STRING_EQ(بیرون.subsystem_name[1], "echo");
	ASSERT_STRING_EQ(بیرون.subsystem_command[1], "/bin/echo");
	ASSERT_STRING_EQ(بیرون.subsystem_آرگومانها[1], "/bin/echo hello");

	free_server_options(&بیرون);
	sshbuf_free(buf);
}

ساكن فراغ
check_rejects_trailing_داده(ثابت ServerOptions *o)
{
	بنية sshbuf *buf = عدم;
	ServerOptions بیرون;
	صحيح r;

	initialize_server_options(&بیرون);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, عدم);
	ASSERT_INT_EQ(sshbuf_put_u8(buf, 0), 0);
	r = deserialise_server_options(buf, &بیرون);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&بیرون);
	sshbuf_free(buf);
}

ساكن فراغ
check_rejects_bad_نسخه(ثابت ServerOptions *o)
{
	بنية sshbuf *buf = عدم;
	ServerOptions بیرون;
	صحيح r;

	initialize_server_options(&بیرون);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, عدم);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), عدم);
	POKE_U32(sshbuf_mutable_ptr(buf), 2);
	r = deserialise_server_options(buf, &بیرون);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&بیرون);
	sshbuf_free(buf);
}

ساكن فراغ
check_rejects_bad_پورت_شمار(ثابت ServerOptions *o)
{
	بنية sshbuf *buf = عدم;
	ServerOptions بیرون;
	صحيح r;

	initialize_server_options(&بیرون);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, عدم);
	ASSERT_اندازه_T_GT(sshbuf_len(buf), 8);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), عدم);
	POKE_U32(sshbuf_mutable_ptr(buf) + 4, MAX_PORTS + 1);
	r = deserialise_server_options(buf, &بیرون);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&بیرون);
	sshbuf_free(buf);
}

ساكن فراغ
check_roundtrip_signed_limits(ثابت ServerOptions *o)
{
	بنية sshbuf *buf = عدم;
	ServerOptions بیرون, درون;

	initialize_server_options(&بیرون);
	درون = *o;
	درون.fwd_opts.streamlocal_bind_ماسک = (نما_t)-1;
	درون.ip_qos_bulk = INT_MIN;
	درون.rekey_حد = INT64_MIN;
	ASSERT_INT_EQ(serialise_server_options(&درون, &buf), 0);
	ASSERT_PTR_NE(buf, عدم);
	ASSERT_INT_EQ(deserialise_server_options(buf, &بیرون), 0);
	ASSERT_INT_EQ(بیرون.fwd_opts.streamlocal_bind_ماسک == (نما_t)-1, 1);
	ASSERT_INT_EQ(بیرون.ip_qos_bulk, INT_MIN);
	ASSERT_LONG_LONG_EQ(بیرون.rekey_حد, INT64_MIN);
	free_server_options(&بیرون);
	sshbuf_free(buf);
}

ساكن فراغ
attempt_deserialise_blob(ثابت u_char *p, اندازه_t len)
{
	بنية sshbuf *buf;
	ServerOptions بیرون;

	initialize_server_options(&بیرون);
	ASSERT_PTR_NE(buf = sshbuf_from(p, len), عدم);
	(فراغ)deserialise_server_options(buf, &بیرون);
	free_server_options(&بیرون);
	sshbuf_free(buf);
}

ساكن فراغ
check_fuzz_deserialise(ثابت ServerOptions *o)
{
	بنية sshbuf *buf = عدم;
	بنية fuzz *fuzz;
	u_int fuzzers = FUZZ_1_بیت_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_شروع | FUZZ_TRUNCATE_انتها;

	إذا (test_is_fast())
		fuzzers &= ~FUZZ_1_بیت_FLIP;
	إذا (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP;

	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, عدم);
	fuzz = fuzz_begin(fuzzers, sshbuf_ptr(buf), sshbuf_len(buf));
	TEST_ONERROR(onerror, fuzz);
	لكل (; !fuzz_انجامشده(fuzz); fuzz_بعدی(fuzz))
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

	TEST_شروع("server options round trip preserves nullable state");
	مجموعه_test_options(&o);
	check_roundtrip(&o);
	free_server_options(&o);
	TEST_انجامشده();

	TEST_شروع("server options reject trailing data");
	مجموعه_test_options(&o);
	check_rejects_trailing_داده(&o);
	free_server_options(&o);
	TEST_انجامشده();

	TEST_شروع("server options reject unsupported version");
	مجموعه_test_options(&o);
	check_rejects_bad_نسخه(&o);
	free_server_options(&o);
	TEST_انجامشده();

	TEST_شروع("server options reject bad port count");
	مجموعه_test_options(&o);
	check_rejects_bad_پورت_شمار(&o);
	free_server_options(&o);
	TEST_انجامشده();

	TEST_شروع("server options round trip signed limits");
	مجموعه_test_options(&o);
	check_roundtrip_signed_limits(&o);
	free_server_options(&o);
	TEST_انجامشده();

	TEST_شروع("server options deserialise fuzz");
	مجموعه_test_options(&o);
	check_fuzz_deserialise(&o);
	free_server_options(&o);
	TEST_انجامشده();
}

فراغ
benchmarks(فراغ)
{
	چاپ_کن("no benchmarks\n");
}
