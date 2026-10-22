/* 	$OpenBSD: tests.c,v 1.1 2026/05/31 11:39:44 djm Exp $ */
/*
 * Regress tests for servconf.h server configuration API
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <limits.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "log.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "xmalloc.h"

ساخت sshbuf *cfg;

/* stub */
صحیح auth2_methods_valid(ثابت حرف *methods, صحیح need_enable);
صحیح
auth2_methods_valid(ثابت حرف *methods, صحیح need_enable)
{
	واپس 1;
}

ساکن خالی
onerror(خالی *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((ساخت fuzz *)fuzz);
}

ساکن خالی
سیٹ_string(حرف **dst, ثابت حرف *s)
{
	*dst = s == تہی ? تہی : xstrdup(s);
}

ساکن حرف **
new_string_array(u_int n)
{
	واپس xcalloc(n, حجم(حرف *));
}

ساکن خالی
سیٹ_test_options(ServerOptions *o)
{
	initialize_server_options(o);

	o->عدد_ports = 2;
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
	سیٹ_string(&o->permit_user_env_allowlist, "");
	o->rekey_حد_بندی = 123456789;
	o->rekey_interval = 600;
	o->timing_secret = 0x0102030405060708ULL;

	سیٹ_string(&o->routing_domain, "");
	سیٹ_string(&o->banner, تہی);
	سیٹ_string(&o->adm_forced_command, "internal-sftp");
	سیٹ_string(&o->chroot_directory, "");
	سیٹ_string(&o->host_کلید_agent, تہی);
	سیٹ_string(&o->authorized_کلیدیں_command, "/bin/echo");
	سیٹ_string(&o->authorized_کلیدیں_command_user, "");
	سیٹ_string(&o->authorized_principals_file, تہی);

	o->عدد_authkeys_files = 3;
	o->authorized_کلیدیں_files = new_string_array(o->عدد_authkeys_files);
	سیٹ_string(&o->authorized_کلیدیں_files[0], تہی);
	سیٹ_string(&o->authorized_کلیدیں_files[1], "");
	سیٹ_string(&o->authorized_کلیدیں_files[2], ".ssh/authorized_keys");

	o->عدد_log_verbose = 2;
	o->log_verbose = new_string_array(o->عدد_log_verbose);
	سیٹ_string(&o->log_verbose[0], تہی);
	سیٹ_string(&o->log_verbose[1], "kex.c:*");

	o->عدد_host_کلید_files = 3;
	o->host_کلید_file_userprovided =
	    xcalloc(o->عدد_host_کلید_files,
	    حجم(*o->host_کلید_file_userprovided));
	o->host_کلید_files = new_string_array(o->عدد_host_کلید_files);
	o->host_کلید_file_userprovided[0] = 0;
	o->host_کلید_file_userprovided[1] = 1;
	o->host_کلید_file_userprovided[2] = -1;
	سیٹ_string(&o->host_کلید_files[0], تہی);
	سیٹ_string(&o->host_کلید_files[1], "");
	سیٹ_string(&o->host_کلید_files[2], "/tmp/ssh_host_ed25519_key");

	o->عدد_queued_listens = 2;
	o->queued_listen_addrs = xcalloc(o->عدد_queued_listens,
	    حجم(*o->queued_listen_addrs));
	سیٹ_string(&o->queued_listen_addrs[0].addr, "127.0.0.1");
	o->queued_listen_addrs[0].پورٹ = 2222;
	سیٹ_string(&o->queued_listen_addrs[0].rdomain, تہی);
	سیٹ_string(&o->queued_listen_addrs[1].addr, "::1");
	o->queued_listen_addrs[1].پورٹ = -1;
	سیٹ_string(&o->queued_listen_addrs[1].rdomain, "");

	o->عدد_subsystems = 2;
	o->subsystem_name = new_string_array(o->عدد_subsystems);
	o->subsystem_command = new_string_array(o->عدد_subsystems);
	o->subsystem_دلائل = new_string_array(o->عدد_subsystems);
	سیٹ_string(&o->subsystem_name[0], "sftp");
	سیٹ_string(&o->subsystem_command[0], "internal-sftp");
	سیٹ_string(&o->subsystem_دلائل[0], "internal-sftp -f AUTH");
	سیٹ_string(&o->subsystem_name[1], "echo");
	سیٹ_string(&o->subsystem_command[1], "/bin/echo");
	سیٹ_string(&o->subsystem_دلائل[1], "/bin/echo hello");
}

ساکن خالی
check_roundtrip(ثابت ServerOptions *o)
{
	ساخت sshbuf *buf = تہی;
	ServerOptions برآمد;

	initialize_server_options(&برآمد);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, تہی);
	ASSERT_INT_EQ(deserialise_server_options(buf, &برآمد), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(buf), 0);

	ASSERT_U_INT_EQ(برآمد.عدد_ports, 2);
	ASSERT_INT_EQ(برآمد.ports[0], 22);
	ASSERT_INT_EQ(برآمد.ports[1], 2022);
	ASSERT_INT_EQ(برآمد.ip_qos_interactive, 0x10);
	ASSERT_INT_EQ(برآمد.ip_qos_bulk, 0x08);
	ASSERT_INT_EQ(برآمد.log_facility, SYSLOG_FACILITY_AUTH);
	ASSERT_INT_EQ(برآمد.log_level, SYSLOG_LEVEL_DEBUG3);
	ASSERT_INT_EQ(برآمد.fwd_opts.gateway_ports, 1);
	ASSERT_INT_EQ(برآمد.fwd_opts.streamlocal_bind_نقاب, 0177);
	ASSERT_INT_EQ(برآمد.fwd_opts.streamlocal_bind_unlink, 1);
	ASSERT_INT_EQ(برآمد.permit_user_env, 1);
	ASSERT_STRING_EQ(برآمد.permit_user_env_allowlist, "");
	ASSERT_LONG_LONG_EQ(برآمد.rekey_حد_بندی, 123456789);
	ASSERT_INT_EQ(برآمد.rekey_interval, 600);
	ASSERT_U64_EQ(برآمد.timing_secret, 0x0102030405060708ULL);

	ASSERT_STRING_EQ(برآمد.routing_domain, "");
	ASSERT_PTR_EQ(برآمد.banner, تہی);
	ASSERT_STRING_EQ(برآمد.adm_forced_command, "internal-sftp");
	ASSERT_STRING_EQ(برآمد.chroot_directory, "");
	ASSERT_PTR_EQ(برآمد.host_کلید_agent, تہی);
	ASSERT_STRING_EQ(برآمد.authorized_کلیدیں_command, "/bin/echo");
	ASSERT_STRING_EQ(برآمد.authorized_کلیدیں_command_user, "");
	ASSERT_PTR_EQ(برآمد.authorized_principals_file, تہی);

	ASSERT_U_INT_EQ(برآمد.عدد_authkeys_files, 3);
	ASSERT_PTR_EQ(برآمد.authorized_کلیدیں_files[0], تہی);
	ASSERT_STRING_EQ(برآمد.authorized_کلیدیں_files[1], "");
	ASSERT_STRING_EQ(برآمد.authorized_کلیدیں_files[2], ".ssh/authorized_keys");

	ASSERT_U_INT_EQ(برآمد.عدد_log_verbose, 2);
	ASSERT_PTR_EQ(برآمد.log_verbose[0], تہی);
	ASSERT_STRING_EQ(برآمد.log_verbose[1], "kex.c:*");

	ASSERT_U_INT_EQ(برآمد.عدد_host_کلید_files, 3);
	ASSERT_INT_EQ(برآمد.host_کلید_file_userprovided[0], 0);
	ASSERT_INT_EQ(برآمد.host_کلید_file_userprovided[1], 1);
	ASSERT_INT_EQ(برآمد.host_کلید_file_userprovided[2], -1);
	ASSERT_PTR_EQ(برآمد.host_کلید_files[0], تہی);
	ASSERT_STRING_EQ(برآمد.host_کلید_files[1], "");
	ASSERT_STRING_EQ(برآمد.host_کلید_files[2], "/tmp/ssh_host_ed25519_key");

	ASSERT_U_INT_EQ(برآمد.عدد_queued_listens, 2);
	ASSERT_STRING_EQ(برآمد.queued_listen_addrs[0].addr, "127.0.0.1");
	ASSERT_INT_EQ(برآمد.queued_listen_addrs[0].پورٹ, 2222);
	ASSERT_PTR_EQ(برآمد.queued_listen_addrs[0].rdomain, تہی);
	ASSERT_STRING_EQ(برآمد.queued_listen_addrs[1].addr, "::1");
	ASSERT_INT_EQ(برآمد.queued_listen_addrs[1].پورٹ, -1);
	ASSERT_STRING_EQ(برآمد.queued_listen_addrs[1].rdomain, "");

	ASSERT_U_INT_EQ(برآمد.عدد_subsystems, 2);
	ASSERT_STRING_EQ(برآمد.subsystem_name[0], "sftp");
	ASSERT_STRING_EQ(برآمد.subsystem_command[0], "internal-sftp");
	ASSERT_STRING_EQ(برآمد.subsystem_دلائل[0], "internal-sftp -f AUTH");
	ASSERT_STRING_EQ(برآمد.subsystem_name[1], "echo");
	ASSERT_STRING_EQ(برآمد.subsystem_command[1], "/bin/echo");
	ASSERT_STRING_EQ(برآمد.subsystem_دلائل[1], "/bin/echo hello");

	free_server_options(&برآمد);
	sshbuf_free(buf);
}

ساکن خالی
check_rejects_trailing_ڈیٹا(ثابت ServerOptions *o)
{
	ساخت sshbuf *buf = تہی;
	ServerOptions برآمد;
	صحیح r;

	initialize_server_options(&برآمد);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, تہی);
	ASSERT_INT_EQ(sshbuf_put_u8(buf, 0), 0);
	r = deserialise_server_options(buf, &برآمد);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&برآمد);
	sshbuf_free(buf);
}

ساکن خالی
check_rejects_bad_نسخہ(ثابت ServerOptions *o)
{
	ساخت sshbuf *buf = تہی;
	ServerOptions برآمد;
	صحیح r;

	initialize_server_options(&برآمد);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, تہی);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), تہی);
	POKE_U32(sshbuf_mutable_ptr(buf), 2);
	r = deserialise_server_options(buf, &برآمد);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&برآمد);
	sshbuf_free(buf);
}

ساکن خالی
check_rejects_bad_پورٹ_گنتی(ثابت ServerOptions *o)
{
	ساخت sshbuf *buf = تہی;
	ServerOptions برآمد;
	صحیح r;

	initialize_server_options(&برآمد);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, تہی);
	ASSERT_سائز_T_GT(sshbuf_len(buf), 8);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), تہی);
	POKE_U32(sshbuf_mutable_ptr(buf) + 4, MAX_PORTS + 1);
	r = deserialise_server_options(buf, &برآمد);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&برآمد);
	sshbuf_free(buf);
}

ساکن خالی
check_roundtrip_signed_limits(ثابت ServerOptions *o)
{
	ساخت sshbuf *buf = تہی;
	ServerOptions برآمد, اندر;

	initialize_server_options(&برآمد);
	اندر = *o;
	اندر.fwd_opts.streamlocal_bind_نقاب = (منوال_t)-1;
	اندر.ip_qos_bulk = INT_MIN;
	اندر.rekey_حد_بندی = INT64_MIN;
	ASSERT_INT_EQ(serialise_server_options(&اندر, &buf), 0);
	ASSERT_PTR_NE(buf, تہی);
	ASSERT_INT_EQ(deserialise_server_options(buf, &برآمد), 0);
	ASSERT_INT_EQ(برآمد.fwd_opts.streamlocal_bind_نقاب == (منوال_t)-1, 1);
	ASSERT_INT_EQ(برآمد.ip_qos_bulk, INT_MIN);
	ASSERT_LONG_LONG_EQ(برآمد.rekey_حد_بندی, INT64_MIN);
	free_server_options(&برآمد);
	sshbuf_free(buf);
}

ساکن خالی
attempt_deserialise_blob(ثابت u_char *p, سائز_t len)
{
	ساخت sshbuf *buf;
	ServerOptions برآمد;

	initialize_server_options(&برآمد);
	ASSERT_PTR_NE(buf = sshbuf_from(p, len), تہی);
	(خالی)deserialise_server_options(buf, &برآمد);
	free_server_options(&برآمد);
	sshbuf_free(buf);
}

ساکن خالی
check_fuzz_deserialise(ثابت ServerOptions *o)
{
	ساخت sshbuf *buf = تہی;
	ساخت fuzz *fuzz;
	u_int fuzzers = FUZZ_1_ثنائی_ہندسہ_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_آغاز | FUZZ_TRUNCATE_انتہا;

	اگر (test_is_fast())
		fuzzers &= ~FUZZ_1_ثنائی_ہندسہ_FLIP;
	اگر (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP;

	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, تہی);
	fuzz = fuzz_begin(fuzzers, sshbuf_ptr(buf), sshbuf_len(buf));
	TEST_ONERROR(onerror, fuzz);
	برائے (; !fuzz_مکمل(fuzz); fuzz_اگلا(fuzz))
		attempt_deserialise_blob(fuzz_ptr(fuzz), fuzz_len(fuzz));
	TEST_ONERROR(تہی, تہی);
	fuzz_cleanup(fuzz);
	sshbuf_free(buf);
}

خالی
tests(خالی)
{
	ServerOptions o;

	log_init("test_servconf", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 1);

	TEST_آغاز("server options round trip preserves nullable state");
	سیٹ_test_options(&o);
	check_roundtrip(&o);
	free_server_options(&o);
	TEST_مکمل();

	TEST_آغاز("server options reject trailing data");
	سیٹ_test_options(&o);
	check_rejects_trailing_ڈیٹا(&o);
	free_server_options(&o);
	TEST_مکمل();

	TEST_آغاز("server options reject unsupported version");
	سیٹ_test_options(&o);
	check_rejects_bad_نسخہ(&o);
	free_server_options(&o);
	TEST_مکمل();

	TEST_آغاز("server options reject bad port count");
	سیٹ_test_options(&o);
	check_rejects_bad_پورٹ_گنتی(&o);
	free_server_options(&o);
	TEST_مکمل();

	TEST_آغاز("server options round trip signed limits");
	سیٹ_test_options(&o);
	check_roundtrip_signed_limits(&o);
	free_server_options(&o);
	TEST_مکمل();

	TEST_آغاز("server options deserialise fuzz");
	سیٹ_test_options(&o);
	check_fuzz_deserialise(&o);
	free_server_options(&o);
	TEST_مکمل();
}

خالی
benchmarks(خالی)
{
	لکھو("no benchmarks\n");
}
