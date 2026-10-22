/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzzer for small string-input parsers across OpenSSH
 *
 * Targets: misc.c, addr.c, addrmatch.c, match.c
 *
 * Threat model:
 * - User-supplied CLI arguments (user@host:port, ssh:// URIs, port and
 *   tunnel numbers)
 * - Admin-supplied patterns in sshd_config / ssh_config (Match Address
 *   CIDR lists, AllowUsers / DenyUsers, AllowGroups, hostname patterns)
 *
 * All targeted functions are pure (no inter-call state). Each iteration
 * invokes every parser exactly once on the same fuzz body in a fixed
 * source order. The body is split into two substrings at the first
 * embedded NUL so two-argument matchers can mutate either side.
 *
 * Parsers covered:
 * - parse_user_host_port, parse_uri, convtime, a2port, a2tun,
 *   argv_split + argv_assemble, valid_domain, valid_env_name,
 *   parse_absolute_time (misc.c)
 * - addr_pton, addr_pton_cidr (addr.c)
 * - addr_match_list, addr_match_cidr_list (addrmatch.c)
 * - match_pattern, match_pattern_list, match_hostname,
 *   match_host_and_ip, match_user (match.c)
 */

#شامل <stdio.h>
#شامل <stddef.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <sys/types.h>

خارجی "C" {
#شامل "addr.h"
#شامل "match.h"
#شامل "misc.h"
#شامل "log.h"
}

ساکن صحیح log_initialized = 0;

ساکن حرف *
dup_n(ثابت uint8_t *body, سائز_t blen)
{
	حرف *s = (حرف *)حافظہ_دو(blen + 1);
	اگر (s == تہی)
		واپس تہی;
	حافظہ_نقل(s, body, blen);
	s[blen] = '\0';
	واپس s;
}

ساکن خالی
بانٹو_two(ثابت uint8_t *body, سائز_t blen, حرف **a, حرف **b)
{
	ثابت uint8_t *nul = (ثابت uint8_t *)memchr(body, 0, blen);
	*a = تہی;
	*b = تہی;
	اگر (nul == تہی) {
		*a = dup_n(body, blen);
		*b = strdup("");
		واپس;
	}
	سائز_t alen = (سائز_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

خارجی "C" صحیح
LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t *ڈیٹا, سائز_t سائز)
{
	اگر (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	اگر (سائز == 0)
		واپس 0;

	حرف *s = dup_n(ڈیٹا, سائز);
	حرف *a = تہی, *b = تہی;
	بانٹو_two(ڈیٹا, سائز, &a, &b);
	اگر (s == تہی || a == تہی || b == تہی) {
		آزاد(s);
		آزاد(a);
		آزاد(b);
		واپس 0;
	}

	{
		حرف *u = تہی, *h = تہی;
		صحیح پورٹ = 0;
		اگر (parse_user_host_پورٹ(s, &u, &h, &پورٹ) == 0) {
			آزاد(u);
			آزاد(h);
		}
	}
	{
		حرف *u = تہی, *h = تہی, *p = تہی;
		صحیح پورٹ = 0;
		اگر (parse_uri("ssh", s, &u, &h, &پورٹ, &p) == 0) {
			آزاد(u);
			آزاد(h);
			آزاد(p);
		}
	}
	(خالی)convtime(s);
	(خالی)a2port(s);
	{
		صحیح tun = 0;
		(خالی)a2tun(s, &tun);
	}
	{
		صحیح ac = 0;
		حرف **av = تہی;
		اگر (argv_بانٹو(s, &ac, &av, 1) == 0) {
			حرف *عقب = argv_assemble(ac, av);
			آزاد(عقب);
			argv_free(av, ac);
		}
	}
	{
		ثابت حرف *err = تہی;
		(خالی)valid_domain(s, 0, &err);
	}
	(خالی)valid_env_name(s);
	{
		uint64_t t = 0;
		(خالی)parse_absolute_وقت(s, &t);
	}

	{
		ساخت xaddr n;
		(خالی)addr_pton(s, &n);
	}
	{
		ساخت xaddr n;
		u_int سابقہ = 0;
		(خالی)addr_pton_cidr(s, &n, &سابقہ);
	}

	(خالی)addr_مطابقت_list(a, b);
	(خالی)addr_مطابقت_cidr_list(a, b);
	(خالی)مطابقت_نمونہ(a, b);
	(خالی)مطابقت_نمونہ_list(a, b, 0);
	(خالی)مطابقت_hostname(a, b);
	(خالی)مطابقت_host_and_ip(a, "127.0.0.1", b);
	(خالی)مطابقت_user("fuzz", a, "127.0.0.1", b);

	آزاد(s);
	آزاد(a);
	آزاد(b);
	واپس 0;
}
