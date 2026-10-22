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

#ضمن <stdio.h>
#ضمن <stddef.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <sys/types.h>

خارجي "C" {
#ضمن "addr.h"
#ضمن "match.h"
#ضمن "misc.h"
#ضمن "log.h"
}

ساكن صحيح log_initialized = 0;

ساكن حرف *
dup_n(ثابت uint8_t *body, سائيز_t blen)
{
	حرف *s = (حرف *)يادگيري_ڏيو(blen + 1);
	إذا (s == عدم)
		أرجع عدم;
	يادگيري_نقل(s, body, blen);
	s[blen] = '\0';
	أرجع s;
}

ساكن فراغ
ورهايو_two(ثابت uint8_t *body, سائيز_t blen, حرف **a, حرف **b)
{
	ثابت uint8_t *nul = (ثابت uint8_t *)memchr(body, 0, blen);
	*a = عدم;
	*b = عدم;
	إذا (nul == عدم) {
		*a = dup_n(body, blen);
		*b = strdup("");
		أرجع;
	}
	سائيز_t alen = (سائيز_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

خارجي "C" صحيح
LLVMFuzzer_Test_One_داخلا(ثابت uint8_t *معلومات, سائيز_t سائيز)
{
	إذا (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	إذا (سائيز == 0)
		أرجع 0;

	حرف *s = dup_n(معلومات, سائيز);
	حرف *a = عدم, *b = عدم;
	ورهايو_two(معلومات, سائيز, &a, &b);
	إذا (s == عدم || a == عدم || b == عدم) {
		حرر(s);
		حرر(a);
		حرر(b);
		أرجع 0;
	}

	{
		حرف *u = عدم, *h = عدم;
		صحيح پورٽ = 0;
		إذا (parse_user_host_پورٽ(s, &u, &h, &پورٽ) == 0) {
			حرر(u);
			حرر(h);
		}
	}
	{
		حرف *u = عدم, *h = عدم, *p = عدم;
		صحيح پورٽ = 0;
		إذا (parse_uri("ssh", s, &u, &h, &پورٽ, &p) == 0) {
			حرر(u);
			حرر(h);
			حرر(p);
		}
	}
	(فراغ)convtime(s);
	(فراغ)a2port(s);
	{
		صحيح tun = 0;
		(فراغ)a2tun(s, &tun);
	}
	{
		صحيح ac = 0;
		حرف **av = عدم;
		إذا (argv_ورهايو(s, &ac, &av, 1) == 0) {
			حرف *پٺ = argv_assemble(ac, av);
			حرر(پٺ);
			argv_free(av, ac);
		}
	}
	{
		ثابت حرف *err = عدم;
		(فراغ)valid_domain(s, 0, &err);
	}
	(فراغ)valid_env_name(s);
	{
		uint64_t t = 0;
		(فراغ)parse_absolute_وقت(s, &t);
	}

	{
		بنية xaddr n;
		(فراغ)addr_pton(s, &n);
	}
	{
		بنية xaddr n;
		u_int اڳياڙي = 0;
		(فراغ)addr_pton_cidr(s, &n, &اڳياڙي);
	}

	(فراغ)addr_ميلاپ_list(a, b);
	(فراغ)addr_ميلاپ_cidr_list(a, b);
	(فراغ)ميلاپ_نمونو(a, b);
	(فراغ)ميلاپ_نمونو_list(a, b, 0);
	(فراغ)ميلاپ_hostname(a, b);
	(فراغ)ميلاپ_host_and_ip(a, "127.0.0.1", b);
	(فراغ)ميلاپ_user("fuzz", a, "127.0.0.1", b);

	حرر(s);
	حرر(a);
	حرر(b);
	أرجع 0;
}
