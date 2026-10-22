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

بیرونی "C" {
#شامل "addr.h"
#شامل "match.h"
#شامل "misc.h"
#شامل "log.h"
}

ایستا صحیح log_initialized = 0;

ایستا نویسه *
dup_n(ثابت uint8_t *body, size_t blen)
{
	نویسه *s = (نویسه *)malloc(blen + 1);
	اگر (s == پوچ)
		بازگشت پوچ;
	memcpy(s, body, blen);
	s[blen] = '\0';
	بازگشت s;
}

ایستا تهی
split_two(ثابت uint8_t *body, size_t blen, نویسه **a, نویسه **b)
{
	ثابت uint8_t *nul = (ثابت uint8_t *)memchr(body, 0, blen);
	*a = پوچ;
	*b = پوچ;
	اگر (nul == پوچ) {
		*a = dup_n(body, blen);
		*b = strdup("");
		بازگشت;
	}
	size_t alen = (size_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

بیرونی "C" صحیح
LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t *data, size_t size)
{
	اگر (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	اگر (size == 0)
		بازگشت 0;

	نویسه *s = dup_n(data, size);
	نویسه *a = پوچ, *b = پوچ;
	split_two(data, size, &a, &b);
	اگر (s == پوچ || a == پوچ || b == پوچ) {
		آزاد(s);
		آزاد(a);
		آزاد(b);
		بازگشت 0;
	}

	{
		نویسه *u = پوچ, *h = پوچ;
		صحیح port = 0;
		اگر (parse_user_host_port(s, &u, &h, &port) == 0) {
			آزاد(u);
			آزاد(h);
		}
	}
	{
		نویسه *u = پوچ, *h = پوچ, *p = پوچ;
		صحیح port = 0;
		اگر (parse_uri("ssh", s, &u, &h, &port, &p) == 0) {
			آزاد(u);
			آزاد(h);
			آزاد(p);
		}
	}
	(تهی)convtime(s);
	(تهی)a2port(s);
	{
		صحیح tun = 0;
		(تهی)a2tun(s, &tun);
	}
	{
		صحیح ac = 0;
		نویسه **av = پوچ;
		اگر (argv_split(s, &ac, &av, 1) == 0) {
			نویسه *back = argv_assemble(ac, av);
			آزاد(back);
			argv_free(av, ac);
		}
	}
	{
		ثابت نویسه *err = پوچ;
		(تهی)valid_domain(s, 0, &err);
	}
	(تهی)valid_env_name(s);
	{
		uint64_t t = 0;
		(تهی)parse_absolute_time(s, &t);
	}

	{
		ساختار xaddr n;
		(تهی)addr_pton(s, &n);
	}
	{
		ساختار xaddr n;
		u_int prefix = 0;
		(تهی)addr_pton_cidr(s, &n, &prefix);
	}

	(تهی)addr_match_list(a, b);
	(تهی)addr_match_cidr_list(a, b);
	(تهی)match_pattern(a, b);
	(تهی)match_pattern_list(a, b, 0);
	(تهی)match_hostname(a, b);
	(تهی)match_host_and_ip(a, "127.0.0.1", b);
	(تهی)match_user("fuzz", a, "127.0.0.1", b);

	آزاد(s);
	آزاد(a);
	آزاد(b);
	بازگشت 0;
}
