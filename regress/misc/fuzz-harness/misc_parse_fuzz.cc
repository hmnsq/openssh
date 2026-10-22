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

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

extern "C" {
#include "addr.h"
#include "match.h"
#include "misc.h"
#include "log.h"
}

static ကိန်းပြည့် log_initialized = 0;

static var_na *
dup_n(const uint8_t *body, size_t blen)
{
	var_na *s = (var_na *)malloc(blen + 1);
	အကယ်၍ (s == NULL)
		ပြန်ပေး NULL;
	memcpy(s, body, blen);
	s[blen] = '\0';
	ပြန်ပေး s;
}

static void
split_two(const uint8_t *body, size_t blen, var_na **a, var_na **b)
{
	const uint8_t *nul = (const uint8_t *)memchr(body, 0, blen);
	*a = NULL;
	*b = NULL;
	အကယ်၍ (nul == NULL) {
		*a = dup_n(body, blen);
		*b = strdup("");
		ပြန်ပေး;
	}
	size_t alen = (size_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

extern "C" ကိန်းပြည့်
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	အကယ်၍ (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	အကယ်၍ (size == 0)
		ပြန်ပေး 0;

	var_na *s = dup_n(data, size);
	var_na *a = NULL, *b = NULL;
	split_two(data, size, &a, &b);
	အကယ်၍ (s == NULL || a == NULL || b == NULL) {
		free(s);
		free(a);
		free(b);
		ပြန်ပေး 0;
	}

	{
		var_na *u = NULL, *h = NULL;
		ကိန်းပြည့် port = 0;
		အကယ်၍ (parse_user_host_port(s, &u, &h, &port) == 0) {
			free(u);
			free(h);
		}
	}
	{
		var_na *u = NULL, *h = NULL, *p = NULL;
		ကိန်းပြည့် port = 0;
		အကယ်၍ (parse_uri("ssh", s, &u, &h, &port, &p) == 0) {
			free(u);
			free(h);
			free(p);
		}
	}
	(void)convtime(s);
	(void)a2port(s);
	{
		ကိန်းပြည့် tun = 0;
		(void)a2tun(s, &tun);
	}
	{
		ကိန်းပြည့် ac = 0;
		var_na **av = NULL;
		အကယ်၍ (argv_split(s, &ac, &av, 1) == 0) {
			var_na *back = argv_assemble(ac, av);
			free(back);
			argv_free(av, ac);
		}
	}
	{
		const var_na *err = NULL;
		(void)valid_domain(s, 0, &err);
	}
	(void)valid_env_name(s);
	{
		uint64_t t = 0;
		(void)parse_absolute_time(s, &t);
	}

	{
		sa_nracanaa xaddr n;
		(void)addr_pton(s, &n);
	}
	{
		sa_nracanaa xaddr n;
		u_int prefix = 0;
		(void)addr_pton_cidr(s, &n, &prefix);
	}

	(void)addr_match_list(a, b);
	(void)addr_match_cidr_list(a, b);
	(void)match_pattern(a, b);
	(void)match_pattern_list(a, b, 0);
	(void)match_hostname(a, b);
	(void)match_host_and_ip(a, "127.0.0.1", b);
	(void)match_user("fuzz", a, "127.0.0.1", b);

	free(s);
	free(a);
	free(b);
	ပြန်ပေး 0;
}
