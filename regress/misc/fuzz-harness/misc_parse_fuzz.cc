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

#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <sys/types.h>

బాహ్య "C" {
#అన్తర్భావ "addr.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "log.h"
}

స్థిర పూర్ణాంకం log_initialized = 0;

స్థిర అక్షరం *
dup_n(స్థిరరాశి uint8_t *body, కొలత_t blen)
{
	అక్షరం *s = (అక్షరం *)జ్ఞాపకం_ఇవ్వు(blen + 1);
	ఒకవేళ (s == ఖాళీ)
		తిరిగి ఖాళీ;
	జ్ఞాపకం_నకలు(s, body, blen);
	s[blen] = '\0';
	తిరిగి s;
}

స్థిర శూన్య
విభజించు_two(స్థిరరాశి uint8_t *body, కొలత_t blen, అక్షరం **a, అక్షరం **b)
{
	స్థిరరాశి uint8_t *nul = (స్థిరరాశి uint8_t *)memchr(body, 0, blen);
	*a = ఖాళీ;
	*b = ఖాళీ;
	ఒకవేళ (nul == ఖాళీ) {
		*a = dup_n(body, blen);
		*b = strdup("");
		తిరిగి;
	}
	కొలత_t alen = (కొలత_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

బాహ్య "C" పూర్ణాంకం
LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత)
{
	ఒకవేళ (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	ఒకవేళ (కొలత == 0)
		తిరిగి 0;

	అక్షరం *s = dup_n(దత్తాంశం, కొలత);
	అక్షరం *a = ఖాళీ, *b = ఖాళీ;
	విభజించు_two(దత్తాంశం, కొలత, &a, &b);
	ఒకవేళ (s == ఖాళీ || a == ఖాళీ || b == ఖాళీ) {
		విడుదల(s);
		విడుదల(a);
		విడుదల(b);
		తిరిగి 0;
	}

	{
		అక్షరం *u = ఖాళీ, *h = ఖాళీ;
		పూర్ణాంకం పోర్టు = 0;
		ఒకవేళ (parse_user_host_పోర్టు(s, &u, &h, &పోర్టు) == 0) {
			విడుదల(u);
			విడుదల(h);
		}
	}
	{
		అక్షరం *u = ఖాళీ, *h = ఖాళీ, *p = ఖాళీ;
		పూర్ణాంకం పోర్టు = 0;
		ఒకవేళ (parse_uri("ssh", s, &u, &h, &పోర్టు, &p) == 0) {
			విడుదల(u);
			విడుదల(h);
			విడుదల(p);
		}
	}
	(శూన్య)convtime(s);
	(శూన్య)a2port(s);
	{
		పూర్ణాంకం tun = 0;
		(శూన్య)a2tun(s, &tun);
	}
	{
		పూర్ణాంకం ac = 0;
		అక్షరం **av = ఖాళీ;
		ఒకవేళ (argv_విభజించు(s, &ac, &av, 1) == 0) {
			అక్షరం *వెనుక = argv_assemble(ac, av);
			విడుదల(వెనుక);
			argv_free(av, ac);
		}
	}
	{
		స్థిరరాశి అక్షరం *err = ఖాళీ;
		(శూన్య)valid_domain(s, 0, &err);
	}
	(శూన్య)valid_env_name(s);
	{
		uint64_t t = 0;
		(శూన్య)parse_absolute_సమయం(s, &t);
	}

	{
		నిర్మాణం xaddr n;
		(శూన్య)addr_pton(s, &n);
	}
	{
		నిర్మాణం xaddr n;
		u_int ఉపసర్గ = 0;
		(శూన్య)addr_pton_cidr(s, &n, &ఉపసర్గ);
	}

	(శూన్య)addr_సరిపోలిక_list(a, b);
	(శూన్య)addr_సరిపోలిక_cidr_list(a, b);
	(శూన్య)సరిపోలిక_నమూనా(a, b);
	(శూన్య)సరిపోలిక_నమూనా_list(a, b, 0);
	(శూన్య)సరిపోలిక_hostname(a, b);
	(శూన్య)సరిపోలిక_host_and_ip(a, "127.0.0.1", b);
	(శూన్య)సరిపోలిక_user("fuzz", a, "127.0.0.1", b);

	విడుదల(s);
	విడుదల(a);
	విడుదల(b);
	తిరిగి 0;
}
