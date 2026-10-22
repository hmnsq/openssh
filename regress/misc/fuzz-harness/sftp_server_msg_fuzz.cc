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

#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>

बाह्य "C" शून्य fuzz_server_one(ध्रुव uint8_t *data, माप_प्रकार size);

बाह्य "C" पूर्णाङ्क
LLVMFuzzer_Test_One_निवेश(ध्रुव uint8_t *data, माप_प्रकार size)
{
	fuzz_server_one(data, size);
	प्रत्यागम 0;
}
