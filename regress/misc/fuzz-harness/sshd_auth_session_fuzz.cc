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

#समावेश <stddef.h>
#समावेश <stdint.h>

बाह्य "C" व्योम fuzz_userauth_one(स्थिर uint8_t *तथ्य, माप_प्रकार आकार);

बाह्य "C" पूर्णांक
LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t *तथ्य, माप_प्रकार आकार)
{
	fuzz_userauth_one(तथ्य, आकार);
	वापस 0;
}
