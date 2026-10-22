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

#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>

ବାହ୍ୟ "C" ଶୂନ୍ୟ fuzz_one_message(ଅଚଳ uint8_t *data, size_t size);

ବାହ୍ୟ "C" ପୂର୍ଣ୍ଣସଂଖ୍ୟା
LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t *data, size_t size)
{
	fuzz_one_message(data, size);
	ଫେରନ୍ତୁ 0;
}
