# FreeRDP: A Remote Desktop Protocol Implementation
# libfreerdp-crypto cmake build script
#
# Copyright 2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set(MODULE_NAME "freerdp-crypto")
set(MODULE_PREFIX "FREERDP_CRYPTO")

freerdp_module_add(
  er.c
  der.c
  ber.c
  per.c
  base64.c
  x509_utils.c
  x509_utils.h
  cert_common.h
  cert_common.c
  privatekey.c
  privatekey.h
  certificate.c
  certificate.h
  certificate_data.c
  certificate_store.c
  crypto.c
  tls.c
  tls.h
  opensslcompat.c
)

freerdp_include_directory_add(${OPENSSL_INCLUDE_DIR})

freerdp_library_add(${OPENSSL_LIBRARIES})

if(MBEDTLS_FOUND)
  freerdp_include_directory_add(${MBEDTLS_INCLUDE_DIR})
  freerdp_library_add(${MBEDTLS_LIBRARIES})
endif()

if(WIN32)
  freerdp_library_add(ws2_32)
endif()

if(BUILD_TESTING_INTERNAL OR BUILD_TESTING)
  add_subdirectory(test)
endif()
