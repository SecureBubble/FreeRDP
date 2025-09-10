/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Network Level Authentication (NLA)
 *
 * Copyright 2023 Armin Novak <anovak@thincast.com>
 * Copyright 2023 Thincast Technologies GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_UTILS_AAD_H
#define FREERDP_UTILS_AAD_H

/** \defgroup AAD AAD related helper utilities
 *  \since version 3.0.0
 */
#include <winpr/wlog.h>
#include <winpr/json.h>

#include <freerdp/api.h>
#include <freerdp/types.h>
#include <freerdp/config.h>

#ifdef __cplusplus
extern "C"
{
#endif

	/** @enum Expected wellknown fields to be supported
	 *  @since version 3.10.0
	 */
	typedef enum
	{
		AAD_WELLKNOWN_token_endpoint = 0,
		AAD_WELLKNOWN_token_endpoint_auth_methods_supported,
		AAD_WELLKNOWN_jwks_uri,
		AAD_WELLKNOWN_response_modes_supported,
		AAD_WELLKNOWN_subject_types_supported,
		AAD_WELLKNOWN_id_token_signing_alg_values_supported,
		AAD_WELLKNOWN_response_types_supported,
		AAD_WELLKNOWN_scopes_supported,
		AAD_WELLKNOWN_issuer,
		AAD_WELLKNOWN_request_uri_parameter_supported,
		AAD_WELLKNOWN_userinfo_endpoint,
		AAD_WELLKNOWN_authorization_endpoint,
		AAD_WELLKNOWN_device_authorization_endpoint,
		AAD_WELLKNOWN_http_logout_supported,
		AAD_WELLKNOWN_frontchannel_logout_supported,
		AAD_WELLKNOWN_end_session_endpoint,
		AAD_WELLKNOWN_claims_supported,
		AAD_WELLKNOWN_kerberos_endpoint,
		AAD_WELLKNOWN_tenant_region_scope,
		AAD_WELLKNOWN_cloud_instance_name,
		AAD_WELLKNOWN_cloud_graph_host_name,
		AAD_WELLKNOWN_msgraph_host,
		AAD_WELLKNOWN_rbac_url
	} AAD_WELLKNOWN_VALUES;

	/** Helper to retrieve the AAD access token from JSON input
	 *
	 *  @param data The JSON to parse
	 *  @param length The number of bytes of the JSON data
	 *
	 *  @since version 3.0.0
	 *
	 * @return The token string or \b NULL
	 */
	WINPR_ATTR_MALLOC(free, 1)
	FREERDP_API char* freerdp_utils_aad_get_access_token(wLog* log, const char* data,
	                                                     size_t length);

	/** Helper to stringify \ref AAD_WELLKNOWN_VALUES enum
	 *
	 *  @param which The enum value to stringify
	 *
	 *  @return The string representation of the enum value
	 *  @since version 3.10.0
	 */
	FREERDP_API const char* freerdp_utils_aad_wellknwon_value_name(AAD_WELLKNOWN_VALUES which);

	/** Helper to extract a string from AAD::wellknown JSON
	 *
	 * @param context The rdpContext to query for
	 * @param which The enum value of the field to query
	 *  @return A constant string to be used for queries or \b NULL in case it does not exist.
	 *
	 *  @since version 3.10.0
	 */
	FREERDP_API const char* freerdp_utils_aad_get_wellknown_string(rdpContext* context,
	                                                               AAD_WELLKNOWN_VALUES which);

	/** Helper to extract a string from AAD::wellknown JSON
	 *
	 * @param context The rdpContext to query for
	 * @param which The raw string name of the field to query
	 *  @return A constant string to be used for queries or \b NULL in case it does not exist.
	 *
	 *  @since version 3.10.0
	 */
	FREERDP_API const char* freerdp_utils_aad_get_wellknown_custom_string(rdpContext* context,
	                                                                      const char* which);

	/** Helper to extract a \b WINPR_JSON object from AAD::wellknown JSON
	 *
	 * @param context The rdpContext to query for
	 * @param which The enum value of the field to query
	 *  @return A \b WINPR_JSON object to be used for queries or \b NULL in case it does not exist.
	 *
	 *  @since version 3.10.0
	 */
	FREERDP_API WINPR_JSON* freerdp_utils_aad_get_wellknown_object(rdpContext* context,
	                                                               AAD_WELLKNOWN_VALUES which);

	/** Helper to extract a \b WINPR_JSON object from AAD::wellknown JSON
	 *
	 * @param context The rdpContext to query for
	 * @param which The raw string name of the field to query
	 *  @return A \b WINPR_JSON object to be used for queries or \b NULL in case it does not exist.
	 *
	 *  @since version 3.10.0
	 */
	FREERDP_API WINPR_JSON* freerdp_utils_aad_get_wellknown_custom_object(rdpContext* context,
	                                                                      const char* which);

	/** Helper to fetch a \b WINPR_JSON object from AAD/ARM::wellknown JSON
	 *
	 * @param  log A logger instance to use
	 * @param base the base URL to connect to
	 * @param tenantid the tenant to use for the connection, use \b common for default
	 *  @return A \b WINPR_JSON object to be used for queries or \b NULL in case it does not exist.
	 *
	 *  @since version 3.10.0
	 */
	WINPR_ATTR_MALLOC(WINPR_JSON_Delete, 1)
	FREERDP_API WINPR_JSON* freerdp_utils_aad_get_wellknown(wLog* log, const char* base,
	                                                        const char* tenantid);

	typedef struct FreeRDP_Aad_callbacks FreeRDP_Aad_callbacks;

	/** @brief various callbacks used during the AAD workflow
	 * @since 3.18.0
	 */
	struct FreeRDP_Aad_callbacks
	{
		/**
		 *
		 * @param context
		 * @return
		 */
		BOOL (*start)(rdpContext* context);

		/** handles the receiving of a server nonce (client impl)
		 *
		 * @param context associated rdpContext
		 * @param s the serverNone
		 * @return if the treatment was successful
		 */
		BOOL (*recvServerNonce)(rdpContext* context, wStream* s);

		/** forges a ServerNonce message (server impl)
		 *
		 * @param context associated rdpContext
		 * @return if the treatment was successful
		 */
		BOOL (*sendServerNonce)(rdpContext* context);

		/** handles the receiving of an auth request (server impl)
		 *
		 * @param context associated rdpContext
		 * @param s the auth request message
		 * @return if the treatment was successful
		 */
		BOOL (*recvAuthRequest)(rdpContext* context, wStream* s);

		/** sends an AuthRequest (client impl)
		 *
		 * @param context associated rdpContext
		 * @param ts_nonce the nonce
		 * @return if the treatment was successful
		 */
		BOOL (*sendAuthRequest)(rdpContext* context, const char* ts_nonce);

		/** handles the receiving of an auth result (client impl)
		 *
		 * @param context associated rdpContext
		 * @param s the auth result message
		 * @return if the treatment was successful
		 */
		BOOL (*recvAuthResponse)(rdpContext* context, wStream* s);

		/** sends an Auth response
		 *
		 * @param context associated rdpContext
		 * @return if the treatment was successful
		 */
		BOOL (*sendAuthResponse)(rdpContext* context);
	};

	/**
	 * install some AAD callbacks on the context
	 *
	 * @param context The rdpContext to install the AAD callbacks on
	 * @param cb the callbacks
	 *
	 *  @since version 3.18.0
	 */
	FREERDP_API void freerdp_utils_aad_set_callbacks(rdpContext* context,
	                                                 const FreeRDP_Aad_callbacks* cb);

	/**
	 * retrieves the installed AAD callbacks
	 *
	 * @param context The rdpContext to query AAD callbacks for
	 * @return the AAD callbacks
	 *
	 *  @since version 3.18.0
	 */
	FREERDP_API FreeRDP_Aad_callbacks freerdp_utils_aad_get_callbacks(rdpContext* context);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_UTILS_AAD_H */
