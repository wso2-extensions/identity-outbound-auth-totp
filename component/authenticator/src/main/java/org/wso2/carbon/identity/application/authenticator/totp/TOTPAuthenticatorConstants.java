/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.totp;

/**
 * TOTP Authenticator Constants.
 *
 * @since 2.0.3
 */
public abstract class TOTPAuthenticatorConstants {

	public static final String TOTP_AUTHENTICATOR = "totp.authenticator";

	/*
	 * Private Constructor will prevent the instantiation of this class directly.
	 */
	private TOTPAuthenticatorConstants() {
	}

	public static final String USER_PROMPT = "USER_PROMPT";
	public static final String AUTHENTICATOR_FRIENDLY_NAME = "TOTP";
	public static final String AUTHENTICATOR_NAME = "totp";
	public static final String AUTHENTICATOR_TOTP = "authenticator.totp";
	public static final String QR_CODE_CLAIM_URL = "http://wso2.org/claims/identity/qrcodeurl";
	public static final String SECRET_KEY_CLAIM_URL = "http://wso2.org/claims/identity/secretkey";
	public static final String TOTP_ENABLED_CLAIM_URI = "http://wso2.org/claims/identity/totpEnabled";
	public static final String VERIFY_SECRET_KEY_CLAIM_URL = "http://wso2.org/claims/identity/verifySecretkey";
	public static final String ENCODING_CLAIM_URL = "http://wso2.org/claims/identity/encoding";
	public static final String FIRST_NAME_CLAIM_URL = "http://wso2.org/claims/givenname";
	public static final String LAST_NAME_CLAIM_URL = "http://wso2.org/claims/lastname";
	public static final String TOTP_FAILED_ATTEMPTS_CLAIM = "http://wso2.org/claims/identity/failedTotpAttempts";
	public static final String FAILED_LOGIN_LOCKOUT_COUNT_CLAIM =
			"http://wso2.org/claims/identity/failedLoginLockoutCount";
	public static final String ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";
	public static final String ACCOUNT_UNLOCK_TIME_CLAIM = "http://wso2.org/claims/identity/unlockTime";
	public static final String ACCOUNT_LOCKED_REASON_CLAIM_URI = "http://wso2.org/claims/identity/lockedReason";
	public static final String BASE32 = "Base32";
	public static final String BASE64 = "Base64";
	public static final String APPLICATION_AUTHENTICATION_XML = "application-authentication.xml";
	public static final String NAME = "name";
	public static final String HMAC_ALGORITHM = "HmacSHA1";
	public static final String EMAIL_TEMPLATE_NAME = "totp";
	public static final String TRANSPORT_MAILTO = "mailto";
	public static final String EMAIL_CLAIM_URL = "http://wso2.org/claims/emailaddress";
	public static final String LOGIN_PAGE = "authenticationendpoint/login.do";

	public static final String TOTP_LOGIN_PAGE = "authenticationendpoint/totp.do";
	public static final String ERROR_PAGE = "authenticationendpoint/totp_error.do";
	public static final String ENABLE_TOTP_REQUEST_PAGE = "authenticationendpoint/totp_enroll.do";

	public static final String TOKEN = "token";
	public static final String DISPLAY_TOKEN = "Token";
	public static final String SEND_TOKEN = "sendToken";
	public static final String AUTHENTICATION = "authentication";
	public static final String BASIC = "basic";
	public static final String FEDERETOR = "federator";
	public static final String SUPER_TENANT_DOMAIN = "carbon.super";
	public static final String GET_PROPERTY_FROM_IDENTITY_CONFIG = "getPropertiesFromLocal";
	public static final String WINDOW_SIZE = "windowSize";
	public static final String ENROL_USER_IN_AUTHENTICATIONFLOW = "enrolUserInAuthenticationFlow";
	public static final String TIME_STEP_SIZE = "timeStepSize";
	public static final String ENCODING_METHOD = "encodingMethod";
	public static final String ENABLE_TOTP = "ENABLE_TOTP";
	public static final String SUPER_TENANT = "carbon.super";
	public static final String TOTP_AUTHENTICATION_ENDPOINT_URL = "TOTPAuthenticationEndpointURL";
	public static final String TOTP_ISSUER = "Issuer";
	public static final String TOTP_COMMON_ISSUER = "UseCommonIssuer";
	public static final String TOTP_HIDE_USERSTORE_FROM_USERNAME = "HideUserStoreFromDisplayInQRUrl";
	public static final String TOTP_AUTHENTICATION_ERROR_PAGE_URL = "TOTPAuthenticationEndpointErrorPage";
	public static final String ENABLE_TOTP_REQUEST_PAGE_URL = "TOTPAuthenticationEndpointEnableTOTPPage";
	public static final String USE_EVENT_HANDLER_BASED_EMAIL_SENDER = "useEventHandlerBasedEmailSender";
	public static final String TEMPLATE_TYPE = "TEMPLATE_TYPE";
	public static final String EVENT_NAME = "TOTP";
	public static final String AUTHENTICATED_USER = "authenticatedUser";
	public static final String LOCAL_AUTHENTICATOR = "LOCAL";
	public static final String ENABLE_ACCOUNT_LOCKING_FOR_FAILED_ATTEMPTS = "EnableAccountLockingForFailedAttempts";
	public static final String PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO = "account.lock.handler.login.fail.timeout.ratio";
	public static final String PROPERTY_ACCOUNT_LOCK_ON_FAILURE = "account.lock.handler.enable";
	public static final String PROPERTY_ACCOUNT_LOCK_ON_FAILURE_ENABLE =
			"account.lock.handler.lock.on.max.failed.attempts.enable";
	public static final String PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX = "account.lock.handler.On.Failure.Max.Attempts";
	public static final String PROPERTY_ACCOUNT_LOCK_TIME = "account.lock.handler.Time";
	public static final String LOGIN_FAIL_MESSAGE = "login.fail.message";
	public static final String ADMIN_INITIATED = "AdminInitiated";
	public static final String FEDERATED_USERNAME = "FederatedUsername";

	public static final String ENABLE_SEND_VERIFICATION_CODE_BY_EMAIL = "AllowSendingVerificationCodeByEmail";

	public static final String IS_INITIAL_FEDERATED_USER_ATTEMPT = "isInitialFederationAttempt";

	public static final String TOTP_AUTHENTICATOR_ERROR_PREFIX = "TPA";

	public static final String MAX_TOTP_ATTEMPTS_EXCEEDED = "MAX_TOTP_ATTEMPTS_EXCEEDED";

	public static final String CONF_SHOW_AUTH_FAILURE_REASON = "showAuthFailureReason";
	public static final String CONF_SHOW_AUTH_FAILURE_REASON_ON_LOGIN_PAGE = "showAuthFailureReasonOnLoginPage";
	public static final String CONF_ACC_LOCK_AUTH_FAILURE_MSG = "accountLockAuthFailureMessage";
	public static final String ERROR_CODE = "errorCode";
	public static final String UNLOCK_TIME = "unlockTime";
	public static final String LOCKED_REASON = "lockedReason";

	// This constant has been defined in FrameworkConstants class in framework repo as well. Hence, when changing this
	// value make sure to change it there as well.
	public static final String ENABLE_ENCRYPTION = "EnableEncryption";

	// Branding constants to resolve TOTP issuer.
	public static final String PATH_TO_IS_BRANDING_ENABLED = "/configs/isBrandingEnabled";
	public static final String PATH_TO_ORG_DISPLAY_NAME = "/organizationDetails/displayName";

	/**
	 * Constants related to log management.
	 */
	public static class LogConstants {

		public static final String TOTP_AUTH_SERVICE = "local-auth-totp";

		/**
		 * Define action IDs for diagnostic logs.
		 */
		public static class ActionIDs {

			public static final String PROCESS_AUTHENTICATION_RESPONSE = "process-totp-authentication-response";
			public static final String INITIATE_TOTP_REQUEST = "initiate-totp-authentication-request";
		}
	}

	/**
	 * Enum which contains the error codes and corresponding error messages.
	 */
	public enum ErrorMessages {

		ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR("65001", "No IDP found with the name IDP: " +
				"%s in tenant: %s"),
		ERROR_CODE_NO_FEDERATED_USER("65002", "No federated user found"),
		ERROR_CODE_INVALID_FEDERATED_USER_AUTHENTICATION("65003", "Can not handle federated user " +
				"authentication with TOTP as JIT Provision is not enabled for the IDP: in the tenant: %s"),
		ERROR_CODE_NO_AUTHENTICATED_USER("65004", "Can not find the authenticated user"),
		ERROR_CODE_NO_USER_TENANT("65005", "Can not find the authenticated user's tenant domain");

		private final String code;
		private final String message;

		ErrorMessages(String code, String message) {

			this.code = code;
			this.message = message;
		}

		public String getCode() {

			return TOTP_AUTHENTICATOR_ERROR_PREFIX + "-" + code;
		}

		public String getMessage() {

			return message;
		}

		@Override
		public String toString() {

			return code + " - " + message;
		}
	}
}
