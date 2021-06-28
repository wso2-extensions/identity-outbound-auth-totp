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

	/*
	 * Private Constructor will prevent the instantiation of this class directly.
	 */
	private TOTPAuthenticatorConstants() {
	}

	public static final String AUTHENTICATOR_FRIENDLY_NAME = "TOTP";
	public static final String AUTHENTICATOR_NAME = "totp";
	public static final String QR_CODE_CLAIM_URL = "http://wso2.org/claims/identity/qrcodeurl";
	public static final String SECRET_KEY_CLAIM_URL = "http://wso2.org/claims/identity/secretkey";
	public static final String VERIFY_SECRET_KEY_CLAIM_URL = "http://wso2.org/claims/identity/verifySecretkey";
	public static final String ENCODING_CLAIM_URL = "http://wso2.org/claims/identity/encoding";
	public static final String FIRST_NAME_CLAIM_URL = "http://wso2.org/claims/givenname";
	public static final String TOTP_FAILED_ATTEMPTS_CLAIM = "http://wso2.org/claims/identity/failedTotpAttempts";
	public static final String FAILED_LOGIN_LOCKOUT_COUNT_CLAIM =
			"http://wso2.org/claims/identity/failedLoginLockoutCount";
	public static final String ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";
	public static final String ACCOUNT_UNLOCK_TIME_CLAIM = "http://wso2.org/claims/identity/unlockTime";
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
	public static final String PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX = "account.lock.handler.On.Failure.Max.Attempts";
	public static final String PROPERTY_ACCOUNT_LOCK_TIME = "account.lock.handler.Time";
	public static final String ADMIN_INITIATED = "AdminInitiated";
	public static final String FEDERATED_USERNAME = "FederatedUsername";

	public static final String ENABLE_SEND_VERIFICATION_CODE_BY_EMAIL = "AllowSendingVerificationCodeByEmail";
}
