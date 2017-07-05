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

package org.wso2.carbon.identity.application.authenticator.totp.util;

import java.util.ArrayList;
import java.util.List;

/**
 * TOTP Authenticator Key.
 *
 * @since 2.0.3
 */
public class TOTPAuthenticatorKey {
	/**
	 * The secret key in Base32 encoding.
	 */
	private final String key;

	/**
	 * The verification code at time = 0 (the UNIX epoch).
	 */
	private final int verificationCode;

	/**
	 * The constructor with package visibility.
	 *
	 * @param secretKey the secret key in Base32 encoding.
	 * @param code      the verification code at time = 0 (the UNIX epoch).
	 */
	TOTPAuthenticatorKey(String secretKey, int code) {
		key = secretKey;
		verificationCode = code;
	}

	/**
	 * Returns the secret key in Base32 encoding.
	 *
	 * @return the secret key in Base32 encoding.
	 */
	public String getKey() {
		return key;
	}

}