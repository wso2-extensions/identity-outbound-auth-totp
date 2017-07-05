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
package org.wso2.carbon.identity.application.authenticator.totp.services;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPKeyGenerator;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;

/**
 * This class is used to initiate, reset the TOTP and refresh the secret key.
 *
 * @since 2.0.3
 */
public class TOTPAdminService {

	/**
	 * Generate TOTP Token for a given user.
	 *
	 * @param username Username of the user
	 * @param context  Authentication context
	 * @return Encoded QR Code URL.
	 * @throws TOTPException when could not find the user
	 */
	public String initTOTP(String username, AuthenticationContext context) throws TOTPException {
		return TOTPKeyGenerator.createUrlWithQRCode(username, false, context);
	}

	/**
	 * Resets TOTP credentials of the user.
	 *
	 * @param username Username of the user
	 * @return true, if successfully resets
	 * @throws TOTPException when could not find the user
	 */
	public boolean resetTOTP(String username) throws TOTPException, AuthenticationFailedException {
		return TOTPKeyGenerator.resetLocal(username);
	}

	/**
	 * Refreshes TOTP secret key of the user.
	 *
	 * @param username Username of the user
	 * @param context  Authentication context
	 * @return Encoded QR Code URL for refreshed secret key
	 * @throws TOTPException when could not find the user
	 */
	public String refreshSecretKey(String username, AuthenticationContext context)
			throws TOTPException {
		return TOTPKeyGenerator.createUrlWithQRCode(username, true, context);
	}
}