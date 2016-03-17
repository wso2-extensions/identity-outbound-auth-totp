/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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


import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;

/**
 * TOTPManager implementation class.
 */
public class TOTPManagerImpl implements TOTPManager {

	private TOTPKeyGenerator totpKeyGenerator;
	private TOTPTokenGenerator totpTokenGenerator;
	private TOTPAccessController totpAccessController;
	private TOTPTokenVerifier totpTokenVerifier;

	public TOTPManagerImpl() {
		this.totpKeyGenerator = TOTPKeyGenerator.getInstance();
		this.totpTokenGenerator = TOTPTokenGenerator.getInstance();
		this.totpAccessController = TOTPAccessController.getInstance();
		this.totpTokenVerifier = TOTPTokenVerifier.getInstance();
	}

	@Override
	public TOTPDTO generateTOTPKeyLocal(String username) throws TOTPException {
        return totpKeyGenerator.generateTOTPKeyLocal(username);
	}

	@Override
	public String generateTOTPTokenLocal(String username) throws TOTPException {
		return totpTokenGenerator.generateTOTPTokenLocal(username);
	}

	@Override
	public boolean isTOTPEnabledForLocalUser(String username) throws TOTPException {
        return totpAccessController.isTOTPEnabledForLocalUser(username);
	}

	@Override
	public boolean isValidTokenLocalUser(int token, String username) throws TOTPException {
        return totpTokenVerifier.isValidTokenLocalUser(token, username);
	}

	@Override
	public String[] getSupportedEncodingMethods() {
		return new String[]{TOTPAuthenticatorConstants.BASE32, TOTPAuthenticatorConstants.BASE64};
	}

	@Override
	public String[] getSupportedHashingMethods() {
		return new String[]{TOTPAuthenticatorConstants.SHA1, TOTPAuthenticatorConstants.MD5};
	}


}
