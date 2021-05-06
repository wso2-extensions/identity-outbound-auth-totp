/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.application.authenticator.totp.dao;

import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;

/**
 * TOTPSecretKeyDAO interface to handle TOTP secret key for federated user related DAO operations.
 */
public interface TOTPSecretKeyDAO {

    /**
     * Store secret key for federated user.
     *
     * @param userId    Federated user id.
     * @param secretKey TOTP Secret key of the federated user.
     * @throws TOTPException if an error occurs when storing the secret key for a federated user.
     */
    void setTOTPSecretKeyOfFederatedUser(String userId, String secretKey) throws TOTPException;

    /**
     * Get the secret key y the federated user id.
     *
     * @param userId Federated user id.
     * @return TOTP secret key of the federated user.
     * @throws TOTPException if an error occurs while retrieving the secret key of a federated user
     */
    String getTOTPSecretKeyOfFederatedUser(String userId) throws TOTPException;
}
