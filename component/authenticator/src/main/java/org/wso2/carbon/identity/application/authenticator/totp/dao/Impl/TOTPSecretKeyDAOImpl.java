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
package org.wso2.carbon.identity.application.authenticator.totp.dao.Impl;

import org.wso2.carbon.identity.application.authenticator.totp.dao.TOTPSecretKeyDAO;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.util.SQLQueries;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Default implementation of {@link TOTPSecretKeyDAO}. This handles DB operations related to configuring TOTP
 * for the federated users.
 */
public class TOTPSecretKeyDAOImpl implements TOTPSecretKeyDAO {

    @Override
    public void setTOTPSecretKeyOfFederatedUser(String userId, String secretKey) throws TOTPException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement preparedStatement = connection
                    .prepareStatement(SQLQueries.SQL_INSERT_TOTP_SECRET_KEY)) {
                preparedStatement.setString(1, userId);
                preparedStatement.setString(2, secretKey);
                preparedStatement.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e1) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new TOTPException("Error when store secret key for the federated user: " + userId, e1);
            }
        } catch (SQLException e) {
            throw new TOTPException("Error while storing secret key against federated user id: " + userId, e);
        }
    }

    @Override
    public String getTOTPSecretKeyOfFederatedUser(String userId) throws TOTPException {

        String secretKey = null;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement preparedStatement = connection
                    .prepareStatement(SQLQueries.SQL_SELECT_SECRET_KEY_OF_USER_ID)) {
                preparedStatement.setString(1, userId);
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    if (resultSet.next()) {
                        secretKey = resultSet.getString(1);
                    }
                }
            }
        } catch (SQLException e) {
            throw new TOTPException("Error while getting the secret key against federated user id: " + userId, e);
        }
        return secretKey;
    }
}
