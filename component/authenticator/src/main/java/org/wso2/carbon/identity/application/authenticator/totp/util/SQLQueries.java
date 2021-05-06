/*
 *   Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.identity.application.authenticator.totp.util;

/**
 * This class holds the SQL queries used by TOTPAuthenticator.
 */
public class SQLQueries {

    public static final String SQL_INSERT_TOTP_SECRET_KEY =
            "INSERT INTO IDN_FEDERATED_USER_TOTP_SECRET_KEY(USER_ID, SECRET_KEY) VALUES (?,?)";

    public static final String SQL_SELECT_SECRET_KEY_OF_USER_ID =
            "SELECT SECRET_KEY FROM IDN_FEDERATED_USER_TOTP_SECRET_KEY WHERE USER_ID = ?";
}
