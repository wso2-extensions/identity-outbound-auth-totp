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

package org.wso2.carbon.identity.application.authenticator.totp.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.util.Hashtable;

/**
 * @scr.component name="identity.application.authenticator.totp.component" immediate="true"
 * @scr.reference name="config.context.service"
 * interface="org.wso2.carbon.utils.ConfigurationContextService"
 * cardinality="1..1" policy="dynamic" bind="setConfigurationContextService"
 * unbind="unsetConfigurationContextService"
 * @scr.reference name="user.realmservice.default" interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class TOTPAuthenticatorServiceComponent {

	private static Log log = LogFactory.getLog(TOTPAuthenticatorServiceComponent.class);

	/**
	 * This method is to register the TOTP authenticator service.
	 *
	 * @param ctxt The Component Context
	 */
	protected void activate(ComponentContext ctxt) {
		TOTPAuthenticator totpAuth = new TOTPAuthenticator();
		Hashtable<String, String> props = new Hashtable<String, String>();

		ctxt.getBundleContext()
		    .registerService(ApplicationAuthenticator.class.getName(), totpAuth, props);

		if (log.isDebugEnabled()) {
			log.debug("TOTPAuthenticator bundle is activated");
		}
	}

	/**
	 * This method is to deactivate the TOTP authenticator the service.
	 *
	 * @param ctxt The Component Context
	 */
	protected void deactivate(ComponentContext ctxt) {
		if (log.isDebugEnabled()) {
			log.debug("TOTPAuthenticator bundle is deactivated");
		}
	}

	/**
	 * This method is used to set the Configuration Context Service.
	 *
	 * @param configurationContextService The Configuration Context which needs to set
	 */
	protected void setConfigurationContextService(
			ConfigurationContextService configurationContextService) {
		TOTPDataHolder.getInstance().setConfigurationContextService(configurationContextService);
	}

	/**
	 * This method is used to unset the Configuration Context Service.
	 *
	 * @param configurationContextService The Configuration Context which needs to unset
	 */
	protected void unsetConfigurationContextService(
			ConfigurationContextService configurationContextService) {
		TOTPDataHolder.getInstance().setConfigurationContextService(null);
	}

	/**
	 * This method is used to set the Realm Service.
	 *
	 * @param realmService The Realm Service which needs to set
	 */
	protected void setRealmService(RealmService realmService) {
		TOTPDataHolder.getInstance().setRealmService(realmService);
	}

	/**
	 * This method is used to unset the Realm Service.
	 *
	 * @param realmService The Realm Service which needs to unset
	 */
	protected void unsetRealmService(RealmService realmService) {
		TOTPDataHolder.getInstance().setRealmService(null);
	}
}