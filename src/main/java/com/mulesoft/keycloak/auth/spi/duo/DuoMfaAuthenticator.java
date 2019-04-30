/*
Copyright 2018 MuleSoft, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.mulesoft.keycloak.auth.spi.duo;

import com.duosecurity.duoweb.DuoWeb;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.Map;

import static com.mulesoft.keycloak.auth.spi.duo.DuoMfaAuthenticatorFactory.PROP_AKEY;
import static com.mulesoft.keycloak.auth.spi.duo.DuoMfaAuthenticatorFactory.PROP_APIHOST;
import static com.mulesoft.keycloak.auth.spi.duo.DuoMfaAuthenticatorFactory.PROP_IKEY;
import static com.mulesoft.keycloak.auth.spi.duo.DuoMfaAuthenticatorFactory.PROP_SKEY;

/**
 * {@link Authenticator} with support for MFA authentication with DUO Security.
 */
public class DuoMfaAuthenticator implements Authenticator {

    @Override
    public boolean requiresUser() {
        // No user-specific configuration needed
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // No user-specific configuration needed, therefore always "configured"
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // None - there is no enrollment within Keycloak (there may be enrollment within the Duo frame)
    }

    private Response createDuoForm(AuthenticationFlowContext context, String error) {

        DuoConfig config = DuoConfig.from(context);
        if (config == null) {
            return context.form()
                    .setError("Did you configure Duo in Keycloak?")
                    .createForm("duo-mfa.ftl");
        }

        String sig_request = DuoWeb.signRequest(config.ikey, config.skey, config.akey, context.getUser().getUsername());
        LoginFormsProvider form = context.form()
                .setAttribute("sig_request", sig_request)
                .setAttribute("apihost", config.apiHost);
        form.addScript("https://api.duosecurity.com/frame/hosted/Duo-Web-v2.js");
        if (error != null) {
            form.setError(error);
        } else if (sig_request.startsWith("ERR")) {
            form.setError("Did you configure Duo in Keycloak?\n" + sig_request);
        }
        return form.createForm("duo-mfa.ftl");
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(createDuoForm(context, null));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.resetFlow();
            return;
        }
        if (!formData.containsKey("sig_response")) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, createDuoForm(context, "missing sig_response"));
            return;
        }

        DuoConfig config = DuoConfig.from(context);
        if (config == null) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, createDuoForm(context, "invalid duo config"));
            return;
        }

        String sig_response = formData.getFirst("sig_response");
        String authenticated_username;
        try {
            authenticated_username = DuoWeb.verifyResponse(config.ikey, config.skey, config.akey, sig_response);
        } catch (Exception ex) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, createDuoForm(context, ex.getMessage()));
            return;
        }
        if (!authenticated_username.equals(context.getUser().getUsername())) {
            String error = "Wrong DUO user returned: " + authenticated_username + " (expected " + context.getUser().getUsername() + ")";
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, createDuoForm(context, error));
            return;
        }
        context.success();
    }

    @Override
    public void close() {
        // NOOP
    }

    static class DuoConfig {

        private final String ikey;

        private final String skey;

        private final String akey;

        private final String apiHost;

        DuoConfig(String ikey, String skey, String akey, String apiHost) {
            this.ikey = ikey;
            this.skey = skey;
            this.akey = akey;
            this.apiHost = apiHost;
        }

        static DuoConfig from(AuthenticationFlowContext context) {

            AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
            if (configModel == null) {
                return null;
            }

            Map<String, String> config = configModel.getConfig();

            return new DuoConfig(config.get(PROP_IKEY), config.get(PROP_SKEY), config.get(PROP_AKEY), config.get(PROP_APIHOST));
        }
    }

}
