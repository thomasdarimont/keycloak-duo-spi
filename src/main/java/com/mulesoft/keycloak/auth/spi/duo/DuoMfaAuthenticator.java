package com.mulesoft.keycloak.auth.spi.duo;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import com.duosecurity.duoweb.DuoWeb;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import static com.mulesoft.keycloak.auth.spi.duo.DuoMfaAuthenticatorFactory.*;

public class DuoMfaAuthenticator implements Authenticator{
    private String akey;
    public DuoMfaAuthenticator() {
        try {
            // yay java `hashlib.sha256(os.urandom(32))`
            akey = new String(MessageDigest.getInstance("SHA256").digest(ByteBuffer.allocate(4).putInt(new Random().nextInt()).array()));
        } catch (NoSuchAlgorithmException ex) {
            throw new AuthenticationFlowException("Error initializing sha256", AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    @Override
    public boolean requiresUser() {
        // No user-specific configuration needed
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return session.userCredentialManager().isConfiguredFor(realm, user, DuoMfaAuthenticatorCredentialProvider.DUO_MFA);
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(createDuoForm(context, null));
    }

    private Response createDuoForm(AuthenticationFlowContext context, String error) {
        String sig_request = DuoWeb.signRequest(duoIkey(context), duoSkey(context), akey, context.getUser().getUsername());
        LoginFormsProvider form = context.form()
                .setAttribute("sig_request", sig_request)
                .setAttribute("apihost", duoApihost(context));
        form.addScript("https://api.duosecurity.com/frame/hosted/Duo-Web-v2.js");
        if (error != null) {
            form.setError(error);
        } else if (sig_request.startsWith("ERR")) {
            form.setError("Did you configure Duo in Keycloak?\n" + sig_request);
        }
        return form.createForm("duo-mfa.ftl");
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }
        if (!formData.containsKey("sig_response")) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, createDuoForm(context, "missing sig_response"));
            return;
        }
        String sig_response = formData.getFirst("sig_response");
        String authenticated_username = null;
        try {
            authenticated_username = DuoWeb.verifyResponse(duoIkey(context), duoSkey(context), akey, sig_response);
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
    public void close() {}

    private String duoIkey(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null) return "";
        return String.valueOf(config.getConfig().get(PROP_IKEY));
    }
    private String duoSkey(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null) return "";
        return String.valueOf(config.getConfig().get(PROP_SKEY));
    }
    private String duoApihost(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null) return "";
        return String.valueOf(config.getConfig().get(PROP_APIHOST));
    }

}
