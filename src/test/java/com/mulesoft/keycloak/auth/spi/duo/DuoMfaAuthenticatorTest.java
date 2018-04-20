package com.mulesoft.keycloak.auth.spi.duo;

import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.plugins.server.BaseHttpRequest;
import org.jboss.resteasy.spi.HttpRequest;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static com.mulesoft.keycloak.auth.spi.duo.DuoMfaAuthenticatorFactory.*;
import static org.mockito.Mockito.*;

import static org.junit.Assert.*;

public class DuoMfaAuthenticatorTest {
    @Test
    public void testAuthenticate() {
        UserModel u = mock(UserModel.class);
        when(u.getUsername()).thenReturn("username");

        LoginFormsProvider lfp = mock(LoginFormsProvider.class);
        when(lfp.setAttribute(anyString(), any())).thenReturn(lfp);

        Map<String, String> m = new HashMap<>(3);
        m.put(PROP_IKEY, "XXXXXXXXXXXXXXXXXXXX");
        m.put(PROP_SKEY, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        m.put(PROP_APIHOST, "api-99999999.duosecurity.com");

        AuthenticatorConfigModel t = mock(AuthenticatorConfigModel.class);
        when(t.getConfig()).thenReturn(m);

        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        when(context.getUser()).thenReturn(u);
        when(context.form()).thenReturn(lfp);
        when(context.getAuthenticatorConfig()).thenReturn(t);

        DuoMfaAuthenticator a = new DuoMfaAuthenticator();
        a.authenticate(context);

        verify(lfp, never()).setError(anyString());
    }

    /**
     * I have no idea how to make a sig_response that will actually verify.
     *
    @Test
    public void testAction() {
        UserModel u = mock(UserModel.class);
        when(u.getUsername()).thenReturn("username");

        LoginFormsProvider lfp = mock(LoginFormsProvider.class);
        when(lfp.setAttribute(anyString(), any())).thenReturn(lfp);

        Map<String, String> m = new HashMap<>(3);
        m.put(PROP_IKEY, "XXXXXXXXXXXXXXXXXXXX");
        m.put(PROP_SKEY, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        m.put(PROP_APIHOST, "api-99999999.duosecurity.com");

        AuthenticatorConfigModel t = mock(AuthenticatorConfigModel.class);
        when(t.getConfig()).thenReturn(m);

        MockHttpRequest r = MockHttpRequest.create("POST", URI.create(""), URI.create(""));
        r.addFormHeader("sig_response", "foo:bar");

        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        when(context.getUser()).thenReturn(u);
        when(context.form()).thenReturn(lfp);
        when(context.getAuthenticatorConfig()).thenReturn(t);
        when(context.getHttpRequest()).thenReturn(r);

        DuoMfaAuthenticator a = new DuoMfaAuthenticator();
        a.action(context);

        verify(lfp, never()).setError(anyString());
    }
    */
}