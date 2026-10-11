package io.jenkins.plugins.googlegroupsoauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.security.FullControlOnceLoggedInAuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.Page;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Break-glass behavior: with the Google realm active, a pre-existing local user (created
 * under the local-database realm, as on the real controller) can still log in with username
 * and password through the standard login form, and the login page carries the
 * "Sign in with Google" button.
 */
@WithJenkins
public class HybridLoginTest {

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule rule) throws Exception {
        j = rule;
        // Simulate the migration: users exist from the local-database era...
        HudsonPrivateSecurityRealm localRealm = new HudsonPrivateSecurityRealm(false, false, null);
        j.jenkins.setSecurityRealm(localRealm);
        localRealm.createAccount("qaautomation", "hunter2");
        // ...then the realm is switched to Google OAuth.
        j.jenkins.setSecurityRealm(new GoogleGroupsSecurityRealm(
                "client-id", null, "example.com"));
    }

    @Test
    public void localPasswordLoginStillWorks() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();
        wc.login("qaautomation", "hunter2");
        assertEquals("qaautomation", wc.executeOnServer(
                () -> jenkins.model.Jenkins.getAuthentication2().getName()));
    }

    @Test
    public void wrongPasswordIsRejected() {
        JenkinsRule.WebClient wc = j.createWebClient();
        assertThrows(FailingHttpStatusCodeException.class, () -> wc.login("qaautomation", "wrong"));
    }

    @Test
    public void unknownUserIsRejected() {
        JenkinsRule.WebClient wc = j.createWebClient();
        assertThrows(FailingHttpStatusCodeException.class, () -> wc.login("nobody", "whatever"));
    }

    @Test
    public void loginPageShowsFormAndGoogleButton() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();
        HtmlPage login = wc.goTo("login");
        String content = login.getWebResponse().getContentAsString();
        assertTrue(content.contains("j_username"), "username/password form should be present");
        assertTrue(content.contains("securityRealm/commenceLogin"),
                "Google sign-in button should be present");
    }

    @Test
    public void googleButtonRendersSymbolAndStylesheetWithoutOverallRead() throws Exception {
        FullControlOnceLoggedInAuthorizationStrategy strategy = new FullControlOnceLoggedInAuthorizationStrategy();
        strategy.setAllowAnonymousRead(false);
        j.jenkins.setAuthorizationStrategy(strategy);

        JenkinsRule.WebClient wc = j.createWebClient();
        String content = wc.goTo("login").getWebResponse().getContentAsString();
        assertTrue(content.contains("fill=\"#4285F4\""), "Google symbol should be rendered inline");
        Matcher stylesheet = Pattern.compile("href=['\"]([^'\"]*/login-button\\.css)['\"]").matcher(content);
        assertTrue(stylesheet.find(), "button stylesheet should be linked");

        // The login page is shown to people who cannot read anything else yet.
        Page css = wc.getPage(new URL(j.getURL(), stylesheet.group(1)));
        assertEquals(200, css.getWebResponse().getStatusCode());
        assertTrue(css.getWebResponse().getContentAsString().contains(".google-groups-oauth-login"));
    }

    @Test
    public void apiTokenOfLocalUserStillAuthenticates() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();
        wc.login("qaautomation", "hunter2");
        String token = wc.executeOnServer(() -> hudson.model.User.getById("qaautomation", false)
                .getProperty(jenkins.security.ApiTokenProperty.class)
                .generateNewToken("test").plainValue);
        JenkinsRule.WebClient anonymous = j.createWebClient();
        anonymous.withBasicCredentials("qaautomation", token);
        assertTrue(anonymous.goTo("whoAmI/api/json", "application/json")
                .getWebResponse().getContentAsString().contains("\"qaautomation\""));
    }
}
