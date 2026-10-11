package io.jenkins.plugins.googlegroupsoauth;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.security.FederatedLoginService;
import hudson.security.FederatedLoginServiceUserProperty;
import jenkins.model.Jenkins;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Adds the "Sign in with Google" button to the standard Jenkins login page (core's
 * {@code login.jelly} includes {@code loginFragment.jelly} of every registered
 * {@link FederatedLoginService}). The username/password form above the button stays fully
 * functional as the break-glass path — see
 * {@link GoogleGroupsSecurityRealm#authenticate2(String, String)}.
 *
 * <p>Only the login-page fragment of the {@link FederatedLoginService} contract is used;
 * the identity-claiming machinery ({@link #getUserPropertyClass()}) is not.
 */
@Restricted(NoExternalUse.class)
@Extension
public class GoogleFederatedLoginService extends FederatedLoginService {

    /** The fragment renders only when this plugin's realm is actually active. */
    public boolean isEnabled() {
        return Jenkins.get().getSecurityRealm() instanceof GoogleGroupsSecurityRealm;
    }

    @Override
    public String getUrlName() {
        return "googleGroupsOAuth";
    }

    @Override
    @SuppressFBWarnings(
            value = "NP_NONNULL_RETURN_VIOLATION",
            justification = "Identity claiming is not used: Google logins map to Jenkins users by email"
                    + " directly in the realm; core only touches this class during claim flows we never offer")
    public Class<? extends FederatedLoginServiceUserProperty> getUserPropertyClass() {
        return null;
    }
}
