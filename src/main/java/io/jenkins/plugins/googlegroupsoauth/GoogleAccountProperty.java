package io.jenkins.plugins.googlegroupsoauth;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import net.sf.json.JSONObject;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerRequest2;

/**
 * Binds a Jenkins user record to the Google account that signs in with its email, and records
 * when that account last signed in. Maintained only by {@link GoogleGroupsSecurityRealm}; there
 * is no UI.
 *
 * <ul>
 *   <li>{@link #getSubject()} is the ID token {@code sub} claim, Google's stable account id.
 *       User ids are emails, and Google can reassign an email to a different account (deleted
 *       user, reused address). Without this binding the new account would inherit the old
 *       record's API tokens, user-scoped credentials and {@code user:} grants.</li>
 *   <li>{@link #getLastLoginMillis()} bounds how long group authorities recorded at login are
 *       trusted for API-token requests (see
 *       {@link GoogleGroupsSecurityRealm#getGroupAuthorityMaxAgeDays()}).</li>
 * </ul>
 */
@Restricted(NoExternalUse.class)
public class GoogleAccountProperty extends UserProperty {

    private final String subject;
    private final long lastLoginMillis;

    public GoogleAccountProperty(@NonNull String subject, long lastLoginMillis) {
        this.subject = subject;
        this.lastLoginMillis = lastLoginMillis;
    }

    @NonNull
    public String getSubject() {
        return subject;
    }

    public long getLastLoginMillis() {
        return lastLoginMillis;
    }

    /** No UI: keep the same object when the user saves their profile. */
    @Override
    public UserProperty reconfigure(StaplerRequest2 req, JSONObject form) {
        return this;
    }

    @Extension
    public static final class DescriptorImpl extends UserPropertyDescriptor {
        @Override
        public boolean isEnabled() {
            return false;
        }

        @Override
        public UserProperty newInstance(User user) {
            return null;
        }
    }
}
