package io.jenkins.plugins.googlegroupsoauth;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.User;
import hudson.tasks.Mailer;
import java.io.IOException;
import java.util.Locale;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Profile claims extracted from the verified Google ID token, applied to the Jenkins
 * {@link User} record (display name, email property).
 */
@Restricted(NoExternalUse.class)
public class GoogleUserInfo {

    private final String subject;
    private final String email;
    @CheckForNull
    private final String name;

    public GoogleUserInfo(@NonNull GoogleIdToken.Payload payload) {
        this.subject = payload.getSubject();
        this.email = payload.getEmail().toLowerCase(Locale.ROOT);
        Object nameClaim = payload.get("name");
        this.name = nameClaim instanceof String s && !s.isBlank() ? s : null;
    }

    /** Google's stable account id (the {@code sub} claim); unlike the email it is never reassigned. */
    @NonNull
    public String getSubject() {
        return subject;
    }

    @NonNull
    public String getEmail() {
        return email;
    }

    @CheckForNull
    public String getName() {
        return name;
    }

    public void updateProfile(@NonNull User user) throws IOException {
        if (name != null) {
            user.setFullName(name);
        }
        user.addProperty(new Mailer.UserProperty(email));
        user.save();
    }
}
