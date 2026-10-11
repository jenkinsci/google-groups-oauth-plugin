package io.jenkins.plugins.googlegroupsoauth;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ProxyConfiguration;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import jenkins.model.Jenkins;
import jenkins.model.JenkinsLocationConfiguration;
import jenkins.security.LastGrantedAuthoritiesProperty;
import jenkins.security.SecurityListener;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Hybrid security realm: sign in with Google OAuth (with the user's direct Google Group
 * memberships — group emails — as Jenkins authorities) <b>or</b> with a local username and
 * password. Group resolution uses the logged-in user's own OAuth token against the Cloud
 * Identity API — no service account or Workspace admin grant needed.
 *
 * <p>The standard Jenkins login page is kept: its username/password form is checked against
 * the {@link HudsonPrivateSecurityRealm.Details} property stored on existing local user
 * records (created under the local-database realm), which is the break-glass path if Google
 * OAuth is down or misconfigured. {@link GoogleFederatedLoginService} adds the
 * "Sign in with Google" button underneath that form.
 *
 * <p>Google user id = full email (lowercase), bound to the Google account's stable {@code sub}
 * on first login ({@link GoogleAccountProperty}). Authorities are re-resolved at each Google
 * login and live for the session; API-token requests get the authorities recorded at the
 * user's last Google login via {@link LastGrantedAuthoritiesProperty}, but only for
 * {@link #getGroupAuthorityMaxAgeDays()} days, because Jenkins cannot see later removals from
 * Google Groups or from the Workspace.
 * Pre-existing local users' API tokens keep working because token authentication checks
 * stored user records independent of this realm.
 */
public class GoogleGroupsSecurityRealm extends AbstractPasswordBasedSecurityRealm {

    private static final Logger LOGGER = Logger.getLogger(GoogleGroupsSecurityRealm.class.getName());

    private static final String SESSION_STATE = GoogleGroupsSecurityRealm.class.getName() + ".state";
    private static final String SESSION_PKCE_VERIFIER = GoogleGroupsSecurityRealm.class.getName() + ".pkceVerifier";
    private static final String SESSION_FROM = GoogleGroupsSecurityRealm.class.getName() + ".from";

    /** Well-formed group email; {@link #loadGroupByGroupname2} accepts these without a directory call. */
    private static final Pattern GROUP_EMAIL = Pattern.compile("^[a-zA-Z0-9._%+'-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");

    /** Absorbs login storms/retries; short enough that membership changes still apply promptly. */
    private static final long GROUP_CACHE_TTL_MILLIS = 60_000;

    /** Expired entries are purged once this many distinct users are cached, bounding memory. */
    private static final int GROUP_CACHE_MAX_SIZE = 1000;

    /** Default for {@link #getGroupAuthorityMaxAgeDays()}. */
    static final int DEFAULT_GROUP_AUTHORITY_MAX_AGE_DAYS = 7;

    /** OAuth 2.0 error codes are short ASCII tokens (RFC 6749 section 4.1.2.1); anything else is not echoed. */
    private static final Pattern OAUTH_ERROR_CODE = Pattern.compile("^[a-z_]{1,64}$");

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Core's password encoder and a hash nobody knows the password for: checking against it when
     * the user has no stored password keeps the response time the same as for a wrong password,
     * so login timing does not reveal which usernames exist (as core's own local realm does).
     */
    private static final PasswordEncoder PASSWORD_ENCODER = HudsonPrivateSecurityRealm.PASSWORD_ENCODER;
    private static final String DUMMY_PASSWORD_HASH = PASSWORD_ENCODER.encode(randomUrlSafeToken());

    private final String clientId;
    private final Secret clientSecret;
    private final String hostedDomain;
    @CheckForNull
    private String groupIncludePattern;
    @NonNull
    private GroupLookupFailurePolicy onGroupLookupFailure = GroupLookupFailurePolicy.DEGRADE;
    /** Null means the default, including for configurations saved before this setting existed. */
    @CheckForNull
    private Integer groupAuthorityMaxAgeDays;

    private transient volatile GoogleOAuthService oauthService;
    private transient volatile GroupResolver groupResolver;
    private transient volatile Map<String, CachedGroups> groupCache;
    private transient LongSupplier clock = System::currentTimeMillis;

    @DataBoundConstructor
    public GoogleGroupsSecurityRealm(String clientId, Secret clientSecret, String hostedDomain) {
        this.clientId = Util.fixEmptyAndTrim(clientId);
        this.clientSecret = clientSecret;
        this.hostedDomain = Util.fixEmptyAndTrim(hostedDomain);
    }

    public String getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret;
    }

    public String getHostedDomain() {
        return hostedDomain;
    }

    @CheckForNull
    public String getGroupIncludePattern() {
        return groupIncludePattern;
    }

    @DataBoundSetter
    public void setGroupIncludePattern(@CheckForNull String groupIncludePattern) {
        this.groupIncludePattern = Util.fixEmptyAndTrim(groupIncludePattern);
    }

    @NonNull
    public GroupLookupFailurePolicy getOnGroupLookupFailure() {
        return onGroupLookupFailure;
    }

    @DataBoundSetter
    public void setOnGroupLookupFailure(@NonNull GroupLookupFailurePolicy onGroupLookupFailure) {
        this.onGroupLookupFailure = onGroupLookupFailure;
    }

    /**
     * How many days the group authorities recorded at a user's last Google login stay valid for
     * API-token requests. Jenkins never re-checks Google between logins, so without a limit
     * someone removed from a group (or from the Workspace) keeps that group's permissions
     * through their API tokens indefinitely. After expiry, token requests carry only
     * {@code authenticated} until the user signs in with Google again. {@code 0} disables
     * expiry. Sessions are not affected; they end with the normal session timeout.
     */
    public int getGroupAuthorityMaxAgeDays() {
        return groupAuthorityMaxAgeDays != null ? groupAuthorityMaxAgeDays : DEFAULT_GROUP_AUTHORITY_MAX_AGE_DAYS;
    }

    @DataBoundSetter
    public void setGroupAuthorityMaxAgeDays(int groupAuthorityMaxAgeDays) {
        this.groupAuthorityMaxAgeDays = Math.max(0, groupAuthorityMaxAgeDays);
    }

    @Override
    public boolean allowsSignup() {
        return false;
    }

    /**
     * Break-glass password login on the standard Jenkins login form: checks the candidate
     * password against the {@link HudsonPrivateSecurityRealm.Details} property stored on the
     * user record (present on users created under the local-database realm). Users without a
     * stored password — i.e. everyone who only ever logged in via Google — cannot log in by
     * password at all.
     */
    @Override
    protected UserDetails authenticate2(String username, String password) throws AuthenticationException {
        User user = User.getById(username, false);
        HudsonPrivateSecurityRealm.Details details =
                user != null ? user.getProperty(HudsonPrivateSecurityRealm.Details.class) : null;
        boolean correct;
        if (details != null) {
            correct = details.isPasswordCorrect(password);
        } else {
            PASSWORD_ENCODER.matches(password, DUMMY_PASSWORD_HASH);
            correct = false;
        }
        if (!correct) {
            LOGGER.warning(() -> "Failed local password login attempt for: " + sanitizeForLog(username));
            throw new BadCredentialsException("Invalid username or password");
        }
        LOGGER.info(() -> "Local password login: " + sanitizeForLog(username));
        return loadUserByUsername2(username);
    }

    /**
     * Returns the user if a Jenkins user record exists — this keeps API-token users resolvable
     * and lets authorization strategies validate names. Authorities come from the last
     * interactive login ({@link LastGrantedAuthoritiesProperty}), so API-token requests carry
     * the user's group authorities too, until {@link #getGroupAuthorityMaxAgeDays()} days after
     * their last Google login. Local users (no {@link GoogleAccountProperty}) never expire:
     * their access comes from {@code user:} grants, not Google Groups.
     */
    @Override
    public UserDetails loadUserByUsername2(String username) throws UsernameNotFoundException {
        User user = User.getById(username, false);
        if (user == null) {
            throw new UsernameNotFoundException("No Jenkins user record for: " + username);
        }
        GoogleAccountProperty google = user.getProperty(GoogleAccountProperty.class);
        if (google != null && groupAuthoritiesExpired(google)) {
            LOGGER.fine(() -> "Group authorities of " + username + " expired (no Google login for more than "
                    + getGroupAuthorityMaxAgeDays() + " days); granting 'authenticated' only");
            return new org.springframework.security.core.userdetails.User(
                    username, "", List.of(AUTHENTICATED_AUTHORITY2));
        }
        LastGrantedAuthoritiesProperty property = user.getProperty(LastGrantedAuthoritiesProperty.class);
        List<GrantedAuthority> authorities = property != null
                ? new ArrayList<>(property.getAuthorities2())
                : List.of(AUTHENTICATED_AUTHORITY2);
        return new org.springframework.security.core.userdetails.User(username, "", authorities);
    }

    /**
     * Accepts any well-formed group email. We cannot enumerate or validate groups server-side
     * in user-token mode, so this never makes a directory call.
     */
    @Override
    public GroupDetails loadGroupByGroupname2(String groupname, boolean fetchMembers) throws UsernameNotFoundException {
        if (groupname == null || !GROUP_EMAIL.matcher(groupname).matches()) {
            throw new UsernameNotFoundException("Not a well-formed group email: " + groupname);
        }
        String normalized = groupname.toLowerCase(Locale.ROOT);
        return new GroupDetails() {
            @Override
            public String getName() {
                return normalized;
            }
        };
    }

    // ---------------------------------------------------------------- login flow

    /**
     * Starts the OAuth code flow. Reached by the "Sign in with Google" link, so it must accept
     * GET and anonymous callers. Its only effect is storing a fresh {@code state} and PKCE
     * verifier in the caller's own session; forcing a victim here merely restarts their login.
     */
    @SuppressWarnings({"lgtm[jenkins/csrf]", "lgtm[jenkins/no-permission-check]"})
    public HttpResponse doCommenceLogin(
            StaplerRequest2 request, @QueryParameter String from, @Header("Referer") String referer)
            throws IOException {
        HttpResponse misconfigured = misconfigured();
        if (misconfigured != null) {
            return misconfigured;
        }
        String redirectOnFinish = calculateSafeRedirect(from, referer);
        String state = randomUrlSafeToken();
        String pkceVerifier = randomUrlSafeToken();
        HttpSession session = request.getSession(true);
        session.setAttribute(SESSION_STATE, state);
        session.setAttribute(SESSION_PKCE_VERIFIER, pkceVerifier);
        session.setAttribute(SESSION_FROM, redirectOnFinish);
        String url = oauthService().buildAuthorizationUrl(buildRedirectUri(), state, s256Challenge(pkceVerifier));
        return HttpResponses.redirectTo(url);
    }

    /**
     * OAuth redirect URI. Google redirects the browser here with a GET request (RFC 6749
     * section 4.1.2) before the user is logged in, so neither POST nor a permission check is
     * possible. CSRF protection is the OAuth {@code state} parameter, which must match the
     * single-use value stored in the caller's session, plus PKCE; the token request to Google's
     * fixed endpoint only happens after that check.
     */
    @SuppressWarnings({"lgtm[jenkins/csrf]", "lgtm[jenkins/no-permission-check]"})
    public HttpResponse doFinishLogin(
            StaplerRequest2 request,
            @QueryParameter String code,
            @QueryParameter String state,
            @QueryParameter String error)
            throws IOException {
        HttpSession session = request.getSession(false);
        String expectedState = session != null ? (String) session.getAttribute(SESSION_STATE) : null;
        String pkceVerifier = session != null ? (String) session.getAttribute(SESSION_PKCE_VERIFIER) : null;
        String from = session != null ? (String) session.getAttribute(SESSION_FROM) : null;

        // The state and PKCE verifier are single-use: a failed callback must restart at
        // commenceLogin instead of retrying with the same state.
        if (session != null) {
            session.removeAttribute(SESSION_STATE);
            session.removeAttribute(SESSION_PKCE_VERIFIER);
            session.removeAttribute(SESSION_FROM);
        }

        HttpResponse misconfigured = misconfigured();
        if (misconfigured != null) {
            return misconfigured;
        }

        if (error != null) {
            LOGGER.warning(() -> "Google login refused by authorization server: " + sanitizeForLog(error));
            String shown = OAUTH_ERROR_CODE.matcher(error).matches() ? error : "unrecognized error";
            return HttpResponses.errorWithoutStack(401, "Google login failed: " + shown);
        }
        if (code == null || state == null || expectedState == null || pkceVerifier == null
                || !MessageDigest.isEqual(
                        expectedState.getBytes(StandardCharsets.UTF_8), state.getBytes(StandardCharsets.UTF_8))) {
            return HttpResponses.errorWithoutStack(401,
                    "State did not match or login session expired. Please try logging in again.");
        }

        GoogleTokenResponse tokenResponse;
        GoogleIdToken.Payload payload;
        try {
            GoogleOAuthService oauth = oauthService();
            tokenResponse = oauth.exchangeCode(code, buildRedirectUri(), pkceVerifier);
            payload = oauth.verifyAndGetPayload(tokenResponse);
        } catch (IOException | GeneralSecurityException e) {
            LOGGER.log(Level.WARNING, "Google login failed during token exchange/validation", e);
            return HttpResponses.errorWithoutStack(401, "Google login failed: " + e.getMessage());
        }

        GoogleUserInfo userInfo = new GoogleUserInfo(payload);
        String userId = userInfo.getEmail();

        // The email may have been reassigned to a different Google account since this user
        // record was bound; never let the new account inherit the old one's tokens and grants.
        User existing = User.getById(userId, false);
        GoogleAccountProperty bound = existing != null ? existing.getProperty(GoogleAccountProperty.class) : null;
        if (bound != null && !bound.getSubject().equals(userInfo.getSubject())) {
            LOGGER.severe(() -> "Refusing Google login for " + userId + ": the Jenkins user record belongs to"
                    + " Google account " + bound.getSubject() + " but this login is account "
                    + userInfo.getSubject() + " (email reassigned?). Delete the Jenkins user to allow it.");
            fireLoginRefused(userId);
            return HttpResponses.errorWithoutStack(401,
                    "Login refused: this email address belongs to a different Google account than the one"
                            + " previously used in Jenkins. Contact an administrator.");
        }

        List<GrantedAuthority> authorities;
        try {
            authorities = authoritiesForLogin(userId, tokenResponse.getAccessToken());
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Refusing login for " + userId
                    + " because group lookup failed and onGroupLookupFailure=FAIL", e);
            fireLoginRefused(userId);
            return HttpResponses.errorWithoutStack(401,
                    "Login refused: Google Groups could not be resolved. Contact an administrator.");
        }

        // Session fixation protection: discard the pre-login session.
        if (session != null) {
            session.invalidate();
        }
        request.getSession(true);

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userId, "", authorities);
        SecurityContextHolder.getContext().setAuthentication(token);

        User user = User.getById(userId, true);
        user.addProperty(new GoogleAccountProperty(userInfo.getSubject(), clock().getAsLong()));
        userInfo.updateProfile(user);

        SecurityListener.fireAuthenticated2(
                new org.springframework.security.core.userdetails.User(userId, "", authorities));
        SecurityListener.fireLoggedIn(userId);

        // The operational answer to Google's silent group filtering: always log what resolved.
        List<String> authorityNames = authorities.stream().map(GrantedAuthority::getAuthority).toList();
        LOGGER.info(() -> "Google login: " + userId + " authorities=" + authorityNames);

        return HttpResponses.redirectTo(from != null ? from : Jenkins.get().getRootUrl());
    }

    /**
     * Resolves group authorities, applying {@link #getOnGroupLookupFailure()}: on lookup
     * failure either degrade to {@code authenticated} only (with a loud WARNING) or rethrow
     * so the login is refused. Failures are never cached.
     */
    @NonNull
    List<GrantedAuthority> authoritiesForLogin(@NonNull String email, @NonNull String accessToken) throws IOException {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(AUTHENTICATED_AUTHORITY2);
        try {
            for (String group : resolveGroupsCached(email, accessToken)) {
                authorities.add(new SimpleGrantedAuthority(group));
            }
        } catch (IOException | RuntimeException e) {
            if (onGroupLookupFailure == GroupLookupFailurePolicy.FAIL) {
                throw e instanceof IOException ioe ? ioe : new IOException("Group lookup failed for " + email, e);
            }
            LOGGER.log(Level.WARNING, "Group lookup failed for " + email
                    + "; logging in with 'authenticated' only (onGroupLookupFailure=DEGRADE). "
                    + "Group-based permissions will be missing until the next successful login.", e);
        }
        return authorities;
    }

    @NonNull
    private List<String> resolveGroupsCached(@NonNull String email, @NonNull String accessToken) throws IOException {
        Map<String, CachedGroups> cache = groupCache();
        long now = clock().getAsLong();
        CachedGroups cached = cache.get(email);
        if (cached != null && now - cached.timestamp() < GROUP_CACHE_TTL_MILLIS) {
            return cached.groups();
        }
        List<String> groups = groupResolver().resolveGroups(email, accessToken);
        if (cache.size() >= GROUP_CACHE_MAX_SIZE) {
            cache.values().removeIf(entry -> now - entry.timestamp() >= GROUP_CACHE_TTL_MILLIS);
        }
        cache.put(email, new CachedGroups(now, List.copyOf(groups)));
        return groups;
    }

    /** Test hook: number of cached group entries. */
    int cachedGroupCount() {
        return groupCache().size();
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Reports a Google login that was authenticated by Google but refused by Jenkins, so audit
     * listeners (e.g. the Audit Trail plugin) record it like a failed password login.
     */
    private static void fireLoginRefused(@NonNull String userId) {
        SecurityListener.fireFailedToAuthenticate(userId);
        SecurityListener.fireFailedToLogIn(userId);
    }

    private boolean groupAuthoritiesExpired(@NonNull GoogleAccountProperty google) {
        int maxAgeDays = getGroupAuthorityMaxAgeDays();
        return maxAgeDays > 0
                && clock().getAsLong() - google.getLastLoginMillis() > TimeUnit.DAYS.toMillis(maxAgeDays);
    }

    /** Replaces control characters so request-supplied values cannot forge extra log lines. */
    @NonNull
    static String sanitizeForLog(@CheckForNull String value) {
        return value == null ? "null" : value.replaceAll("\\p{Cntrl}", "_");
    }

    /**
     * @return why Google login cannot work with the current configuration, or null if it can.
     *     Checked at login rather than rejected at configuration time: failing the configuration
     *     (e.g. a JCasC reload) would also take down the break-glass password login.
     */
    @CheckForNull
    String configurationProblem() {
        if (clientId == null) {
            return "the Client ID is not configured";
        }
        if (hostedDomain == null) {
            return "the hosted domain is not configured";
        }
        if (JenkinsLocationConfiguration.get().getUrl() == null) {
            return "the Jenkins URL is not configured (Manage Jenkins > System > Jenkins URL);"
                    + " it is required to build the OAuth redirect URI";
        }
        return null;
    }

    @CheckForNull
    private HttpResponse misconfigured() {
        String problem = configurationProblem();
        if (problem == null) {
            return null;
        }
        LOGGER.severe(() -> "Google login is unavailable: " + problem);
        return HttpResponses.errorWithoutStack(500,
                "Google login is not configured correctly: " + problem + ". Contact an administrator.");
    }

    /**
     * Uses only the configured Jenkins URL. {@link Jenkins#getRootUrl()} would fall back to the
     * request's Host header when none is configured, letting a request choose the redirect URI.
     */
    @NonNull
    String buildRedirectUri() {
        String redirectUri = configuredRedirectUri();
        if (redirectUri == null) {
            throw new IllegalStateException(
                    "Jenkins URL is not configured; it is required to build the OAuth redirect URI");
        }
        return redirectUri;
    }

    @CheckForNull
    static String configuredRedirectUri() {
        String url = JenkinsLocationConfiguration.get().getUrl();
        return url == null ? null : Util.ensureEndsWith(url, "/") + "securityRealm/finishLogin";
    }

    @NonNull
    private String calculateSafeRedirect(@CheckForNull String from, @CheckForNull String referer) {
        String rootUrl = Jenkins.get().getRootUrl();
        from = Util.fixEmptyAndTrim(from);
        String target = null;
        if (from != null && Util.isSafeToRedirectTo(from)) {
            target = from;
        } else if (referer != null && rootUrl != null && referer.startsWith(rootUrl)) {
            target = referer;
        }
        // Never bounce back to the login page: after a successful login it would just
        // show the form again, making the login look like a no-op.
        if (target == null || isLoginPage(target)) {
            return rootUrl != null ? rootUrl : "/";
        }
        return target;
    }

    private static boolean isLoginPage(@NonNull String url) {
        String path = url.split("[?#]", 2)[0];
        return path.endsWith("/login") || path.endsWith("/loginError");
    }

    /**
     * One service per realm instance, so its ID token verifier keeps Google's signing keys cached
     * between logins instead of downloading them on every login. Reconfiguring the realm creates
     * a new instance, so the cached service never outlives the settings it was built from.
     */
    @NonNull
    private GoogleOAuthService oauthService() {
        GoogleOAuthService service = oauthService;
        if (service == null) {
            service = createOAuthService();
            oauthService = service;
        }
        return service;
    }

    @NonNull
    GoogleOAuthService createOAuthService() {
        return new GoogleOAuthService(clientId, clientSecret, hostedDomain, createTransport());
    }

    /**
     * Connects through the HTTP proxy configured in Jenkins (Manage Jenkins &gt; System), if
     * any. A plain {@link NetHttpTransport} would only honor JVM-wide proxy system properties.
     */
    @NonNull
    static HttpTransport createTransport() {
        return new NetHttpTransport.Builder()
                .setConnectionFactory(url -> (HttpURLConnection) ProxyConfiguration.open(url))
                .build();
    }

    @NonNull
    private GroupResolver groupResolver() {
        GroupResolver resolver = groupResolver;
        if (resolver == null) {
            Pattern pattern = groupIncludePattern != null ? Pattern.compile(groupIncludePattern) : null;
            resolver = new CloudIdentityDirectGroupResolver(createTransport(), pattern);
            groupResolver = resolver;
        }
        return resolver;
    }

    /** Test hook: inject a stub resolver. */
    void setGroupResolver(@CheckForNull GroupResolver groupResolver) {
        this.groupResolver = groupResolver;
    }

    @NonNull
    private Map<String, CachedGroups> groupCache() {
        Map<String, CachedGroups> cache = groupCache;
        if (cache == null) {
            synchronized (this) {
                cache = groupCache;
                if (cache == null) {
                    cache = new ConcurrentHashMap<>();
                    groupCache = cache;
                }
            }
        }
        return cache;
    }

    @NonNull
    private LongSupplier clock() {
        LongSupplier c = clock;
        if (c == null) {
            c = System::currentTimeMillis;
            clock = c;
        }
        return c;
    }

    /** Test hook: control time for cache-expiry tests. */
    void setClock(@NonNull LongSupplier clock) {
        this.clock = clock;
    }

    @NonNull
    private static String randomUrlSafeToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @NonNull
    static String s256Challenge(@NonNull String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(digest.digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private record CachedGroups(long timestamp, @NonNull List<String> groups) {}

    @Extension
    @Symbol("googleGroupsOAuth")
    public static class DescriptorImpl extends Descriptor<SecurityRealm> {

        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.GoogleGroupsSecurityRealm_DisplayName();
        }

        /** For {@code help-clientId.jelly}: the redirect URI to register, or null without a Jenkins URL. */
        @CheckForNull
        @Restricted(NoExternalUse.class)
        public String getRedirectUri() {
            return configuredRedirectUri();
        }

        @RequirePOST
        public FormValidation doCheckHostedDomain(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            String domain = Util.fixEmptyAndTrim(value);
            if (domain == null) {
                return FormValidation.error(Messages.GoogleGroupsSecurityRealm_HostedDomainRequired());
            }
            if (domain.contains("@") || domain.contains("/") || !domain.contains(".")) {
                return FormValidation.error(Messages.GoogleGroupsSecurityRealm_HostedDomainInvalid());
            }
            return FormValidation.ok();
        }

        @RequirePOST
        public FormValidation doCheckGroupIncludePattern(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            String pattern = Util.fixEmptyAndTrim(value);
            if (pattern == null) {
                return FormValidation.ok(Messages.GoogleGroupsSecurityRealm_GroupIncludePatternEmpty());
            }
            try {
                Pattern.compile(pattern);
                return FormValidation.ok();
            } catch (PatternSyntaxException e) {
                return FormValidation.error(e, Messages.GoogleGroupsSecurityRealm_GroupIncludePatternInvalid());
            }
        }

        @RequirePOST
        public FormValidation doCheckGroupAuthorityMaxAgeDays(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            int days;
            try {
                days = Integer.parseInt(Util.fixEmptyAndTrim(value) == null ? "" : value.trim());
            } catch (NumberFormatException e) {
                return FormValidation.error(Messages.GoogleGroupsSecurityRealm_GroupAuthorityMaxAgeDaysInvalid());
            }
            if (days < 0) {
                return FormValidation.error(Messages.GoogleGroupsSecurityRealm_GroupAuthorityMaxAgeDaysInvalid());
            }
            if (days == 0) {
                return FormValidation.warning(Messages.GoogleGroupsSecurityRealm_GroupAuthorityMaxAgeDaysDisabled());
            }
            return FormValidation.ok();
        }
    }
}
