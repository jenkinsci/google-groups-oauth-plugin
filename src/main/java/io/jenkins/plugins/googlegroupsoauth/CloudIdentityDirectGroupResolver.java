package io.jenkins.plugins.googlegroupsoauth;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Resolves the user's <b>direct</b> Google Group memberships with the user's own OAuth access
 * token, via the Cloud Identity API
 * {@code GET /v1/groups/-/memberships:searchDirectGroups?query=member_key_id == '<email>'}.
 *
 * <p>Constraints inherent to this mode (documented for operators in the README):
 * <ul>
 *   <li><b>Direct memberships only</b> — nested groups do not resolve (the transitive API
 *       family requires premium Workspace/Cloud Identity editions). Groups used for Jenkins
 *       RBAC must be flat.</li>
 *   <li><b>Silent filtering</b> — groups whose memberships the caller cannot view are silently
 *       omitted by Google. Mitigated operationally by login-time authority logging and
 *       Jenkins' built-in {@code /whoAmI} page.</li>
 * </ul>
 */
@Restricted(NoExternalUse.class)
public class CloudIdentityDirectGroupResolver implements GroupResolver {

    private static final Logger LOGGER = Logger.getLogger(CloudIdentityDirectGroupResolver.class.getName());

    static final String SEARCH_URL = "https://cloudidentity.googleapis.com/v1/groups/-/memberships:searchDirectGroups";
    private static final int PAGE_SIZE = 200;
    private static final int MAX_PAGES = 50;

    private final HttpTransport transport;
    @CheckForNull
    private final Pattern includePattern;

    public CloudIdentityDirectGroupResolver(@NonNull HttpTransport transport, @CheckForNull Pattern includePattern) {
        this.transport = transport;
        this.includePattern = includePattern;
    }

    @NonNull
    @Override
    public List<String> resolveGroups(@NonNull String email, @NonNull String accessToken) throws IOException {
        if (email.indexOf('\'') >= 0 || email.indexOf('\\') >= 0) {
            throw new IOException("Refusing to build a group query for suspicious email: " + email);
        }
        HttpRequestFactory requestFactory = transport.createRequestFactory();
        Set<String> groups = new LinkedHashSet<>();
        String pageToken = null;
        int pages = 0;
        do {
            GenericUrl url = new GenericUrl(SEARCH_URL);
            url.set("query", "member_key_id == '" + email + "'");
            url.set("pageSize", PAGE_SIZE);
            if (pageToken != null) {
                url.set("pageToken", pageToken);
            }
            HttpRequest request = requestFactory.buildGetRequest(url);
            request.getHeaders().setAuthorization("Bearer " + accessToken);
            HttpResponse response = request.execute(); // throws HttpResponseException on non-2xx
            String body;
            try {
                body = response.parseAsString();
            } finally {
                response.disconnect();
            }
            pageToken = parsePage(body, groups);
            pages++;
        } while (pageToken != null && pages < MAX_PAGES);
        if (pageToken != null) {
            LOGGER.log(Level.WARNING,
                    "Stopped paginating group memberships for {0} after {1} pages; authority list may be incomplete",
                    new Object[] {email, MAX_PAGES});
        }
        return new ArrayList<>(groups);
    }

    /** @return the next page token, or null when this was the last page */
    @CheckForNull
    private String parsePage(@NonNull String body, @NonNull Set<String> groups) throws IOException {
        JsonObject root;
        try {
            root = JsonParser.parseString(body).getAsJsonObject();
        } catch (JsonParseException | IllegalStateException e) {
            throw new IOException("Malformed searchDirectGroups response", e);
        }
        JsonArray memberships = root.has("memberships") ? root.getAsJsonArray("memberships") : null;
        if (memberships != null) {
            for (JsonElement element : memberships) {
                if (!element.isJsonObject()) {
                    continue;
                }
                JsonObject groupKey = element.getAsJsonObject().has("groupKey")
                        ? element.getAsJsonObject().getAsJsonObject("groupKey")
                        : null;
                if (groupKey == null || !groupKey.has("id")) {
                    continue;
                }
                String groupEmail = groupKey.get("id").getAsString().toLowerCase(Locale.ROOT);
                if (includePattern == null || includePattern.matcher(groupEmail).matches()) {
                    groups.add(groupEmail);
                }
            }
        }
        if (root.has("nextPageToken")) {
            String token = root.get("nextPageToken").getAsString();
            if (!token.isEmpty()) {
                return token;
            }
        }
        return null;
    }
}
