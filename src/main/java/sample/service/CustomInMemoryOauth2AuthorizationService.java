package sample.service;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.Assert;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class CustomInMemoryOauth2AuthorizationService implements OAuth2AuthorizationService {

    private final int maxInitializedAuthorizations;
    private Map<String, OAuth2Authorization> initializedAuthorizations;
    private final Map<String, OAuth2Authorization> authorizations;

    public CustomInMemoryOauth2AuthorizationService(int maxInitializedAuthorizations) {
        this.maxInitializedAuthorizations = maxInitializedAuthorizations;
        this.initializedAuthorizations =
                Collections.synchronizedMap(new CustomInMemoryOauth2AuthorizationService.MaxSizeHashMap<>(this.maxInitializedAuthorizations));
        this.authorizations = new ConcurrentHashMap<>();
        this.initializedAuthorizations =
                Collections.synchronizedMap(new CustomInMemoryOauth2AuthorizationService.MaxSizeHashMap<>(this.maxInitializedAuthorizations));
    }

    public CustomInMemoryOauth2AuthorizationService() {
        this(Collections.emptyList());
    }

    public CustomInMemoryOauth2AuthorizationService(OAuth2Authorization... authorizations) {
        this(Arrays.asList(authorizations));
    }

    public CustomInMemoryOauth2AuthorizationService(List<OAuth2Authorization> authorizations) {
        this.maxInitializedAuthorizations = 100;
        this.initializedAuthorizations =
                Collections.synchronizedMap(new CustomInMemoryOauth2AuthorizationService.MaxSizeHashMap<>(this.maxInitializedAuthorizations));
        this.authorizations = new ConcurrentHashMap<>();
        Assert.notNull(authorizations, "authorizations cannot be null");
        authorizations.forEach((authorization) -> {
            Assert.notNull(authorization, "authorization cannot be null");
            Assert.isTrue(!this.authorizations.containsKey(authorization.getId()), "The authorization must be unique. Found duplicate identifier: " + authorization.getId());
            this.authorizations.put(authorization.getId(), authorization);
        });
    }

    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        if (isComplete(authorization)) {
            this.authorizations.put(authorization.getId(), authorization);
        } else {
            this.initializedAuthorizations.put(authorization.getId(), authorization);
        }

    }

    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        if (isComplete(authorization)) {
            this.authorizations.remove(authorization.getId(), authorization);
        } else {
            this.initializedAuthorizations.remove(authorization.getId(), authorization);
        }

    }

    @Nullable
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        OAuth2Authorization authorization = this.authorizations.get(id);
        return authorization != null ? authorization : this.initializedAuthorizations.get(id);
    }

    @Nullable
    public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        Iterator<OAuth2Authorization> oAuth2AuthorizationIterator = this.authorizations.values().iterator();

        OAuth2Authorization authorization;
        do {
            if (!oAuth2AuthorizationIterator.hasNext()) {
                oAuth2AuthorizationIterator = this.initializedAuthorizations.values().iterator();

                do {
                    if (!oAuth2AuthorizationIterator.hasNext()) {
                        return null;
                    }

                    authorization = oAuth2AuthorizationIterator.next();
                } while(!hasToken(authorization, token, tokenType));

                return authorization;
            }

            authorization = oAuth2AuthorizationIterator.next();
        } while(!hasToken(authorization, token, tokenType));

        return authorization;
    }

    private static boolean isComplete(OAuth2Authorization authorization) {
        return authorization.getAccessToken() != null;
    }

    private static boolean hasToken(OAuth2Authorization authorization, String token, @Nullable OAuth2TokenType tokenType) {
        if (tokenType != null) {
            if ("state".equals(tokenType.getValue())) {
                return matchesState(authorization, token);
            } else if ("code".equals(tokenType.getValue())) {
                return matchesAuthorizationCode(authorization, token);
            } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
                return matchesAccessToken(authorization, token);
            } else {
                return OAuth2TokenType.REFRESH_TOKEN.equals(tokenType) && matchesRefreshToken(authorization, token);
            }
        } else {
            return matchesState(authorization, token) || matchesAuthorizationCode(authorization, token) || matchesAccessToken(authorization, token) || matchesRefreshToken(authorization, token);
        }
    }

    private static boolean matchesState(OAuth2Authorization authorization, String token) {
        return token.equals(authorization.getAttribute("state"));
    }

    private static boolean matchesAuthorizationCode(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
        return authorizationCode != null && authorizationCode.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesAccessToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
        return accessToken != null && accessToken.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesRefreshToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getToken(OAuth2RefreshToken.class);
        return refreshToken != null && refreshToken.getToken().getTokenValue().equals(token);
    }

    private static final class MaxSizeHashMap<K, V> extends LinkedHashMap<K, V> {
        private final int maxSize;

        private MaxSizeHashMap(int maxSize) {
            this.maxSize = maxSize;
        }

        protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
            return this.size() > this.maxSize;
        }
    }

}
