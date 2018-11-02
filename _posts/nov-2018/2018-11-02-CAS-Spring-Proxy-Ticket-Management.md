---
layout: post
title: Proxy Ticketing, Camel Spring security and CAS
---

#### Spring security Proxy Ticket Interceptor

Spring security can intercept each request and add a Proxy Token.

```
/*
 * Mosaic
 *
 * Copyright 2011 Corelogic Ltd All Rights Reserved.
 */
package <custom package>;
import org.apache.commons.collections.CollectionUtils;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.RequestWrapper;
import org.apache.http.protocol.HttpContext;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import uk.co.corelogic.mosaic.portal.authentication.CasAnonymousLoginToken;
import uk.co.corelogic.mosaic.portal.common.exceptions.PortalRuntimeException;
import uk.co.corelogic.mosaic.portal.sushi.cookie.UserSessionCookieStore;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;


public class AddCasTicketToRequestInterceptor implements HttpRequestInterceptor {

    @Override
    public void process(final HttpRequest request, final HttpContext context) throws HttpException, IOException {
        final String backbaseSessionId = request.getFirstHeader(MOSAIC_REMOTE_APPLICATION_USER_SESSION_STATE_ID).getValue();
        final UserSessionCookieStore userSessionCookieStore = (UserSessionCookieStore) context.getAttribute(ClientContext.COOKIE_STORE);
        final List<Cookie> sessionCookies = userSessionCookieStore.getCookies(backbaseSessionId);
        if (CollectionUtils.isEmpty(sessionCookies)) {
            final RequestWrapper requestWrapper = (RequestWrapper) request;
            final HttpUriRequest original = (HttpUriRequest) requestWrapper.getOriginal();
            final String requestUrl = original.getURI().toURL().toString();
            final SecurityContext securityContext = SecurityContextHolder.getContext();
            final Authentication authentication = securityContext.getAuthentication();
            if (authentication != null) {
                final CasAuthenticationToken casAuthenticationToken =  getCasAuthenticationToken(authentication);
                final String ticket = casAuthenticationToken.getAssertion().getPrincipal().getProxyTicketFor(requestUrl);
                URI requestUri = null;
                try {
                    requestUri = getRequestUri((RequestWrapper) request, ticket);
                } catch (URISyntaxException e) {
                    throw new PortalRuntimeException("Invalid Url", e);
                }
                requestWrapper.setURI(requestUri);
            } else {
                throw new IllegalStateException("Authentication token cannot be null");
            }
        }
    }

    private URI getRequestUri(final RequestWrapper request, final String ticket) throws URISyntaxException {
        String requestUri =  request.getURI().toString();
        if (requestUri.contains("?")) {
            requestUri = requestUri + "&ticket=" + ticket;
        } else {
            requestUri = requestUri + "?ticket=" + ticket;
        }
        return new URI(requestUri);
    }

    private CasAuthenticationToken getCasAuthenticationToken(final Authentication authentication) {
        CasAuthenticationToken casAuthenticationToken = null;
        if (authentication instanceof CasAnonymousLoginToken) {
            casAuthenticationToken = ((CasAnonymousLoginToken) authentication).getCasToken();
        } else if (authentication instanceof CasAuthenticationToken) {
            casAuthenticationToken = (CasAuthenticationToken) authentication;
        }
        return casAuthenticationToken;
    }
}


```

#### Dependent classes

```
public class UserSessionCookieStore extends BasicCookieStore {

    private transient CookieCache cookieCache;

    public UserSessionCookieStore(final CookieCache cookieCache) {
        this.cookieCache = cookieCache;
    }

    public void addCookie(final String key, final List<Cookie> cookies) {
        this.cookieCache.cacheCookies(key, cookies);
    }

    public List<Cookie> getCookies(final String key) {
        return this.cookieCache.getCachedCookies(key);
    }

    public void removeCookies(final String key) {
        this.cookieCache.removeCookies(key);
    }

}

```