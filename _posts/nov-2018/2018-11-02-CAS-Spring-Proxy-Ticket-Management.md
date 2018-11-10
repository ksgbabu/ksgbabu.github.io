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
import com.portal.authentication.CasAnonymousLoginToken;
import com.portal.common.exceptions.PortalRuntimeException;
import com.portal.sushi.cookie.UserSessionCookieStore;

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

import org.apache.http.cookie.Cookie;

import java.util.List;

public interface CookieCache {

    /**
     * Caches the cookies with specified key
     *
     * @param key
     * @param cookies
     */
    void cacheCookies(String key, List<Cookie> cookies);

    /**
     * Retrieves the cookies for the specified key.If the cookie is expired then returns null
     * @return
     */
    List<Cookie> getCachedCookies(String key);

    /**
     * Checks if the entry is there for the key
     * @param key
     * @return
     */
    void removeCookies(String key);
}


import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;
import org.apache.http.cookie.Cookie;

import java.util.ArrayList;
import java.util.List;

public class EhCookieCache implements CookieCache {

    private Ehcache ehCache;


    public Ehcache getEhCache() {
        return ehCache;
    }

    public void setEhCache(final Ehcache ehCache) {
        this.ehCache = ehCache;
    }

    @Override
    public void cacheCookies(final String key, final List<Cookie> cookies) {
        final Element element = new Element(key, cookies);
        this.ehCache.put(element);
    }

    @Override
    public List<Cookie> getCachedCookies(final String key) {
        final Element element = this.ehCache.get(key);

        if (element == null || (element.isExpired())) {
            return new ArrayList<Cookie>();
        }

        return (List<Cookie>) element.getObjectValue();
    }

    @Override
    public void removeCookies(String key) {
        this.ehCache.remove(key);
    }


}

import org.apache.commons.collections.CollectionUtils;
import org.apache.http.*;
import org.apache.http.annotation.Immutable;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.conn.HttpRoutedConnection;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.CookieSpecRegistry;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.portal.sushi.cookie.UserSessionCookieStore;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static com.portal.sushi.MosaicSushiConstants.MOSAIC_REMOTE_APPLICATION_USER_SESSION_STATE_ID;

@Immutable
public class AddRequestCookieInterceptor implements HttpRequestInterceptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(AddRequestCookieInterceptor.class);

    @Override
    public void process(final HttpRequest request, final HttpContext context) throws HttpException, IOException {

        // Obtain the registry of cookie specs
        final CookieSpecRegistry registry = (CookieSpecRegistry) context.getAttribute(
                ClientContext.COOKIESPEC_REGISTRY);
        if (registry == null) {
            this.LOGGER.debug("CookieSpec registry not specified in HTTP context");
            return;
        }

        final String policy = HttpClientParams.getCookiePolicy(request.getParams());
        if (this.LOGGER.isDebugEnabled()) {
            this.LOGGER.debug("CookieSpec selected: " + policy);
        }

        final CookieOrigin cookieOrigin = getCookieOrigin(request, context);
        if (cookieOrigin == null) {
            this.LOGGER.debug("CookieOrigin is null");
            return;
        }
        final CookieSpec cookieSpec = registry.getCookieSpec(policy, request.getParams());
        final String backbaseSessionId = request.getFirstHeader(MOSAIC_REMOTE_APPLICATION_USER_SESSION_STATE_ID).getValue();
        addCookiesFromStoreToHeader(backbaseSessionId, context, cookieOrigin, cookieSpec, request);
        context.setAttribute(MOSAIC_REMOTE_APPLICATION_USER_SESSION_STATE_ID, backbaseSessionId);
        context.setAttribute(ClientContext.COOKIE_SPEC, cookieSpec);
        context.setAttribute(ClientContext.COOKIE_ORIGIN, cookieOrigin);

    }

    private void addCookiesFromStoreToHeader(final String backbaseSessionId, final HttpContext context,
                                             final CookieOrigin cookieOrigin, final CookieSpec cookieSpec, final HttpRequest request) {

        final UserSessionCookieStore cookieStore = (UserSessionCookieStore) context.getAttribute(ClientContext.COOKIE_STORE);
        final List<Cookie> cookies = cookieStore.getCookies(backbaseSessionId);
        if (CollectionUtils.isNotEmpty(cookies)) {
            final Date now = new Date();
            final List<Cookie> matchedCookies = new ArrayList<Cookie>();
            for (final Cookie cookie : cookies) {
                if (!cookie.isExpired(now) && cookieSpec.match(cookie, cookieOrigin)) {
                    matchedCookies.add(cookie);
                }
            }
            // Generate Cookie request headers
            if (!matchedCookies.isEmpty()) {
                final List<Header> headers = cookieSpec.formatCookies(matchedCookies);
                for (Header header : headers) {
                    request.addHeader(header);
                }
            }
        }
    }

    private CookieOrigin getCookieOrigin(final HttpRequest request, final HttpContext context) throws ProtocolException {
        final URI requestURI;
        if (request instanceof HttpUriRequest) {
            requestURI = ((HttpUriRequest) request).getURI();
        } else {
            try {
                requestURI = new URI(request.getRequestLine().getUri());
            } catch (URISyntaxException ex) {
                throw new ProtocolException("Invalid request URI: " +
                        request.getRequestLine().getUri(), ex);
            }
        }

        // Obtain the target host (required)
        HttpHost targetHost = (HttpHost) context.getAttribute(
                ExecutionContext.HTTP_TARGET_HOST);
        if (targetHost == null) {
            this.LOGGER.debug("Target host not set in the context");
            return null;
        }

        // Obtain the client connection (required)
        HttpRoutedConnection conn = (HttpRoutedConnection) context.getAttribute(
                ExecutionContext.HTTP_CONNECTION);
        if (conn == null) {
            this.LOGGER.debug("HTTP connection not set in the context");
            return null;
        }

        String hostName = targetHost.getHostName();

        int port = getPort(targetHost, conn);


        return new CookieOrigin(
                hostName,
                port,
                requestURI.getPath(),
                conn.isSecure());
    }

    private int getPort(HttpHost targetHost, HttpRoutedConnection conn) {
        int port = targetHost.getPort();
        if (port < 0) {
            HttpRoute route = conn.getRoute();
            if (route.getHopCount() == 1) {
                port = conn.getRemotePort();
            } else {
                // Target port will be selected by the proxy.
                // Use conventional ports for known schemes
                String scheme = targetHost.getSchemeName();
                if ("http".equalsIgnoreCase(scheme)) {
                    port = 80;
                } else if ("https".equalsIgnoreCase(scheme)) {
                    port = 443;
                } else {
                    port = 0;
                }
            }
        }
        return port;
    }
}


public class ErrorResponseInterceptor implements HttpResponseInterceptor {

    @Override
    public void process(final HttpResponse response, final HttpContext context) throws HttpException, IOException {
        final UserSessionCookieStore cookieStore = (UserSessionCookieStore) context.getAttribute(COOKIE_STORE);
        final String backbaseSessionId = (String) context
                .getAttribute(MosaicSushiConstants.MOSAIC_REMOTE_APPLICATION_USER_SESSION_STATE_ID);

        final int statusCode = response.getStatusLine().getStatusCode();
        if (isAuthenticationFailed(statusCode, response)) {
            cookieStore.removeCookies(backbaseSessionId);
            throw new RemoteApplicationAuthenticationException("Authentication failure");
        } else if (statusCode == 500) {
            throw new PortalRuntimeException("Unexpected error");
        }
        final Header header = response.getFirstHeader("isError");
        if (header != null && "true".equals(header.getValue())) {
            throw new ShowErrorPageException("An unexpected error has been encountered");
        }
    }

    private boolean isAuthenticationFailed(final int statusCode, final HttpResponse response) {
        final Header location = response.getFirstHeader("Location");
        if (statusCode == 403) {
            return true;
        } else if (statusCode == 302 && location != null && location.getValue().endsWith("login.jsp")) {
            return true;
        }
        return false;
    }
}



import org.apache.commons.collections.CollectionUtils;
import org.apache.http.*;
import org.apache.http.annotation.Immutable;
import org.apache.http.cookie.*;
import org.apache.http.protocol.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.myportal.portal.sushi.MosaicSushiConstants;
import com.myportal.portal.sushi.cookie.UserSessionCookieStore;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.apache.http.client.protocol.ClientContext.*;

@Immutable
public class ProcessResponseCookiesInterceptor implements HttpResponseInterceptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProcessResponseCookiesInterceptor.class);

    @Override
    public void process(final HttpResponse response, final HttpContext context) throws HttpException, IOException {
        final UserSessionCookieStore cookieStore = (UserSessionCookieStore) context.getAttribute(COOKIE_STORE);
        final String backbaseSessionId = (String) context.getAttribute(MosaicSushiConstants.MOSAIC_REMOTE_APPLICATION_USER_SESSION_STATE_ID);

        final CookieSpec cookieSpec = (CookieSpec) context.getAttribute(COOKIE_SPEC);
        if (cookieSpec == null) {
            this.LOGGER.debug("Cookie spec not specified in HTTP context");
            return;
        }

        // Obtain actual CookieOrigin instance
        final CookieOrigin cookieOrigin = (CookieOrigin) context.getAttribute(COOKIE_ORIGIN);
        if (cookieOrigin == null) {
            this.LOGGER.debug("Cookie origin not specified in HTTP context");
            return;
        }

        HeaderIterator headerIterator = response.headerIterator(SM.SET_COOKIE);
        processCookies(headerIterator, cookieStore, cookieSpec, cookieOrigin, backbaseSessionId);

        // see if the cookie spec supports cookie versioning.
        if (cookieSpec.getVersion() > 0) {
            // process set-cookie2 headers.
            headerIterator = response.headerIterator(SM.SET_COOKIE2);
            processCookies(headerIterator, cookieStore, cookieSpec, cookieOrigin, backbaseSessionId);


        }
    }

    private void processCookies(final HeaderIterator headerIterator, final UserSessionCookieStore cookieStore,
                                final CookieSpec cookieSpec, final CookieOrigin cookieOrigin, final String backbaseSessionId) throws MalformedCookieException {
        final List<Cookie> cookieList = new ArrayList<>();
        while (headerIterator.hasNext()) {
            final Header header = headerIterator.nextHeader();
            cookieList.addAll(cookieSpec.parse(header, cookieOrigin));

        }
        if (CollectionUtils.isNotEmpty(cookieList)) {
            cookieStore.addCookie(backbaseSessionId, cookieList);
        }
    }
}


```