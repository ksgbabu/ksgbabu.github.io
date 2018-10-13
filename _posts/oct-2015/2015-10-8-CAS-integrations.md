---
layout: post
title: Spring security and CAS
---
CAS Proxy Authentication will have a source application and target service/application URL to be accessed
over single sign on. Both source application and Target service CAS based configurations are expained below.

# The Source Side Configurations

## To explain the steps and configurations for Spring to CAS integration.

### Spring security filter configurations

Add a custom filter in the security.xml

#### Add the following security filter configuration

```
    <sec:http>
    <sec:custom-filter ref="casFilter" position="CAS_FILTER" />
    </sec:http>
```

	        <custom-filter after="ANONYMOUS_FILTER" ref="cas_anonymousLoginFilterChain"/>
			<custom-filter position="CAS_FILTER" ref="casFilter" />
			

		     <beans:bean id="cas_anonymousLoginFilter"
		                 class="com.mozanta.portal.filter.CasAnonymousLoginFilter">
		         <beans:property name="authenticationProvider" ref="casAuthenticationProvider"/>
		         <beans:property name="ticketRetriever" ref="serviceTicketRetriever"/>
		         <beans:property name="user" value="${portal.anonymous.username}"/>
		     </beans:bean>

		     <beans:bean id="serviceTicketRetriever"
		                 class="com.mozanta.portal.authentication.ServiceTicketRetriever">
		         <beans:property name="url" value="${cas.server.url}/v1/tickets"/>
		         <beans:property name="serviceProperties" ref="serviceProperties"/>
		         <beans:property name="userDetailsService" ref="portalUserDetailsService"/>
		     </beans:bean>

#### User Details Service (portalUserDetailsService)

```
public class CasUserDetailsService implements AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {


    @Loggable
    Logger log;

    @Override
    public UserDetails loadUserDetails(final CasAssertionAuthenticationToken auth) throws UsernameNotFoundException {
        Validate.notNull(auth.getAssertion(), "CAS assertion cannot be null.");
        Validate.notNull(auth.getAssertion().getPrincipal(), "CAS assertion principal cannot be null.");
        //Load user details from LDAP for authentication

        return (UserDetails) user;
    }

    private void logDetails(final CurrentUser user) {
        if (log.isDebugEnabled()) {
            log.debug("Mosaic worker loaded for CAS.");
            log.debug("ID >> " + user.getId());
            log.debug("Name >> " + user.getActingForName());
            log.debug("Role >>" + user.getRole());
        }
    }
}

Custome success Authenitcation Handler

public class MosaicAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
            final Authentication authentication) throws ServletException, IOException {
        final SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest == null) {
            super.onAuthenticationSuccess(request, response, authentication);

            return;
        }

        clearAuthenticationAttributes(request);
        final String targetUrl = getTargetUrl(savedRequest);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    private String getTargetUrl(final SavedRequest savedRequest) {
        final String queryString = ((DefaultSavedRequest) savedRequest).getQueryString();
        final String targetUrl = getDefaultTargetUrl() + "?" + queryString;
        return targetUrl;
    }

    public void setRequestCache(final RequestCache requestCache) {
        this.requestCache = requestCache;
    }

}

public class PortalCustomSpecialPageHandler extends CustomSpecialPageHandler {

    @Autowired
    public PortalCustomSpecialPageHandler(PortalBusinessService pPortalBusinessService,
                                          @Qualifier("securityHelper") SecurityHelper pSecurityHelper, LinkBusinessService pLinkBusinessService,
                                          @Qualifier("linkBusinessProcess") LinkBusinessProcess pLinkBusinessProcess) {
        super(pPortalBusinessService, pSecurityHelper, pLinkBusinessService, pLinkBusinessProcess);
    }

    @Override
    public void handle(final HttpServletRequest request, final HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        if (isAjax(request)) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
        } else {
            super.handle(request, response, accessDeniedException);
        }
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws
            IOException, ServletException {
        if (isAjax(request)) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
        } else {
            super.onAuthenticationFailure(request, response, exception);
        }
    }

    private boolean isAjax(final HttpServletRequest request) {
        return "XMLHttpRequest".equals(request.getHeader("X-Requested-With"));
    }
}


public class CasLogoutHandler implements LogoutHandler, InitializingBean {
    private final HttpClient client = new HttpClient();
    private String casRestUri;

    @Override
    public void logout(final HttpServletRequest request, final HttpServletResponse response,
            final Authentication authentication) {
        try {
            if (authentication != null) {
                final DeleteMethod delete = new DeleteMethod(casRestUri + '/' + authentication.getCredentials());
                client.executeMethod(delete);
            }
        } catch (HttpException e) {
            throw new MosaicRuntimeException("Error when logging out from CAS", e);
        } catch (IOException e) {
            throw new MosaicRuntimeException("Error when logging out from CAS", e);
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.hasText(this.casRestUri, "A casRestUri must be set");
    }

    public void setCasRestUri(String casRestUri) {
        this.casRestUri = casRestUri;
    }
}


public class PortalCasAuthenticationProvider extends CasAuthenticationProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(PortalCasAuthenticationProvider.class);
    private TicketRetriever ticketRetriever;
    private PasswordEncoder passwordEncoder = new PlaintextPasswordEncoder();
    private AuthenticationService authenticationService;
    private Object salt;

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.ticketRetriever, "A ticketRetriever must be set");
        Assert.notNull(this.authenticationService, "Authentication Service must be set");
        super.afterPropertiesSet();
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        final Authentication authToken;
        if (isUsernamePasswordAuthentication(authentication)) {
            this.validate(authentication);
            authToken = this.getUsernamePasswordAuthentication(authentication);
        } else {
            authToken = authentication;
        }
        final CasAuthenticationToken auth = (CasAuthenticationToken) super.authenticate(authToken);
        final User user = (User) auth.getUserDetails();
        final UserDetails userDetails = authenticationService.getByUserId(user.getId());

        final CurrentUser currentUser = CurrentUser.builder().build(user, userDetails);
        return new CasAuthenticationToken(this.getKey(), currentUser, authentication.getCredentials(),
                auth.getAuthorities(), currentUser, auth.getAssertion());
    }

    private void validate(final Authentication authentication) {
        if (authentication.getCredentials() == null) {
            throw new BadCredentialsException(messages.getMessage("PortalCasAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }
    }

    private Authentication getUsernamePasswordAuthentication(final Authentication authentication) {
        final String reqUsername = authentication.getName();
        final String reqPassword = passwordEncoder.encodePassword(authentication.getCredentials().toString(), salt);
        try {
            final String username = CasAuthenticationFilter.CAS_STATEFUL_IDENTIFIER;
            final String password = ticketRetriever.getTicket(reqUsername, reqPassword);
            return new UsernamePasswordAuthenticationToken(username, password);
        } catch (final RuntimeException e) {
            LOGGER.error("Failed to retrieve ticket", e);
            throw new BadCredentialsException(e.getMessage(), e);
        }
    }

    private boolean isUsernamePasswordAuthentication(final Authentication authentication) {
        return authentication instanceof UsernamePasswordAuthenticationToken
                && (!CasAuthenticationFilter.CAS_STATEFUL_IDENTIFIER.equals(authentication.getPrincipal().toString()) && !CasAuthenticationFilter.CAS_STATELESS_IDENTIFIER
                        .equals(authentication.getPrincipal().toString()));
    }

    public void setTicketRetriever(final TicketRetriever ticketRetriever) {
        this.ticketRetriever = ticketRetriever;
    }

    public void setAuthenticationService(final AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    public void setPasswordEncoder(final PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public void setSalt(final Object salt) {
        this.salt = salt;
    }

}


public class AuthenticationServiceImpl implements AuthenticationService {

    public final VersionControlGateway versionControlGateway;
    public final AuditSessionService auditSessionService;
    private final SecurityGateway securityGateway;
    private final CurrentUserProvider currentUserProvider;

    @Inject
    public AuthenticationServiceImpl(final VersionControlGateway versionControlGateway,
            final AuditSessionService auditSessionService, final SecurityGateway securityGateway,
            final CurrentUserProvider currentUserProvider) {
        this.versionControlGateway = versionControlGateway;
        this.auditSessionService = auditSessionService;
        this.securityGateway = securityGateway;
        this.currentUserProvider = currentUserProvider;
    }

    @Override
    public void postSuccessfulLogin() {
        this.securityGateway.loadSecurityStore();
    }

    @Override
    public boolean isValidConfiguration() {
        final CurrentUser currentUser = currentUserProvider.getCurrentUser();
        return versionControlGateway.isValidConfiguration(currentUser);
    }
    
    @Override
    public long auditSessionLogin(final CurrentUser currentUser) {
        final long auditSessionId = this.auditSessionService.login(currentUser.getId(),
                new Long(currentUser.getActingForId()), currentUser.getRemoteHost(), currentUser.getRemoteAddress());
        return auditSessionId;
    }

    @Override
    public List<String> getInvalidComponents() {
        return versionControlGateway.getInvalidComponents(currentUserProvider.getCurrentUser());
    }
    
    @Override
    public void updateSecurityContext(final CurrentUser currentUser) {
        final SecurityContext context = SecurityContextHolder.getContext();
        final UsernamePasswordAuthenticationToken existingAuthorisation = (UsernamePasswordAuthenticationToken) context.getAuthentication();
        if (existingAuthorisation == null) {
            throw new IllegalStateException("updateSecurityContext was called when the existing SecurityContext did not hold the expected Authorisation");
        }
        final Collection<GrantedAuthority> authorities = existingAuthorisation.getAuthorities();
        final UsernamePasswordAuthenticationToken updatedAuthorisation = new UsernamePasswordAuthenticationToken(currentUser, null, authorities);
        context.setAuthentication(updatedAuthorisation);
    }

}

```
		    <beans:bean id="casFilter" class="org.springframework.security.cas.web.CasAuthenticationFilter">
		         <beans:property name="authenticationManager" ref="authenticationManager"/>
		         <beans:property name="authenticationSuccessHandler" ref="customAuthenticationSuccessHandler"/>
		         <beans:property name="proxyGrantingTicketStorage" ref="pgtStorage" />
		         <beans:property name="proxyReceptorUrl" value="/j_spring_cas_security_proxyreceptor" />
		     </beans:bean>

		     <beans:bean id="serviceProperties" class="org.springframework.security.cas.ServiceProperties">
		         <beans:property name="authenticateAllArtifacts" value="true" />
		         <beans:property name="service" value="${cas.service.url}/j_spring_security_check"/>
		         <beans:property name="sendRenew" value="false"/>
		     </beans:bean>

		     <!-- CAS LOGOUT -->
		     <!-- This filter handles a Single Logout Request from the CAS Server -->
		     <beans:bean id="singleLogoutFilter" class="org.jasig.cas.client.session.SingleSignOutFilter"/>

		     <!-- This filter redirects to the CAS Server to signal Single Logout should be performed -->
		     <beans:bean id="requestSingleLogoutFilter" class="org.springframework.security.web.authentication.logout.LogoutFilter">
		         <beans:constructor-arg name="logoutSuccessHandler" ref="customSpecialPageHandler" />
		         <beans:constructor-arg>
		             <beans:array>
		                 <beans:bean class="org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler" />
		                 <beans:bean class="com.mozanta.portal.authentication.logout.PortalCasLogoutHandler">
		                     <beans:property name="casRestUri" value="${cas.server.url}/v1/tickets" />
		                 </beans:bean>
		             </beans:array>
		         </beans:constructor-arg>
		     </beans:bean>

### Spring security configurations

	<authentication-manager alias="authenticationManager">
	        <authentication-provider ref="casAuthenticationProvider"/>
	    </authentication-manager>

	    <beans:bean id="casAuthenticationProvider" class="com.innovent.store.authentication.PortalCasAuthenticationProvider">
	        <beans:property name="authenticationUserDetailsService">
	            <beans:bean class="org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper">
	                <beans:constructor-arg ref="userDetailsService" />
	            </beans:bean>
	        </beans:property>
	        <beans:property name="serviceProperties" ref="serviceProperties" />
	        <beans:property name="ticketValidator">
	            <beans:bean class="org.jasig.cas.client.validation.Cas20ServiceTicketValidator">
	                <beans:constructor-arg value="${cas.server.url}" />
	                <beans:property name="proxyCallbackUrl" value="${cas.service.url}/j_spring_cas_security_proxyreceptor"/>
	                <beans:property name="proxyGrantingTicketStorage" ref="pgtStorage" />
	            </beans:bean>
	        </beans:property>
	        <beans:property name="key" value="system_cas"/>
	        <beans:property name="ticketRetriever" ref="serviceTicketRetriever"/>
	        <beans:property name="passwordEncoder" ref="passwordEncoder" />
	        <beans:property name="authenticationService" ref="authenticationService" />
	    </beans:bean>

	    <beans:bean id="pgtStorage" class="org.jasig.cas.client.proxy.ProxyGrantingTicketStorageImpl" />
	
### Portal CAS Authentication Provider

    public class PortalCasAuthenticationProvider extends PortalAuthenticationProvider {
    private MosaicGrantedAuthoritiesProvider grantedAuthoritiesProvider;

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final CasAuthenticationToken auth = (CasAuthenticationToken) super.authenticate(authentication);
        final Set<GrantedAuthority> authorities = grantedAuthoritiesProvider.provide((Principal) auth.getPrincipal());
        return new CasAuthenticationToken(this.getKey(), auth.getUserDetails(), authentication.getCredentials(),
                authorities, auth.getUserDetails(), auth.getAssertion());
    }

    public void setGrantedAuthoritiesProvider(MosaicGrantedAuthoritiesProvider grantedAuthoritiesProvider) {
        this.grantedAuthoritiesProvider = grantedAuthoritiesProvider;
    }
}

### Portal Authority Granter


public class BreadPermissionAuthorityGranter {

    private final AuthorisationService authorisationService;

    @Inject
    public BreadPermissionAuthorityGranter(final AuthorisationService authorisationService) {
        this.authorisationService = authorisationService;
    }

    public Set<BreadPermission> grant(final Principal principal) {
        final Set<BreadPermission> breadPermissionAuthorities = new HashSet<BreadPermission>();
        
        final List<BreadPermission> breadPermissions = this.authorisationService
                .retrieveBreadPermissions((CurrentUser) principal);
        
        for (final BreadPermission breadPermission : breadPermissions) {
            breadPermissionAuthorities.add(breadPermission);
        }
        
        return breadPermissionAuthorities;
    }

}

### Bread Permission

@SuppressWarnings("serial")
public class BreadPermission extends Permissions implements Cloneable, Serializable {

    private String uri;
    private String role;

    private BreadPermission(final Builder builder) {
        super(builder);
        this.uri = builder.uri;
        this.role = builder.role;
    }

    public String getUri() {
        return uri;
    }

    public String getRole() {
        return role;
    }

    public boolean isReadOnly() {
        return !(this.isEdit() || this.isAdd() || this.isDelete());
    }
    
    @Override
    public BreadPermission clone() {
        try {
            return (BreadPermission) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(); // Can't happen
        }
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("uri", this.uri).append("role", this.role).append("browse", isBrowse())
                .append("read", isRead()).append("edit", isEdit()).append("add", isAdd()).append("delete", isDelete())
                .toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || obj.getClass() != getClass()) {
            return false;
        }
        if (obj == this) {
            return true;
        }

        BreadPermission other = (BreadPermission) obj;
        return new EqualsBuilder().append(this.uri, other.uri).append(this.role, other.role)
                .append(isBrowse(), other.isBrowse()).append(this.isRead(), other.isRead())
                .append(this.isRead(), other.isRead()).append(this.isAdd(), other.isAdd())
                .append(this.isDelete(), other.isDelete()).isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(3, 5).append(this.uri).append(this.role).toHashCode();
    }

    public static class Builder extends Permissions.Builder {
        private String uri;
        private String role;

        public Builder(final GranularPermissionDTO granularPermissionDTO) {
            this.browse(granularPermissionDTO.isBrowse());
            this.read(granularPermissionDTO.isRead());
            this.edit(granularPermissionDTO.isEdit());
            this.add(granularPermissionDTO.isAdd());
            this.delete(granularPermissionDTO.isDelete());
            this.uri = granularPermissionDTO.getUri();
            this.role = granularPermissionDTO.getRole();
        }

        public Builder uri(final String uri) {
            this.uri = uri;
            return this;
        }

        public Builder role(final String role) {
            this.role = role;
            return this;
        }

        public Builder browse(final boolean browse) {
            super.browse(browse);
            return this;
        }

        public Builder read(final boolean read) {
            super.read(read);
            return this;
        }

        public Builder edit(final boolean edit) {
            super.edit(edit);
            return this;
        }

        public Builder add(final boolean add) {
            super.add(add);
            return this;
        }

        public Builder delete(final boolean delete) {
            super.delete(delete);
            return this;
        }

        public BreadPermission build() {
            return new BreadPermission(this);
        }
    }
}

### BreadPermissionGranted Authority


@SuppressWarnings("serial")
public class BreadPermissionGrantedAuthority implements GrantedAuthority {

    private final BreadPermission breadPermission;

    public BreadPermissionGrantedAuthority(final BreadPermission breadPermission) {
        this.breadPermission = breadPermission;
    }

    public String getAuthority() {
        return null;
    }
    
    public BreadPermission getBreadPermission() {
        return breadPermission;
    }

    public int hashCode() {
        return breadPermission.hashCode();
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj instanceof BreadPermissionGrantedAuthority) {
            BreadPermissionGrantedAuthority bpga = (BreadPermissionGrantedAuthority) obj;
            return this.breadPermission.equals(bpga.breadPermission);
        }

        return false;
    }

    public String toString() {
        return "Bread Authority [" + breadPermission.getUri() + "]";
    }
}

### AuditSessionFacade


public interface AuditSessionFacade {
    long login(long workerId, Long workerActingForId, String remoteHost, String remoteAddress);

    void logoff(long sessionId);

    void timeout(long sessionId);

    void audit(long sessionId, AuditOperationType auditedOperation, long auditedRecordId);

    void auditPersonSearch(long sessionId, AuditPersonSearchDTO auditPersonSearchDTO);

    void auditFailedLogOn(String systemUserId, String remoteHost, String remoteIpAddress);

    long portalLogin(CurrentUser user);
}


### TicketRetriever Interface

    
public interface TicketRetriever {
    String getTicket(String user);

    String getTicket (String username, String password);
}

### ServiceTicketRetriever

	import java.io.IOException;

	import org.apache.commons.httpclient.Header;
	import org.apache.commons.httpclient.HttpClient;
	import org.apache.commons.httpclient.HttpException;
	import org.apache.commons.httpclient.methods.PostMethod;
	import org.springframework.security.cas.ServiceProperties;
	import org.springframework.security.core.userdetails.UserDetails;
	import org.springframework.security.core.userdetails.UserDetailsService;

	import com.mozanta.portal.common.exceptions.PortalRuntimeException;

	public class ServiceTicketRetriever implements TicketRetriever {
	    private final HttpClient client = new HttpClient();
	    private UserDetailsService userDetailsService;
	    private String service;
	    private String url;

	    @Override
	    public String getTicket(final String user) {
	        final String tgtUrl = getTgtUrl(user);
	        final String serviceTicket = getServiceTicket(tgtUrl);
	        return serviceTicket;
	    }

	    @Override
	    public String getTicket(final String username, final String password) {
	        final String tgtUrl = getTgtUrl(username, password);
	        final String serviceTicket = getServiceTicket(tgtUrl);
	        return serviceTicket;
	    }

	    private String getServiceTicket(final String tgtUrl) {
	        final PostMethod postMethod = new PostMethod(tgtUrl);
	        postMethod.addParameter("service", getService());

	        final int status = execute(postMethod);
	        if (status != 200) {
	            throw new PortalRuntimeException("Failed to get TGT");
	        }
	        try {
	            return postMethod.getResponseBodyAsString();
	        } catch (IOException e) {
	            throw new PortalRuntimeException(e);
	        }
	    }

	    private String getTgtUrl(final String username, final String password) {
	        final PostMethod postMethod = new PostMethod(getUrl());
	        postMethod.addParameter("username", username);
	        postMethod.addParameter("password", password);
	        final int status = execute(postMethod);
	        if (status != 201) {
	            throw new PortalRuntimeException("Failed to authenticate using the provided account.");
	        }
	        final Header location = postMethod.getResponseHeader("Location");
	        return location.getValue();
	    }

	    private String getTgtUrl(final String user) {
	        final UserDetails userDetails = userDetailsService.loadUserByUsername(user);
	        return this.getTgtUrl(userDetails.getUsername(), userDetails.getPassword());
	    }

	    private int execute(final PostMethod postMethod) {
	        try {
	            final int status = client.executeMethod(postMethod);
	            return status;
	        } catch (HttpException e) {
	            throw new PortalRuntimeException(e);
	        } catch (IOException e) {
	            throw new PortalRuntimeException(e);
	        }
	    }

	    public String getService() {
	        return service;
	    }

	    public String getUrl() {
	        return url;
	    }

	    public void setUrl(String url) {
	        this.url = url;
	    }

	    public void setServiceProperties(final ServiceProperties serviceProperties) {
	        service = serviceProperties.getService();
	    }

	    public UserDetailsService getUserDetailsService() {
	        return userDetailsService;
	    }

	    public void setUserDetailsService(UserDetailsService userDetailsService) {
	        this.userDetailsService = userDetailsService;
	    }

	}
	
# The Target Side Configurations
	
###Ticket Validation Side TargetURL

		<sec:custom-filter ref="casFilter" position="CAS_FILTER" />
        <sec:custom-filter ref="casLogoutFilter" before="LOGOUT_FILTER"/>
		
		<bean id="casFilter" class="org.springframework.security.cas.web.CasAuthenticationFilter">
		        <property name="authenticationManager" ref="casAuthenticationManager" />
		        <property name="authenticationFailureHandler" ref="casAuthenticationFailureHandler" />
		        <property name="proxyAuthenticationFailureHandler" ref="casProxyAuthenticationFailureHandler" />
		        <property name="serviceProperties" ref="serviceProperties" />
		        <property name="authenticationDetailsSource">
		            <bean
		                class="org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsSource">
		                <constructor-arg ref="serviceProperties"/>
		             </bean>
		        </property>
		    </bean>
			
			<sec:authentication-manager id="casAuthenticationManager">
			        <sec:authentication-provider ref="casProxyAuthenticationProvider" />
			    </sec:authentication-manager>

			    <bean id="casProxyAuthenticationProvider"
			        class="com.mozanta.application.security.cas.MosaicCasAuthenticationProvider">
			        <property name="ticketValidator">
			            <bean class="org.jasig.cas.client.validation.Cas20ProxyTicketValidator">
			                <constructor-arg value="#{T(org.apache.commons.lang3.StringUtils).defaultIfEmpty(T(com.mozanta.common.util.FrameworkProperties).get('casUrl'),'https://localhost:8443/cas')}" />
			                <property name="acceptAnyProxy" value="true" />
			            </bean>
			        </property>
			        <property name="authenticationUserDetailsService">
			            <bean class="com.mozanta.application.authentication.service.CasUserDetailsService"/>
			        </property>
        
			        <property name="grantedAuthoritiesProvider" ref="mosaicGrantedAuthoritiesProvider"></property>
			        <property name="key" value="mozanta_cas" />
			    </bean>
    
			    <bean id="casLogoutSuccessHandler" class="com.mozanta.application.security.cas.CasLogoutSuccessHandler" />
			    <bean id="casLogoutHandler" class="com.mozanta.application.security.cas.CasLogoutHandler">
			       <property name="casRestUri" value="#{T(org.apache.commons.lang3.StringUtils).defaultIfEmpty(T(com.mozanta.framework.common.util.FrameworkProperties).get('casUrl'),'https://localhost:8443/cas')}/v1/tickets" />
			    </bean>
    
			    <!-- This filter redirects to the CAS Server to signal Single Logout should be performed -->
			    <bean id="casLogoutFilter" class="org.springframework.security.web.authentication.logout.LogoutFilter">
			        <constructor-arg name="logoutSuccessHandler" ref="casLogoutSuccessHandler" />
			        <constructor-arg>
			            <array>
			                <bean class="org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler" />
			                <ref bean="casLogoutHandler"/>
			            </array>
			        </constructor-arg>
			        <!-- Currently limited to portal access, can be extended to use other URL patterns with Regex matcher if needed.  -->
			        <property name="filterProcessesUrl" value="/controller/portal/authentication/logout"></property>
			    </bean>
				
			       <bean id="tokenServices" class="org.springframework.security.oauth2.provider.token.DefaultTokenServices">
			           <property name="tokenStore" ref="tokenStore" />
			           <property name="supportRefreshToken" value="true" />
			           <property name="clientDetailsService" ref="clientDetails" />
			       </bean>
			       
### TokenStore sample implementation


import javax.inject.Inject;

import org.apache.commons.lang3.Validate;
import org.springframework.stereotype.Service;

import uk.co.corelogic.gateway.common.security.CurrentUser;
import uk.co.corelogic.mosaic.common.exception.ValidationErrorException;

@Service
public class MockTokenStore {

    private final Map<String, AccessToken> tokensByTokenId = new HashMap<String, AccessToken>();
    private final Map<String, CurrentUser> currentUsersByTokenId = new HashMap<String, CurrentUser>();
    private final AccessTokenFactory tokenFactory;
    
    @Inject
    private MockTokenStore(final AccessTokenFactory tokenFactory) {
        this.tokenFactory = tokenFactory;
    }

    public AccessToken createToken(final CurrentUser currentUser) {
        Validate.notNull(currentUser);
        final AccessToken accessToken = tokenFactory.createAccessToken(currentUser);
        tokensByTokenId.put(accessToken.getToken(), accessToken);
        currentUsersByTokenId.put(accessToken.getToken(), currentUser);
        return accessToken;
    }

    public CurrentUser getCurrentUser(final String token) {
        final AccessToken accessToken = tokensByTokenId.get(token);

        if (accessToken == null) {
            throw new ValidationErrorException("no token found");
        }

        if (System.currentTimeMillis() > accessToken.getExpiry()) {
            throw new ValidationErrorException("token expired");
        }

        final CurrentUser currentUser = currentUsersByTokenId.get(token);
        return currentUser;
    }

}

### client details class 

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;

public class ClientDetailsImpl implements ClientDetails {

    private Integer accessTokenValiditySeconds;
    private String clientId;
    private Collection<GrantedAuthority> authorities;
    private Set<String> authorizedGrantTypes;
    private String clientSecret;
    private boolean isSecretRequired;
    private boolean isScoped;
    private Integer refreshTokenValiditySeconds;
    private Set<String> registeredRedirectUri;
    private Set<String> resourceIds;
    private Set<String> scope;
    private Map<String, Object> additionalInformation;

    @Override
    public Integer getAccessTokenValiditySeconds() {
        return accessTokenValiditySeconds;
    }

    public void setAccessTokenValiditySeconds(Integer accessTokenValiditySeconds) {
        this.accessTokenValiditySeconds = accessTokenValiditySeconds;
    }

    @Override
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public Set<String> getAuthorizedGrantTypes() {
        return authorizedGrantTypes;
    }

    public void setAuthorizedGrantTypes(Set<String> authorizedGrantTypes) {
        this.authorizedGrantTypes = authorizedGrantTypes;
    }

    @Override
    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    @Override
    public boolean isSecretRequired() {
        return isSecretRequired;
    }

    public void setSecretRequired(boolean isSecretRequired) {
        this.isSecretRequired = isSecretRequired;
    }

    @Override
    public boolean isScoped() {
        return isScoped;
    }

    public void setScoped(boolean isScoped) {
        this.isScoped = isScoped;
    }

    @Override
    public Integer getRefreshTokenValiditySeconds() {
        return refreshTokenValiditySeconds;
    }

    public void setRefreshTokenValiditySeconds(Integer refreshTokenValiditySeconds) {
        this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
    }

    @Override
    public Set<String> getRegisteredRedirectUri() {
        return registeredRedirectUri;
    }

    public void setRegisteredRedirectUri(Set<String> registeredRedirectUri) {
        this.registeredRedirectUri = registeredRedirectUri;
    }

    @Override
    public Set<String> getResourceIds() {
        return resourceIds;
    }

    public void setResourceIds(Set<String> resourceIds) {
        this.resourceIds = resourceIds;
    }

    @Override
    public Set<String> getScope() {
        return scope;
    }

    public void setScope(Set<String> scope) {
        this.scope = scope;
    }

    @Override
    public Map<String, Object> getAdditionalInformation() {
        return additionalInformation;
    }

    public void setAdditionalInformation(Map<String, Object> additionalInformation) {
        this.additionalInformation = additionalInformation;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAutoApprove(String s) {
        return false;
    }

    public void setAuthorities(final Collection<GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

}


### Portal Authentication Provider


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.authentication.encoding.PlaintextPasswordEncoder;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

import uk.co.corelogic.mosaic.portal.authentication.service.AuthenticationService;
import uk.co.corelogic.mosaic.portal.common.domain.model.CurrentUser;
import uk.co.corelogic.mosaic.portal.common.persistence.domain.model.UserDetails;

import com.backbase.portal.foundation.domain.model.User;


public class PortalCasAuthenticationProvider extends CasAuthenticationProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(PortalCasAuthenticationProvider.class);
    private TicketRetriever ticketRetriever;
    private PasswordEncoder passwordEncoder = new PlaintextPasswordEncoder();
    private AuthenticationService authenticationService;
    private Object salt;

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.ticketRetriever, "A ticketRetriever must be set");
        Assert.notNull(this.authenticationService, "Authentication Service must be set");
        super.afterPropertiesSet();
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        final Authentication authToken;
        if (isUsernamePasswordAuthentication(authentication)) {
            this.validate(authentication);
            authToken = this.getUsernamePasswordAuthentication(authentication);
        } else {
            authToken = authentication;
        }
        final CasAuthenticationToken auth = (CasAuthenticationToken) super.authenticate(authToken);
        final User user = (User) auth.getUserDetails();
        final UserDetails userDetails = authenticationService.getByUserId(user.getId());

        final CurrentUser currentUser = CurrentUser.builder().build(user, userDetails);
        return new CasAuthenticationToken(this.getKey(), currentUser, authentication.getCredentials(),
                auth.getAuthorities(), currentUser, auth.getAssertion());
    }

    private void validate(final Authentication authentication) {
        if (authentication.getCredentials() == null) {
            throw new BadCredentialsException(messages.getMessage("PortalCasAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }
    }

    private Authentication getUsernamePasswordAuthentication(final Authentication authentication) {
        final String reqUsername = authentication.getName();
        final String reqPassword = passwordEncoder.encodePassword(authentication.getCredentials().toString(), salt);
        try {
            final String username = CasAuthenticationFilter.CAS_STATEFUL_IDENTIFIER;
            final String password = ticketRetriever.getTicket(reqUsername, reqPassword);
            return new UsernamePasswordAuthenticationToken(username, password);
        } catch (final RuntimeException e) {
            LOGGER.error("Failed to retrieve ticket", e);
            throw new BadCredentialsException(e.getMessage(), e);
        }
    }

    private boolean isUsernamePasswordAuthentication(final Authentication authentication) {
        return authentication instanceof UsernamePasswordAuthenticationToken
                && (!CasAuthenticationFilter.CAS_STATEFUL_IDENTIFIER.equals(authentication.getPrincipal().toString()) && !CasAuthenticationFilter.CAS_STATELESS_IDENTIFIER
                        .equals(authentication.getPrincipal().toString()));
    }

    public void setTicketRetriever(final TicketRetriever ticketRetriever) {
        this.ticketRetriever = ticketRetriever;
    }

    public void setAuthenticationService(final AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    public void setPasswordEncoder(final PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public void setSalt(final Object salt) {
        this.salt = salt;
    }

}

### Granted Authorities


import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.jaas.AuthorityGranter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

import uk.co.corelogic.mosaic.configuration.domain.BreadPermission;

public class GrantedAuthoritiesProvider implements InitializingBean {
    private AuthorityGranter[] authorityGranters;
    private BreadPermissionAuthorityGranter[] breadPermissionsAuthorityGranters;

    public void setAuthorityGranters(AuthorityGranter[] authorityGranters) {
        this.authorityGranters = authorityGranters;
    }

    public void setBreadPermissionAuthorityGranters(BreadPermissionAuthorityGranter[] breadPermissionsAuthorityGranters) {
        this.breadPermissionsAuthorityGranters = breadPermissionsAuthorityGranters;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notEmpty(authorityGranters, "authorityGranters cannot be null or empty");
        Assert.notEmpty(breadPermissionsAuthorityGranters, "breadPermissionsAuthorityGranters cannot be null or empty");
    }

    public Set<GrantedAuthority> provide(final Principal principal) {
        final Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
        for (AuthorityGranter granter : authorityGranters) {
            final Set<String> roles = granter.grant(principal);

            // If the granter doesn't wish to grant any authorities, it should
            // return null.
            if ((roles != null) && !roles.isEmpty()) {
                for (String role : roles) {
                    authorities.add(new SimpleGrantedAuthority(role));
                }
            }
        }

        for (BreadPermissionAuthorityGranter breadGranter : breadPermissionsAuthorityGranters) {
            Set<BreadPermission> breadPermissions = breadGranter.grant(principal);
            if ((breadPermissions != null) && !breadPermissions.isEmpty()) {
                for (BreadPermission breadPermission : breadPermissions) {
                    authorities.add(new BreadPermissionGrantedAuthority(breadPermission));
                }
            }
        }

        return authorities;
    }
}


### AccessToken Factory


import java.util.UUID;

import org.apache.commons.lang3.Validate;
import org.springframework.stereotype.Service;

import uk.co.corelogic.gateway.common.security.CurrentUser;

@Service
public class AccessTokenFactory {

    private final long EXPIRY_PERIOD = 1800000;

    public AccessToken createAccessToken(final CurrentUser currentUser) {
        Validate.notNull(currentUser);
        final AccessToken accessToken = new AccessToken();
        accessToken.setExpiry(System.currentTimeMillis() + EXPIRY_PERIOD);
        accessToken.setSecret(UUID.randomUUID().toString());
        accessToken.setToken(UUID.randomUUID().toString());
        accessToken.setWorkerId(Long.toString(currentUser.getActingForId()));
        return accessToken;
    }
}

### Access Token


public class AccessToken {

    private String workerId;
    private long expiry;
    private String token;
    private String secret;

    public String getWorkerId() {
        return workerId;
    }

    public void setWorkerId(String workerId) {
        this.workerId = workerId;
    }

    public long getExpiry() {
        return expiry;
    }

    public void setExpiry(long expiry) {
        this.expiry = expiry;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }
    
    @Override
    public boolean equals(Object object) {
        if(object == null || !(object instanceof AccessToken)) {
            return false;
        }
        if(this.token == null || ((AccessToken) object).getToken() == null) {
            return false;
        }
        return this.token.equals(((AccessToken) object).getToken());
    }
    
    @Override
    public int hashCode() {
        return this.token.hashCode();
    }
}
