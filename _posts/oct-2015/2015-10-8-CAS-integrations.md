---
layout: post
title: Spring security
---

# The Source Side Configurations

To explain the steps and configurations for Spring to CAS integration.

### Spring security filter configurations

Add a custom filter in the security.xm

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