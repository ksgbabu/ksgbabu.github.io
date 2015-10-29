---
layout: post
---

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
	

### Service Ticket Retriever


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