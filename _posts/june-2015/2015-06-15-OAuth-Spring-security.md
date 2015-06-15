---
layout: post
---

The first step in spring security OAuth to define Authorization-Server, which define authorization flows to support.

	<oauth:authorization-server client-details-service-ref="clientDetails" token-services-ref="tokenServices">
	        <oauth:authorization-code />
	        <oauth:implicit />
	        <oauth:refresh-token />
	        <oauth:client-credentials />
	        <oauth:password />
	    </oauth:authorization-server>

Second step is to protect the auth/token endpoint.

    <http pattern="/oauth/**" create-session="stateless" authentication-manager-ref="clientAuthenticationManager"
             use-expressions="false">
         <anonymous enabled="false" />
         <csrf disabled="true"/>
         <intercept-url pattern="/oauth/**" access="IS_AUTHENTICATED_FULLY" />
         <http-basic entry-point-ref="clientAuthenticationEntryPoint" />
         <access-denied-handler ref="oauthAccessDeniedHandler" />
     </http>

Third step is to configure the authentication manager and client details service:

    <authentication-manager id="clientAuthenticationManager">
          <authentication-provider ref="daoAuthenticationProvider" />
      </authentication-manager>
	  
    <bean id="clientDetails" class="org.springframework.security.oauth2.provider.client.JdbcClientDetailsService">
         <constructor-arg ref="dataSource"/>
         <property name="passwordEncoder" ref="passwordEncoder" /> 
    </bean>
	
* token service
 
    <bean id="tokenServices" class="org.springframework.security.oauth2.provider.token.DefaultTokenServices">
        <property name="tokenStore" ref="tokenStore" />
        <property name="supportRefreshToken" value="true" />
        <property name="clientDetailsService" ref="clientDetails" />
    </bean>

*  Configure each access points as:
 
	<http pattern="/v1/persons/**" create-session="never" entry-point-ref="oauthAuthenticationEntryPoint"
	        access-decision-manager-ref="accessDecisionManager" use-expressions="false">
	        <anonymous enabled="false" />
	        <intercept-url pattern="/v1/persons/**" access="ROLE_CLIENT" />
	        <custom-filter ref="oauth2ProviderFilter" before="PRE_AUTH_FILTER" />
	        <custom-filter ref="currentUserProviderFilter" before="BASIC_AUTH_FILTER" />
	        <access-denied-handler ref="oauthAccessDeniedHandler" />
	</http>
    <bean:bean id="oauthAuthenticationEntryPoint" class="org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint">
        <bean:property name="realmName" value="Secured APIs" />
    </bean:bean>	
	
	<bean:bean id="accessDecisionManager" class="org.springframework.security.access.vote.UnanimousBased">
	      <bean:constructor-arg>
	          <bean:list>
	              <bean:bean class="org.springframework.security.oauth2.provider.vote.ScopeVoter" />
	              <bean:bean class="org.springframework.security.access.vote.RoleVoter" />
	              <bean:bean class="org.springframework.security.access.vote.AuthenticatedVoter" />
	          </bean:list>
	      </bean:constructor-arg>
	 </bean:bean>
	
	 <oauth:resource-server id="oauth2ProviderFilter" token-services-ref="tokenServices" />
	 
	 <bean:bean id="currentUserProviderFilter" class="app.api.security.WebApiCurrentUserProviderFilter" > 
	        <bean:property name="authenticationManager" ref="webApiAuthenticationManager" />
	        <bean:property name="webApiClientLoginFailureHandler" ref="webApiClientLoginFailureHandler" />
	  </bean:bean> 	
	  
      <authentication-manager alias="webApiAuthenticationManager">
           <authentication-provider ref="webApiCurrentUserProvider" />
       </authentication-manager>
    
       <bean:bean id="webApiClientLoginFailureHandler" class="app.api.security.DefaultWebApiClientLoginFailureHandler"/>
    
       <bean:bean id="webApiCurrentUserProvider" class="app.api.security.WebApiCurrentUserProvider"> 
           <bean:constructor-arg ref="webApiClientFacadeImpl" />
       </bean:bean>
	   
*  Protecting access to Resources

For this configure a spring resource server filter.  This will check that there is a valid access token in the request header.

       <oauth:resource-server id="oauth2ProviderFilter" token-services-ref="tokenServices" />
	
-- example for filter

	package app.api.security;

	import java.io.IOException;

	import javax.servlet.FilterChain;
	import javax.servlet.ServletException;
	import javax.servlet.ServletRequest;
	import javax.servlet.ServletResponse;
	import javax.servlet.http.HttpServletRequest;
	import javax.servlet.http.HttpServletResponse;

	import org.apache.commons.lang3.Validate;
	import org.springframework.security.authentication.AuthenticationManager;
	import org.springframework.security.core.context.SecurityContextHolder;
	import org.springframework.security.oauth2.provider.OAuth2Authentication;
	import org.springframework.web.filter.GenericFilterBean;

	import app.api.security.WebApiOAuth2Authentication;

	public class WebApiCurrentUserProviderFilter extends GenericFilterBean {

	    private AuthenticationManager authenticationManager;
	    private WebApiClientLoginFailureHandler failureHandler = new DefaultWebApiClientLoginFailureHandler();
    
	    @Override
	    public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain) throws IOException,
	            ServletException {
	        final OAuth2Authentication authRequest =  (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
	        try {
	            final WebApiOAuth2Authentication authResult = (WebApiOAuth2Authentication) getAuthenticationManager().authenticate(authRequest);
	            SecurityContextHolder.getContext().setAuthentication(authResult);
	        } catch (Exception exception) {
	            failureHandler.handle((HttpServletRequest) req, (HttpServletResponse) res, exception);
	            return;
	        }    
	        chain.doFilter(req, res);
	    }

	    public void setAuthenticationManager(final AuthenticationManager authenticationManager) {
	        Validate.notNull(authenticationManager, "authenticationManager cannot be null");
	        this.authenticationManager = authenticationManager;
	    }

	    protected AuthenticationManager getAuthenticationManager() {
	        return authenticationManager;
	    }

	    public void setWebApiClientLoginFailureHandler(final WebApiClientLoginFailureHandler failureHandler) {
	        Validate.notNull(failureHandler, "failureHandler cannot be null");
	        this.failureHandler = failureHandler;
	    }

	    protected WebApiClientLoginFailureHandler getWebApiClientLoginFailureHandlerHandler() {
	        return failureHandler;
	    }
	}	
	
-- example for webpiClientFacacdeImpl

	package app.webapiclient.facade;

	import java.util.List;

	import javax.inject.Inject;

	import org.springframework.stereotype.Service;
	import org.springframework.transaction.annotation.Propagation;
	import org.springframework.transaction.annotation.Transactional;

	import app.gateway.common.security.CurrentUser;
	import app.application.webapiclient.service.WebApiClientService;
	import app.common.advice.PerformanceLogging;
	import app.dto.webapiclient.ClientDetailsDTO;

	@Service
	@PerformanceLogging
	public class WebApiClientFacadeImpl implements WebApiClientFacade {

	    private final WebApiClientService webApiClientService;

	    @Inject
	    public WebApiClientFacadeImpl(final WebApiClientService webApiClientService) {
	        this.webApiClientService = webApiClientService;
	    }

	    @Override
	    @Transactional(propagation = Propagation.NEVER)
	    public List<ClientDetailsDTO> retrieveWebApiClients() {
	        return webApiClientService.retrieveWebApiClients();
	    }

	    @Override
	    @Transactional(propagation = Propagation.REQUIRES_NEW)
	    public void createWebApiClient(final ClientDetailsDTO webApiClient, final CurrentUser currentUser) {
	        webApiClientService.createWebApiClient(webApiClient, currentUser);
	    }

	    @Override
	    @Transactional(propagation = Propagation.REQUIRES_NEW)
	    public void updateWebApiClient(final ClientDetailsDTO webApiClient, final CurrentUser currentUser) {
	        webApiClientService.updateWebApiClient(webApiClient, currentUser);
	    }

	    @Override
	    @Transactional(propagation = Propagation.REQUIRES_NEW)
	    public void deleteWebApiClient(final String clientId, final CurrentUser currentUser) {
	        webApiClientService.deleteWebApiClient(clientId, currentUser);
	    }

	    @Override
	    @Transactional(propagation = Propagation.REQUIRES_NEW)
	    public CurrentUser login(final String clientId) {
	        return webApiClientService.login(clientId);
	    }

	    @Override
	    @Transactional(propagation = Propagation.REQUIRES_NEW)
	    public void logoff(final CurrentUser currentUser) {
	        webApiClientService.logoff(currentUser);
	    }
	}
    


