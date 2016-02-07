---
layout: post
title: Sample Spring Test for Camel
---


How to write test for Camel was a day of effort.  Especially using the latest tools like spring 4.1, camel 2.15.  But the beauty is to keep the spring dsl xml in the class path where the package path should be the same.  Say we can keep the spring dsl xml in test/resources/com/ksgbabu/gateway/Usercontext...-context.xml

### Sample code

	package com.ksgbabu.gateway;

	import com.ksgbabu.gateway.processor.UserContextPopulatingProcessor;
	import org.apache.camel.EndpointInject;
	import org.apache.camel.Exchange;
	import org.apache.camel.Produce;
	import org.apache.camel.ProducerTemplate;
	import org.apache.camel.component.mock.MockEndpoint;
	import org.apache.camel.test.spring.CamelSpringJUnit4ClassRunner;
	import org.apache.camel.test.spring.CamelTestContextBootstrapper;
	import org.junit.Assert;
	import org.junit.Test;
	import org.junit.runner.RunWith;
	import org.mockito.Mockito;
	import org.slf4j.Logger;
	import org.slf4j.LoggerFactory;
	import org.springframework.test.annotation.DirtiesContext;
	import org.springframework.test.context.BootstrapWith;
	import org.springframework.test.context.ContextConfiguration;

	import javax.servlet.http.HttpServletRequest;
	import javax.servlet.http.HttpSession;
	import java.net.URISyntaxException;
	import java.util.Enumeration;

	import static org.mockito.Matchers.any;


	/**
	 * Created by gireeshbabu on 05/02/16.
	 */

	@RunWith(CamelSpringJUnit4ClassRunner.class)
	@BootstrapWith(CamelTestContextBootstrapper.class)
	@ContextConfiguration
	public class UserContextPopulatingProcessorTest{

	    public static Logger logger = LoggerFactory.getLogger(UserContextPopulatingProcessor.class);

	    @Produce(uri = "direct://start")
	    protected ProducerTemplate template;

	    @EndpointInject(uri = "mock://gw/html")
	    protected MockEndpoint gwHtmlEndpoint;

	    @Test
	    @DirtiesContext
	    public void shouldPopulateContext() throws InterruptedException, URISyntaxException {

	        logger.debug("￿cuted");
	        gwHtmlEndpoint.expectedMessageCount(1);

	        HttpServletRequest request = getHttpServletRequest();
	        template.sendBodyAndHeader("direct://start","{message:1}","CamelHttpServletRequest", request);

	        Exchange exchange = getExchange();
	        Assert.assertEquals("{message:1}",exchange.getIn().getBody());

	        Assert.assertEquals(9,exchange.getIn().getHeaders().size());

	    }

	    private Exchange getExchange() {
	        Exchange exchange = gwHtmlEndpoint.getExchanges().get(0);
	        Assert.assertNotNull(exchange);
	        return exchange;
	    }

	    private HttpServletRequest getHttpServletRequest() {
	        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
	        Mockito.when(request.getRemoteUser()).thenReturn("myUser");
	        Mockito.when(request.getRemoteAddr()).thenReturn("myAddr");
	        HttpSession session = Mockito.mock(HttpSession.class);
	        Mockito.when(session.getId()).thenReturn("");
	        Mockito.when(session.getAttribute("partyId")).thenReturn("myParty");
	        Mockito.when(request.getSession()).thenReturn(session);
	        Enumeration enumeration = Mockito.mock(Enumeration.class);
	        Mockito.when(enumeration.hasMoreElements()).thenReturn(false);
	        Mockito.when(request.getHeaders(any(String.class))).thenReturn(enumeration);
	        return request;
	    }
	}
	