---
layout: post
title: "Http client Search"
date: 2015-05-22 17:38:54
categories: http client
---

My job is to find an http client which is suitable for connecting in between two different systems that we are developing now.  There are too many choices but I have a doubt in my criterial lists that I am using for comparing them.  

I kind of set aside http client in the initial phase itself.  Looks like it is very heavy weight.  The second tool was Jetty.  That looks like an appropriate tool as of now.  But I was not able to find the source code of it.  Is that really open source.  I think so by looking at its package structure with eclipse in it.  Let me see...

I think I got the solution.  I went and search in the apache maven repo and found some reference on it.

	<dependency>
	    <groupId>org.eclipse.jetty</groupId>
	    <artifactId>jetty-client</artifactId>
	    <version>9.3.0.RC0</version>
	</dependency>

Unfortunately that version was not supporting jre 1.6 and my all efforts like went vain.  So some of my colleague suggested to use spray-can but that is in scala and did not get any head start on it.  Possibly every line of code and api has to be translated to Java eventhough it is not laborious any way.

One big mistake was I did not check the API list and document within the code. I hope I can do it when I get some time.  It is a good idea to look at the API list and if any documentation around it (say grep code).

