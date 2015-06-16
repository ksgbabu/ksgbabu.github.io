---
layout: post
---

I came across to the usage of API-Gateway pattern which is a part of microservices architecture.  The usual questions that arises are related to the granularity of services exposed at server side.  Different client might require different data.  Typically a desktop page details will be more elaborative than a mobile version of the site.  Network performance will be different for different type of clients.  

We could provide a gateway-api that is a single point for all clients.  Some requests are simply proxied/routed to the appropriate services.  It handles other requests by fanning out to multiple services.

** Using Gateway-API has the following benefits **

-  Insulates the client from how the application is partitioned into microservices
-  Insulates the client from the problem of determining the locations of service instances
-  Provides the optimal API for each client
-  Reduces the number of requests roundtrips.  That means the gateway can collect data from multiple services and send a single response
-  Simplifies the client by moving logic for calling multiple services from the client to API gateway.

** The drawbacks are **

-  Increased complexity - another moving part to be deployed and configured
-  Increased response time due to additonal n/w hop through API gateway

** How to implement the API gateway **

An event driven/reactive approach is best if it must scale to handle high loads.  Netty, Spring Reactor, Nodejs are the choices.


