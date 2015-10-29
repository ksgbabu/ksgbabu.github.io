---
layout: post
---

The description of various Camel components.

Service
-------
Basic interface in Camel is Service which has a start and stop method.  Suspendable Service is an extension of it having suspend and resume methods.  ShutdownableService also a sibling to the former. StatefulService again extending both of these Services and provide the status related info like isStarted. ServiceSupport just help to change the state of the Service. 

Consumer and Producer
-------------------
 Every Consumer, Producer, Component etc. are extension of ServiceSupport.  A producer or consumer will have an endpoint inside it.  Producer can create Exchange.
 
Component
--------
  A component can create endpoint from the uri.  It can *create both endpoint* and component configuration.  
  
Endpoint
---------
  
 Endpoint will have a uri and configuration it will have a key.  It can create producer, consumer and exchange. It embeds the component that uses to create the endpoint.  
 
Exchange
-------
 It has context, Properties, in and out messages, exception, exchangeID, UnitOfWork, pattern, fromEndPoint, fromRoutId, onCompletions List.
 
Context
---------
It is a collection of all in Camel like routeDefinitions, consumers, producers, components, endpoints, routes, typeConverter, type converterRegistry, registry etc.  It can create	both consumer and producerTemplates 

InterceptorStrategy
------------------
To know how exceptions are built. 

Message
-------
Body, headers Map, attachments map, 


 
 
 