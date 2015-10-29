---
layout: post
---

Basic concept in CXF is an interceptor.  The interceptors are in, out and inFault and outFault. Interceptor has a method handleMessage and hanldeFault.  

Message
---------
It is a map.  It is an id, InterceptorChain, Exchange, Attachment, Content and ContextCache.

Bus
---
Provides a mechanism where many interceptors can be registered to process messages.  A Bus has features, properties and extensions and extensionManager.  

Service
------
It has list of ServiceInfos, data binding, executor, invoker, and endpoints.  Databinding is to create reader and writer.  For example for a JaxRS service it can have additional service name and address.   Simpling binding means create message.

MessageInfo
-----------
MessageInfo has a name, operation, messageparts map, outof band parts, 

OperationInfo
-----------
InterfaceInfo, name, in and out MessageInfo, faults, unwrapped operation, parameter ordering. 

BindingInfo
----------
Service and Operations.  

Exchange
---------
It holds Bus, Service, endpoint, binding and bindingoperation info. 


 