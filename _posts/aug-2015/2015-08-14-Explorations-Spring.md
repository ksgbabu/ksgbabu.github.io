---
layout: post
---

I started going through one of the code that was given for review to me.  And some findings and learning that I had is added here.

The basic concept of configurations in any project/application is Resource and which is an InputStreamSource.  Input stream source can be an interface that will have getInputStream.  AbstractResource class will impelement this resource. The AbstractFileResolvingResource works on files. ClassPathResource uses this abstraction.  ClassPathResource has inner attributes which are path, classloader and class attributes.

There is a ResourceLoader interface which implements getResource and getClassLoader methods.  DefaultResourceLoader class will have a class loader variable embedded so that any-one can set the class loader to it.  When an empty constructor of DefaultResourceLoader is called it uses getDefaultClassLoader() method of ClassUtils.  This method eventually returns either the thread-context-class loader or the default classloader or the system classloader.  see the post (classloaders-java) in this blog.

There is an another interface ContextResource which is an extension of Resource with a method getPathWithinContext() method.  There is something like ClassPathContextResource which is an extension of ClassPathResource which is a protected innerclass of DefaultResourceLoader class. This enables DefaultResourceLoader to find the context-relative resource and load it.

AbstractApplicationContext is an extension of DefaultResourceLoader and implements ConfigurableApplicationContext.  ApplicationContext is the concept and interface which has abilities such as (implements interfaces) ResourceLoader, ApplicationEventPublisher (can publish events), MessageSource (getMessage method), Heirarchical and Listable BeanFactory (getBean method) and EnvironmentCapable (getEnvironment method).  The ApplicationContext gives the methods like applicationName, parent, and AutowireCapableBeanFactory.  The AbstractApplicatonContext class is extended by AbstractRefreshableApplicationContext.  



 