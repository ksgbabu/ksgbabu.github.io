---
layout: post
---

I knew the concept of class loaders and its hierarchies.  But was not very sure about the difference between the classloader difference when it is related to ThreadContext.  I got a read today, it says, that is something related the Thread which the class is being executed. At the momement what I understood is that will have more visibility to the other class than the class level class loader has.

There are some concepts around Class-loaders such that they can load classes parallel.  ClassLoader.registerAsParallelCapable method is for that capability.  This is the default behaviour of it.  But their sub-classes still neede to register if they are parallely capable.  If they are not loading classes in parallel then there can be a serious issue of deadlock beacuse of loader lock.  This can be seen at loadClass method.




