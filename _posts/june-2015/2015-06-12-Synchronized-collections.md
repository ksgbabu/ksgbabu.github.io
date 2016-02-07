---
layout: post
---

I found interesting part in collection class as Synchronized Collections, where they define a mutex and add synchronized blocks for each operations.  I think the threads will all will be queued up there an thus the data will be having some stability on concurrency issues.

In the queued up scenarios will jvm take care unnecessary thread switches?  My question in mind is, as the thread has no anything to do now as they are queued up.  The unnecessary switching (in context thread switching) can be avoided.  I hope JVM would have handled this situation gracefully.

