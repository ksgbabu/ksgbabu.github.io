---
layout: post
---

I was thinking about what would be the trick they do in java to have an Unmodifiable Collections.  When I looked inside I understood that it is just a wrapper overriding the methods put, add etc to through Unsupported exceptions.  Also they extend the entry sets (incase of Map) and make sure they are also unmodifiable. 

Also find an interesting part in collection as Synchronized Collections, where they define a mutex and add synchronized blocks for each operations.  I think the threads will all will be queued up there an thus the data will be having some stability on concurrency issues.

