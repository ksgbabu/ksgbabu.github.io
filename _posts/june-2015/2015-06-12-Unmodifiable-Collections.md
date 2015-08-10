---
layout: post
---

I was thinking about what would be the trick they do in java to have an Unmodifiable Collections.  When I looked inside I understood that it is just a wrapper overriding the methods put, add etc to through Unsupported exceptions.  Also they extend the entry sets (incase of Map) and make sure they are also unmodifiable. 

