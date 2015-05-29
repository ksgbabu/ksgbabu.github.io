---
layout: post
---

We are in the process of building integration server for our product suite.  Knowing the fact that a monolithic integration server is an old generation concepts, the solutions that bring on the table was bit attractive.  So we also decided to have a light weight esb layer for our product suite.

When there was a discussion about document store, we were constantly saying that the integration server can store any inbound document temporarily in the cache store.  The store id or key can be UID which can be passed to any place so that they can pull that document.  Conceptaully I feel that is the correct way.  But some of my team members are asking that about the transaction issues that can bring.  I don't get an idea why there is an atomicity of operations required for a document sync like this.  I can understand a simple status flag to keep track of the document transfer but why would meta-data and document store/transfer be in single transaction!  By the way, is that possible to execute in a single transaction with out a two phase commit transaction?  If required what kind of API and mechanism will be used?  

  
