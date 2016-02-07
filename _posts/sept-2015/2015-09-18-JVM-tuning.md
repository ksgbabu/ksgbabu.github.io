---
layout: post
---

Typically Garbage collection has impact on multiprocessor systems.  An application spending only 1% of the time in gc collection on a uniprocessor system will translates to more than 20% loss in throughput on 32 processor systems.  At 10% of the time in gc more than 75% of throughput is lost when scaling up to 32 processors.

This shows that negligible speed issues when developing on small systems may become principal bottlenecks when scaling upto large systems.  However, small improvements in reducing such a bottleneck can produce large gains in performance.  For a sufficiently large system it becomes well worthwhile to tune the garbage collector.

The default collector should be the first choice for gc and will be adequate for the majority of applications.  The exception to this rule is large applications that are heavily threaded and run on hardware with a large amount of memory and large number of processors. For such applications, first try the aggressive heap option (-XX:+AggreassiveHeap).

