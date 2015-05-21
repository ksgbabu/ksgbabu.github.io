---
author:gireesh babu
title: class path issue in java
---

I faced a boring issue today.  I have my maven build and that has to run picking up a jtds server to create my db schema.  However that was not picking up the jtds server from my class path.  I guess maven is not really caring the shell level or environment level class path variable.  Is maven really executing in an another command line shell?

