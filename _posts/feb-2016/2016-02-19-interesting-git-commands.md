---
layout: post
title: Git commands
---

Interesting git commands are explained here.

##Git Archive

Probably the simplest way to achieve this is with git archive. If you really need just the expanded tree you can do something like this.

git archive master | tar -x -C /somewhere/else

Most of the time that I need to 'export' something from git, I want a compressed archive in any case so I do something like this.

git archive master | bzip2 >source-tree.tar.bz2

ZIP archive:

git archive --format zip --output /full/path/to/zipfile.zip master 
