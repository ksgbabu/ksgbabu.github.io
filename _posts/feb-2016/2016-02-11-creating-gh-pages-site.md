---
layout: default
title: Creating gh-pages in github
---

It was good thing for every developer to note down all the learnings and experience in a location so that himself or any descendants can easily understand how to work on a piece of work or understand what is the rationale behind it.  I had several attempt for it like having a blogspot.com domain, wordpress site mapped to my domain etc.  Finaly I have been using the gh-pages for some time now.  It has the support of markdown file format to work on it. 

Here are my some of my remeberance on how I did that.

I opened a domain ending with github.io for example ksgbabu.github.io.  I used jekyll a ruby based tool to get a decent laout for all of my post.  It is still not very well formated by I guess I have a start at the least.  I pushed the changes in the _post folder to master branch and then merged that to gh-pages before pushing it to origin.  I had to use --orphan option while checking out the gh-pages.  eg. git checkout --orphan gh-pages

