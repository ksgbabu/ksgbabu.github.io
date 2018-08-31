---
layout: post
title:  "Some R tips for aggregation Query - Data Analytics"
date:   2018-08-31
categories: Technical Solution
---

R has always helped us to find some best of the class solutions to 
various data analtyics taks that we have under taken.

Just to summarise the work, let me exemplify it as:

We were supposed to use a data frame like:

df <- data.frame(
 x = c("apple", "orange", "apple", "strawberry","apple"),
 d = as.Date(c('2009-02-02', '2008-03-03','2009-02-02','2008-03-03','2010-04-04')),
 y = c("a", "d","e", "c","d"),
 z = c(5:1)
)

We could write an Analtical Query like:

aggregate(df,list(df[,1],df[,2]),function(i){ paste0(unique(i))})

To group some columns of that data frame. 

To understand this query df is the original data before aggregation
df[,1] and df[,1] the fields in the data frame to be agreegated upon
The function takes each column of each row and do some operations
that we can decide on!!!