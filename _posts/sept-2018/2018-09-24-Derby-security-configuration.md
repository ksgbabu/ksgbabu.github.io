---
layout: post
title: Derby security
---

#Derby Security Policy

To configure the derby security we can use a security file security.policy and mention as it below

grant {
permission java.net.SocketPermission "localhost:1527","listen,resolve";
permission java.io.FilePermission "directory${/}/-", "read,write,delete";
permission java.io.FilePermission "./derby.log", "read,write,delete";
};

Edit the startNetowrkserver file and mention to parameters in it as:

-Djava.security.manager -Djava.security.policy=/home/user/security.policy

