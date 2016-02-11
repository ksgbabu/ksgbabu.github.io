---
layout: default
title: Multile SSH keys for github repo in the same machine
---

Multiple SSH Keys settings for different github account
create different public key

create different ssh key according the article Mac Set-Up Git

$ ssh-keygen -t rsa -C "your_email@youremail.com"

Please refer to github ssh issues for common problems.

for example, 2 keys created at:

~/.ssh/id_rsa_giri4it
~/.ssh/id_rsa_ksgbabu

then, add these two keys as following

$ ssh-add ~/.ssh/id_rsa_ksgbabu
$ ssh-add ~/.ssh/id_rsa_giri4it

you can delete all cached keys before

$ ssh-add -D

finally, you can check your saved keys

$ ssh-add -l

Modify the ssh config

$ cd ~/.ssh/
$ touch config
$ vim config

Then added

#ksgbabu account
Host github.com-ksgbabu
    HostName ksgbabu.github.com
    User git
    IdentityFile ~/.ssh/id_rsa_ksgbabu

#giri4it account
Host github.com-giri4it
    HostName giri4it.github.com
    User git
    IdentityFile ~/.ssh/id_rsa_giri4it
