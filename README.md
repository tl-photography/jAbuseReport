# jAbsueReport

This program collects abuse information from the auth.log* files, when using WP fail2ban for Wordpress.
It was initial written to ease the process from collection informations about abuse on a Wordpress server and send it to the ISP.

I tested it with Debian 7.6, Wordpress 4.* and WP fail2ban 2.3.0

The program searches in the log files for lines like:
Mar 29 10:01:16 sgc wordpress(www.tl-photography.at)[20119]: Authentication failure for admin from 79.141.172.17

It extracts then the IP and executes a whois request to find an email that maches this regex:
[a-zA-Z0-9_.-]*abuse[a-zA-Z0-9_.-]*@[a-zA-Z0-9_.-]*\\.[a-zA-Z0-9_.-]{2,4}

After executing, it will take a while and the output looks like:

abuse@corp.vodafone.es =
Mar 10 00:08:35 sgc wordpress(tl-photography.at)[25781]: Authentication failure for thomas from 89.7.28.254

abuse@business.telecomitalia.it =
Mar 10 01:23:48 sgc wordpress(tl-photography.at)[16705]: Authentication failure for thomas from 87.15.19.213

abuse@clouditalia.com =
Mar  2 01:59:09 sgc wordpress(www.tl-photography.at)[5090]: Authentication failure for admin from 62.94.154.243
Mar  2 05:54:34 sgc wordpress(www.tl-photography.at)[12737]: Authentication failure for admin from 62.94.198.163
...
Mar 31 14:40:21 sgc wordpress(www.tl-photography.at)[10638]: Authentication failure for admin from 212.90.11.160
Apr  1 09:36:12 sgc wordpress(www.tl-photography.at)[773]: Authentication failure for admin from 62.94.206.11

abuse@CABLEONLINE.COM.MX =
Mar  9 21:39:07 sgc wordpress(tl-photography.at)[10534]: Authentication failure for thomas from 187.252.160.112
Mar 10 00:34:36 sgc wordpress(tl-photography.at)[25758]: Authentication failure for thomas from 201.160.150.33

abuse@nmc.kaiaglobal.com =
Mar 29 09:52:13 sgc wordpress(www.tl-photography.at)[16371]: Authentication failure for thomas from 79.141.172.21
Mar 29 10:06:21 sgc wordpress(www.tl-photography.at)[11405]: Authentication failure for thomas from 79.141.172.17

abuse@poweruphosting.com =
Mar 18 05:14:21 sgc wordpress(www.tl-photography.at)[28182]: Authentication failure for apolamhooncob from 162.244.13.14

abuse.italy.g@bt.com =
Mar  1 10:20:18 sgc wordpress(www.tl-photography.at)[5090]: Authentication failure for admin from 78.7.85.58
Mar  1 14:14:34 sgc wordpress(www.tl-photography.at)[5090]: Authentication failure for admin from 78.6.29.62
...
Apr  1 09:36:10 sgc wordpress(www.tl-photography.at)[8955]: Authentication failure for admin from 78.5.120.118
Apr  1 09:36:10 sgc wordpress(www.tl-photography.at)[17080]: Authentication failure for admin from 78.5.17.102


not found =
Mar  3 17:58:18 sgc wordpress(www.tl-photography.at)[14182]: Authentication failure for admin from 82.215.150.67
Mar  8 13:55:32 sgc wordpress(www.tl-photography.at)[1983]: Authentication failure for admin from 82.215.181.8
...
Apr  1 00:12:29 sgc wordpress(www.tl-photography.at)[2199]: Authentication failure for admin from 159.20.165.9
Apr  1 09:36:11 sgc wordpress(www.tl-photography.at)[8961]: Authentication failure for admin from 159.20.144.199


There will be maybe a large number of not found entries. This cannot be fixed completely, since some of the entries do not have a adress with abuse in the name. 





Thomas Leber
tl-photography.at 

