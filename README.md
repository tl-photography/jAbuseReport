# jAbuseReport

This program collects abuse information from the auth.log* files when using WP fail2ban for Wordpress.
It was initially written to ease the process of collecting information about abuse on a Wordpress server and sending it to the associated ISP.

I am using it to send monthly abuse reports to the three worst offender ISPs for spamming.

I have tested it with Debian 7.6, Wordpress 4.* and WP fail2ban 2.3.0.

The program searches in the log files for lines like:

Mar 29 10:01:16 sgc wordpress(www.tl-photography.at)[20119]: Authentication failure for admin from 79.141.172.17

It extracts then the IP and executes a whois request to find an email that maches this regex:
[a-zA-Z0-9_.-]*abuse[a-zA-Z0-9_.-]*@[a-zA-Z0-9_.-]*\\.[a-zA-Z0-9_.-]{2,4}

After execution it will take a while and the output looks like:

abuse@corp.vodafone.es = <br>
Mar 10 00:08:35 sgc wordpress(tl-photography.at)[25781]: Authentication failure for thomas from 89.7.28.254 <br>

abuse@business.telecomitalia.it = <br>
Mar 10 01:23:48 sgc wordpress(tl-photography.at)[16705]: Authentication failure for thomas from 87.15.19.213 <br>

abuse@clouditalia.com = <br>
Mar  2 01:59:09 sgc wordpress(www.tl-photography.at)[5090]: Authentication failure for admin from 62.94.154.243 <br>
Mar  2 05:54:34 sgc wordpress(www.tl-photography.at)[12737]: Authentication failure for admin from 62.94.198.163 <br>
... <br>
Mar 31 14:40:21 sgc wordpress(www.tl-photography.at)[10638]: Authentication failure for admin from 212.90.11.160 <br>
Apr  1 09:36:12 sgc wordpress(www.tl-photography.at)[773]: Authentication failure for admin from 62.94.206.11 <br>

abuse@CABLEONLINE.COM.MX = <br>
Mar  9 21:39:07 sgc wordpress(tl-photography.at)[10534]: Authentication failure for thomas from 187.252.160.112 <br>
Mar 10 00:34:36 sgc wordpress(tl-photography.at)[25758]: Authentication failure for thomas from 201.160.150.33 <br>

abuse@nmc.kaiaglobal.com = <br>
Mar 29 09:52:13 sgc wordpress(www.tl-photography.at)[16371]: Authentication failure for thomas from 79.141.172.21 <br>
Mar 29 10:06:21 sgc wordpress(www.tl-photography.at)[11405]: Authentication failure for thomas from 79.141.172.17 <br>

abuse@poweruphosting.com = <br>
Mar 18 05:14:21 sgc wordpress(www.tl-photography.at)[28182]: Authentication failure for apolamhooncob from 162.244.13.14 <br>

abuse.italy.g@bt.com = <br>
Mar  1 10:20:18 sgc wordpress(www.tl-photography.at)[5090]: Authentication failure for admin from 78.7.85.58 <br>
Mar  1 14:14:34 sgc wordpress(www.tl-photography.at)[5090]: Authentication failure for admin from 78.6.29.62 <br>
... <br>
Apr  1 09:36:10 sgc wordpress(www.tl-photography.at)[8955]: Authentication failure for admin from 78.5.120.118 <br>
Apr  1 09:36:10 sgc wordpress(www.tl-photography.at)[17080]: Authentication failure for admin from 78.5.17.102 <br>

not found = <br>
Mar  3 17:58:18 sgc wordpress(www.tl-photography.at)[14182]: Authentication failure for admin from 82.215.150.67 <br>
Mar  8 13:55:32 sgc wordpress(www.tl-photography.at)[1983]: Authentication failure for admin from 82.215.181.8 <br>
... <br>
Apr  1 00:12:29 sgc wordpress(www.tl-photography.at)[2199]: Authentication failure for admin from 159.20.165.9 <br>
Apr  1 09:36:11 sgc wordpress(www.tl-photography.at)[8961]: Authentication failure for admin from 159.20.144.199 <br>

The code I wrote will handle many cases, however there are a number of instances that it will not. Unhandled abuses are indicated as 'not found'. I have not written code that can find every 'abuse' email address, one specific and most common example of this is for the many ISPs that do not have an email on record that contains the substring 'abuse'. 

Thomas Leber
tl-photography.at 

