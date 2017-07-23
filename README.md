# YASUO [@0xsauby]

[![AUR](https://img.shields.io/aur/license/yaourt.svg?maxAge=2592000)](http://www.fsf.org/licensing/)
[![ToolsWatch 2016 Arsenal](https://www.toolswatch.org/badges/arsenal/2016.svg)](https://www.blackhat.com/eu-16/arsenal.html)
[![ToolsWatch 2017 Arsenal](https://rawgithub.com/toolswatch/badges/master/arsenal/2017.svg)](https://www.blackhat.com/us-17/arsenal/schedule/index.html#yasuo-7909)
[![Twitter URL](https://img.shields.io/twitter/url/http/shields.io.svg?style=social&maxAge=2592000)](https://twitter.com/0xsauby)

## Description

Yasuo is a ruby script that scans for vulnerable 3rd-party web applications.

While working on a network security assessment (internal, external, redteam
gigs etc.), we often come across vulnerable 3rd-party web applications or web
front-ends that allow us to compromise the remote server by exploiting publicly
known vulnerabilities. Some of the common & favorite applications are Apache
Tomcat administrative interface, JBoss jmx-console, Hudson Jenkins and so on.

If you search through Exploit-db, there are over 10,000 remotely exploitable
vulnerabilities that exist in tons of web applications/front-ends and could
allow an attacker to completely compromise the back-end server. These
vulnerabilities range from RCE to malicious file uploads to SQL injection to
RFI/LFI etc.

Yasuo is built to quickly scan the network for such vulnerable applications
thus serving pwnable targets on a silver platter.

## Setup / Install
You would need to install the following gems:

- gem install ruby-nmap net-http-persistent mechanize text-table sqlite3

## Details

Yasuo provides following command-line options:

-r :: If you want Yasuo to perform port scan, use this switch to provide an IP address or IP range

-l :: If you want Yasuo to perform port scan, use this switch to provide an input file with new-line separated IP addresses, similar to nmap's -iL option

-s :: Provide custom signature file. [./yasuo.rb -s mysignatures.yaml -f nmap.xml] [Default - signatures.yaml]

-f :: If you do not want Yasuo to perform port scan and already have an nmap output in xml format, use this switch to feed the nmap output

-u :: Takes a newline-separated file of URLs saved from previous run of Yasuo. See below for more details.

-n :: Tells Yasuo to not ping the host while performing the port scan. Standard nmap option.

-p :: Use this switch to provide port number(s)/range

-A :: Use this switch to scan all the 65535 ports. Standard nmap option.

-b [all/form/basic] :: If the discovered application implements authentication, use this switch to brute-force the auth. "all" will brute-force both form & http basic auth. "form" will only brute-force form-based auth. "basic" will only brute-force http basic auth.

-t :: Specify maximum number of threads

-h :: Well, take a guess

## What is this new switch: --usesavedstate (-u)

When Yasuo runs, it performs several steps before starting to enumerate vulnerable applications. If you provide an IP address or range, it will perform a port scan against the provided targets. If you provide Yasuo with nmap xml output file, it will parse that file and enumerate hosts with open web ports. It then sends a request for a fake (non-existent) file and directory to each enumerated host:ip. To reduce false-positives, it discards all ip:port that respond back with HTTP 200 Ok for the fake file & directory requests. At the end of this whole process, we get a list of, let's say, "good urls". These good urls are then used to enumerate vulnerable applications.

If for some reason, you have to re-run Yasuo against the same set of targets, the previous versions of Yasuo will go through this whole process again. That's not efficient at all. I know, I am mostly dumb and a slow learner but I am constantly evolving. Anyways, a good reason to re-run Yasuo against the same targets could be to use a different (or custom) signatures file.

This latest version of Yasuo will automatically save a file, savedURLstateXXXXX.out, in the same folder it runs from. This file will contain all the "good urls". If you plan to re-run Yasuo on the same targets, just feed this file to Yasuo without the -f or -r options.

`Example: ruby yasuo.rb -s my_custom_signatures.yaml -u savedURLstateXXXXX.out`

Yasuo will parse this file and start enumerating vulnerable applications against the listed "good urls". Ta-Da.

## Examples

`./yasuo -r 127.0.0.1 -p 80,8080,443,8443 -b form`

The above command will perform port scan against 127.0.0.1 on ports 80, 8080,
443 and 8443 and will brute-force login for all the applications that implement
form-based authentication.


`./yasuo -l /project/hosts -p 80,8080,443,8443`

The above command will perform port scan against the hosts in file /projetcs/hosts 
on ports 80, 8080, 443 and 8443 and will not perform any brute-force actions against
the applications dicovered.


`./yasuo -f my_nmap_output.xml -b all`

The above command will parse the nmap output file "my_nmap_output.xml" and will
brute-force login for all the applications that implement form-based and http
basic authentication.


## Tetris-style Program Flow

![Alt text](./tetris-style-program-flow.JPG)
