#YASUO

##Description

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

##Setup / Install
You would need to install the following gems:

- gem install ruby-nmap net-http-persistent mechanize colorize

##Details

Yasuo provides following command-line options:

-r :: If you want Yasuo to perform port scan, use this switch to provide an IP address or IP range or an input file with new-line separated IP addresses

-f :: If you do not want Yasuo to perform port scan and already have an nmap output in xml format, use this switch to feed the nmap output

-n :: Tells Yasuo to not ping the host while performing the port scan. Standard nmap option.

-p :: Use this switch to provide port number(s)/range

-D :: Use this switch to scan top 1000 ports. Standard nmap option.

-A :: Use this switch to scan all the 65535 ports. Standard nmap option.

-b [all/form/basic] :: If the discovered application implements authentication, use this switch to brute-force the auth. "all" will brute-force both form & http basic auth. "form" will only brute-force form-based auth. "basic" will only brute-force http basic auth.

-h :: Well, take a guess

##Examples

`./yasuo -r 127.0.0.1 -p 80,8080,443,8443 -b form`

The above command will perform port scan against 127.0.0.1 on ports 80, 8080,
443 and 8443 and will brute-force login for all the applications that implement
form-based authentication.


`./yasuo -f my_nmap_output.xml -b all`

The above command will parse the nmap output file "my_nmap_output.xml" and will
brute-force login for all the applications that implement form-based and http
basic authentication.


##Tetris-style Program Flow

![Alt text](./tetris-style-program-flow.JPG)
