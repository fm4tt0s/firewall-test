# firewall-test

it tests firewall rules - no problemo scripto!

it receives as input a file with:

<code>source;destination;port</code>

then it will iterate thru it and test connectivity over tcp socket.

# background

let's say I may not be the network's team best buddy. I usually request a ton of fw changes, I mean, a <b>TON</b>. requests of worth thousand rules and I had to come up with some to test it in a smart way. that might my (possible one and only) masterpiece.

# say again?

test firewall rules. it receives as input a file with source;destination;port and it will iterate thru it and test connectivity using internal TCP socket mechanism.

# remarks

it <b>WONT</b> work if you dont have private keys at host that is firing the command, simply because it would be just dumb to keep typing password over and over, right? 

you <b>NEED</b> to have acccess to the source boxes and - I cant believe I need to write it down - obviously have connectivity to it from whenever you choose to run it. 

yeah, I think. There is an issue here if the source is AIX; this function makes usage of bash socket capabilities whose are obviously not available on AIX (boo-hoo), well in case the source is namaed after some pre-defined pattern it will use telnet instaed - you may need to customize it, I addoped a naming convention that it is meaninful to me - either way, result may look funky, never got to test it fully.

# how to

easy peasy. create a file with following format:

<code>source;destination;port</code>

then execute:

<code>./firewall-test.sh [your-rules-file]</code>

wait et voi'la. results will be shown whilst tests run and you'll be presented with a summary when it finishes. eg:

<pre>server_a (1.1.1.1) > server_c(3.3.3.3):22 - open/connected
server_b (2.2.2.2) > server_c(3.3.3.3):22 - open/connected
server_a (1.1.1.1) > server_d(4.4.4.4)):22 - open/connected
server_b (2.2.2.2) > server_d(4.4.4.4)):22 - open/connected

-------------- fwtest  results -------------
--------------------------------------------
rules tested              4
elapsed                   0m 2s
--------------------------------------------
open/connected            4
open/refused              0
closed/timeout            0
--------------------------------------------
source unreacheable       0
not tested/no access      0
unknown                   0
--------------------------------------------
log file: result.fwtest.d60b1b34.log
--------------------------------------------</pre>

# last resort notes

I assume you know the difference between open/refused/timeout, if not, you probably shouldn't be interested on this repo. 
