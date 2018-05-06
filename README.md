# capstat #

## network-traffic AS-repartitions ##

**capstat** is a C++ utility that fastly aggregates network statistics.

from a set of libpcap captures it will produce :

- [x] per AS repartitions
- [x] from-AS / dest-AS matrices
- [x] arbitrary-length-prefix repartitions and matrices
- [x] all the above IPv4 and IPv6

and also the more common :
* per mac-address repartitions and matrices
* per ethertype repartitions
* vlan repartitions
* ...

## requirements ##
**libpcap** needs to be linked against the regular **libpcap** libraries, thus, for example, *debian-alike* machines would need **libpcap-dev** packages.

**libpcap** needs to be linked against the regular **libresolv** libraries, thus, for example, *debian-alike* machines have it provided via **libc6-dev**

the regular **STL** library is used too, so a valid **C++** compiler and templates is mandatory at building.

Now that an **external dns service** is used for matching IP with AS (rezopole's goasmap/asdig) the requirement of a **bgp full-view** isn't as mandatory as it used to, though it's still possible to use a particular local fullview, say for local-tuned results.

## build ##
yet there is no *autoconf* involved, so the **Makefile** may need some tuning with uncommon machines.

```
shell> make
g++ -Wall -o capstat capstat.cpp -lpcap
echo extracting full-view sample from archive
extracting full-view sample from archive
gzip -dc full.bgp.txt.gz > full.bgp.txt
```

## use ##
Here's below an example of use on a single-host end-user capture (september 2016).
You'll notice that **one third** of the capture was **IPv6**, because the Internet-provider involved do supply **public IPv6 to the end-user**.

Default full-view and an AS-names list are provided, but for accuracy you **must** match the captures with full-views close in time, and probably
supplied by your own routers.

```
# first get a capture to analyse !
shell> tcpdump -i en0 -c 10000 -w capture_file.pcap
    .../...

# process the capture
shell> capstat capture_file.pcap --sizes
ipv4mask = 255.255.255.0
ipv6mask = ffff:ffff:ffff::


pcap_loop returned : 0
EtherType repartition : 3 EtherType, spread over 10000 packets
1 IPv4 6670 66%  66%  (66%  66%  grand-total) 
2 IPv6 3305 33%  99%  (33%  99%  grand-total) 
3 ARP    25  0% 100%   (0% 100%  grand-total) 

EtherType repartition : 3 EtherType, spread over 4453257 bytes
1 IPv4 2404078 53%  53%  (53%  53%  grand-total) 
2 IPv6 2048129 45%  99%  (45%  99%  grand-total) 
3 ARP     1050  0% 100%   (0% 100%  grand-total) 

VLan repartition : 1 VLan, spread over 10000 packets
1 untagged 10000 100% 100%  (100% 100%  grand-total) 

VLan repartition : 1 VLan, spread over 4453257 bytes
1 untagged 4453257 100% 100%  (100% 100%  grand-total) 

src mac-address repartition : 4 src mac-address, spread over 4453257 bytes
1 68a3787dfe99 3646504 81% 81%  (81% 81%  grand-total) 
2 0088653cfaea  805173 18% 99%  (18% 99%  grand-total) 

dst mac-address repartition : 9 dst mac-address, spread over 4453257 bytes
1 0088653cfaea 3644787 81% 81%  (81% 81%  grand-total) 
2 68a3787dfe99  805173 18% 99%  (18% 99%  grand-total) 

src/dst mac-addresses repartition : 10 src/dst mac-addresses, spread over 4453257 bytes
1 [ 68a3787dfe99 0088653cfaea ] 3644787 81% 81%  (81% 81%  grand-total) 
2 [ 0088653cfaea 68a3787dfe99 ]  805173 18% 99%  (18% 99%  grand-total) 

src IP address repartition : 54 src IP address, spread over 4452207 bytes
 1 2a00:1450:4007::(;GOOGLE as15169)        1755746 39% 39%  (39% 39%  grand-total) 
 2 192.168.0.0                               662880 14% 54%  (14% 54%  grand-total) 
 3 216.58.208.0(;GOOGLE as15169)             330228  7% 61%   (7% 61%  grand-total) 
 4 151.101.60.0(;FASTLY as54113)             302068  6% 68%   (6% 68%  grand-total) 
 5 77.238.163.0(;Yahoo-Switzerland as42173)  253906  5% 74%   (5% 74%  grand-total) 
 6 77.95.64.0(;Rezopole-Services as199422)   172406  3% 78%   (3% 78%  grand-total) 
 7 2a01:e34:ef6a::(;PROXAD as12322)          170452  3% 81%   (3% 81%  grand-total) 
 8 192.30.253.0(;GITHUB as36459)             151382  3% 85%   (3% 85%  grand-total) 
 9 193.0.6.0(;RIPE-NCC-AS as3333)            147543  3% 88%   (3% 88%  grand-total) 
10 2620:0:862::(;WIKIMEDIA-EU as43821)        83278  1% 90%   (1% 90%  grand-total) 

dst IP adress repartition : 57 dst IP adress, spread over 4452207 bytes
1 2a01:e34:ef6a::(;PROXAD as12322)        1876857 42% 42%  (42% 42%  grand-total) 
2 192.168.0.0                             1782990 40% 82%  (40% 82%  grand-total) 
3 77.95.64.0(;Rezopole-Services as199422)  240522  5% 87%   (5% 87%  grand-total) 
4 2a00:1450:4007::(;GOOGLE as15169)        138534  3% 90%   (3% 90%  grand-total) 

src/dst IP addresses repartition : 109 src/dst IP addresses, spread over 4452207 bytes
 1 [ 2a00:1450:4007::(;GOOGLE as15169)                2a01:e34:ef6a::(;PROXAD as12322) ] 1755746 39% 39%  (39% 39%  grand-total) 
 2 [ 216.58.208.0(;GOOGLE as15169)                                         192.168.0.0 ]  330228  7% 46%   (7% 46%  grand-total) 
 3 [ 151.101.60.0(;FASTLY as54113)                                         192.168.0.0 ]  302068  6% 53%   (6% 53%  grand-total) 
 4 [ 77.238.163.0(;Yahoo-Switzerland as42173)                              192.168.0.0 ]  253906  5% 59%   (5% 59%  grand-total) 
 5 [ 192.168.0.0                               77.95.64.0(;Rezopole-Services as199422) ]  240522  5% 64%   (5% 64%  grand-total) 
 6 [ 77.95.64.0(;Rezopole-Services as199422)                               192.168.0.0 ]  172406  3% 68%   (3% 68%  grand-total) 
 7 [ 192.30.253.0(;GITHUB as36459)                                         192.168.0.0 ]  151382  3% 72%   (3% 71%  grand-total) 
 8 [ 193.0.6.0(;RIPE-NCC-AS as3333)                                        192.168.0.0 ]  147543  3% 75%   (3% 75%  grand-total) 
 9 [ 2a01:e34:ef6a::(;PROXAD as12322)                2a00:1450:4007::(;GOOGLE as15169) ]  138534  3% 78%   (3% 78%  grand-total) 
10 [ 2620:0:862::(;WIKIMEDIA-EU as43821)              2a01:e34:ef6a::(;PROXAD as12322) ]   83278  1% 80%   (1% 80%  grand-total) 
11 [ 149.255.137.0(;RMI-FITECH as16347)                                    192.168.0.0 ]   82120  1% 82%   (1% 82%  grand-total) 
12 [ 192.168.0.0                                         192.30.253.0(;GITHUB as36459) ]   77477  1% 83%   (1% 83%  grand-total) 
13 [ 74.125.71.0(;GOOGLE as15169)                                          192.168.0.0 ]   76725  1% 85%   (1% 85%  grand-total) 
14 [ 217.12.1.0(as15635)                                                   192.168.0.0 ]   69750  1% 87%   (1% 87%  grand-total) 
15 [ 192.168.0.0                                         216.58.208.0(;GOOGLE as15169) ]   55804  1% 88%   (1% 88%  grand-total) 
16 [ 192.168.0.0                              77.238.163.0(;Yahoo-Switzerland as42173) ]   42992  0% 89%   (0% 89%  grand-total) 
17 [ 192.168.0.0                                                           192.168.0.0 ]   41792  0% 90%   (0% 90%  grand-total) 

src IPv6 repartition : 9 src IPv6, spread over 2048129 bytes
1 2a00:1450:4007::(;GOOGLE as15169) 1755746 85% 85%  (39% 39%  grand-total) 
2 2a01:e34:ef6a::(;PROXAD as12322)   170452  8% 94%   (3% 43%  grand-total) 

dst IPv6 repartition : 10 dst IPv6, spread over 2048129 bytes
1 2a01:e34:ef6a::(;PROXAD as12322) 1876857 91% 91%  (42% 42%  grand-total) 

src/dst IPv6 repartition : 18 src/dst IPv6, spread over 2048129 bytes
1 [ 2a00:1450:4007::(;GOOGLE as15169)  2a01:e34:ef6a::(;PROXAD as12322) ] 1755746 85% 85%  (39% 39%  grand-total) 
2 [ 2a01:e34:ef6a::(;PROXAD as12322)  2a00:1450:4007::(;GOOGLE as15169) ]  138534  6% 92%   (3% 42%  grand-total) 

src AS repartition : 32 src AS, spread over 4452207 bytes
1 (;GOOGLE as15169)             2199899 49% 49%  (49% 49%  grand-total) 
2 (as0)                          667139 14% 64%  (14% 64%  grand-total) 
3 (;FASTLY as54113)              302348  6% 71%   (6% 71%  grand-total) 
4 (;Yahoo-Switzerland as42173)   253906  5% 76%   (5% 76%  grand-total) 
5 (;Rezopole-Services as199422)  181393  4% 80%   (4% 80%  grand-total) 
6 (;PROXAD as12322)              170452  3% 84%   (3% 84%  grand-total) 
7 (;GITHUB as36459)              151382  3% 88%   (3% 88%  grand-total) 
8 (;RIPE-NCC-AS as3333)          147543  3% 91%   (3% 91%  grand-total) 

dst AS repartition : 32 dst AS, spread over 4452207 bytes
1 (;PROXAD as12322)             1876857 42% 42%  (42% 42%  grand-total) 
2 (as0)                         1786916 40% 82%  (40% 82%  grand-total) 
3 (;Rezopole-Services as199422)  247943  5% 87%   (5% 87%  grand-total) 
4 (;GOOGLE as15169)              232534  5% 93%   (5% 93%  grand-total) 

src/dst AS repartition : 70 src/dst AS, spread over 4452207 bytes
 1 [ (;GOOGLE as15169)                         (;PROXAD as12322) ] 1779811 39% 39%  (39% 39%  grand-total) 
 2 [ (;GOOGLE as15169)                                     (as0) ]  420088  9% 49%   (9% 49%  grand-total) 
 3 [ (;FASTLY as54113)                                     (as0) ]  302348  6% 56%   (6% 56%  grand-total) 
 4 [ (;Yahoo-Switzerland as42173)                          (as0) ]  253906  5% 61%   (5% 61%  grand-total) 
 5 [ (as0)                         (;Rezopole-Services as199422) ]  247943  5% 67%   (5% 67%  grand-total) 
 6 [ (;Rezopole-Services as199422)                         (as0) ]  181393  4% 71%   (4% 71%  grand-total) 
 7 [ (;PROXAD as12322)                         (;GOOGLE as15169) ]  154726  3% 75%   (3% 75%  grand-total) 
 8 [ (;GITHUB as36459)                                     (as0) ]  151382  3% 78%   (3% 78%  grand-total) 
 9 [ (;RIPE-NCC-AS as3333)                                 (as0) ]  147543  3% 81%   (3% 81%  grand-total) 
10 [ (;WIKIMEDIA-EU as43821)                   (;PROXAD as12322) ]   83278  1% 83%   (1% 83%  grand-total) 
11 [ (;RMI-FITECH as16347)                                 (as0) ]   82120  1% 85%   (1% 85%  grand-total) 
12 [ (as0)                                     (;GOOGLE as15169) ]   77808  1% 87%   (1% 87%  grand-total) 
13 [ (as0)                                     (;GITHUB as36459) ]   77477  1% 88%   (1% 88%  grand-total) 
14 [ (as15635)                                             (as0) ]   69750  1% 90%   (1% 90%  grand-total) 
```

## TODO ##

#### BUGs !
- [x] verify prefix inclusion matching into getAS procedure !!!
- [x] be classful-IPv4 aware and behave accordingly for full-view parsing
- [ ] introduce a default local AS for locally announced prefix ie empty AS-paths)
- [x] introduce RF1918 privates spaces ... (considered done via external lookup)
- [ ] ICMP ???
- [ ] ICMPV6 : dst endress ending with ':' to remove !

#### ergonomy
- [x]	provide an inner piped-call for tcpdump rather than guessing the proper pipe ? (moved to libpcap instead)
- [ ]	man pages, examples

#### data sorting and consolidations
- [x]   use a dns-provided external lookup for IP-AS matches
- [ ]   read _All_ prefixes as-path from instead of only the _Bests_.
- [ ]   check for multiple-AS appartainances (?)
- [x]   retrieve the full view via snmp ?? (probably won't do, because of new external lookup)
- [ ]   use whois and an inner cache for per-AS repartition
- [x]   use a BGP full-view dump for per-AS repartition
- [x]   use a mac-address registry for human-clarifyed output (iptraf format ?)
- [ ]	use timestamps in order to output average rates ???

#### command flags
- [x]	toggle between packet number views or packet size views

#### Unit Testings
- [ ]   provide a neutral and rather exhaustive capture for unit-testings

#### Outputs
- [ ]	json-encoded output
- [ ]	html output
- [ ]	svg or better output ?


## unit-tests ##
there are not many unit-tests yet, but the target do exist in the makefile :

```
shell>make test
./capstat --fullview=full.bgp.txt --dumpfv
reading full view ...  done. 597814 IPv4 prefixes (53629 AS), 29939 IPv6 prefixes (11463 AS).   total :  53929 AS
ipv4mask = 255.255.255.0
.../...
diff fullfv_dump.bis.txt fullfv_dump.txt  && echo "      fullview re-reading test ok" && rm fullfv_dump.bis.txt
      fullview re-reading test ok
```

## authors ##
please supply any request to capstat@rezopole.net, thanks in advance !
