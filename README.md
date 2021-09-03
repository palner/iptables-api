# iptables-api

Very simple API for managing local iptables chain: `APIBANLOCAL`

Simple `GET` actions of add, remove, and flush (see [API usage](#API-usage) for more).

## Usage

`./iptables-api`

Defaults:

* port: `8082`
* log: `/var/log/iptables-api.log`
* target: `REJECT`

Compiled `iptables-api` will work for most linux distributions and `iptables-api-arm` will work for most Raspberry Pi distributions.

You can also compile the program using `go build iptables-api.go`.

### Example with flags

`./iptables-api -log=stdout -port=8008 -target=DROP`

## Running as a Service (example)

If executable is in `/usr/local/iptables-api/`...

```bash
cat > /lib/systemd/system/iptables-api.service << EOT
[Unit]
Description=iptables-api

[Service]
Type=simple
Restart=always
RestartSec=5s
ExecStart=/usr/local/iptables-api/iptables-api

[Install]
WantedBy=multi-user.target
EOT
```

Log rotate...

```bash
cat > /etc/logrotate.d/iptables-api << EOF
/var/log/iptables-api.log {
        daily
        copytruncate
        rotate 12
        compress
}
EOF
```

## Kamailio Example

```bash
loadmodule "http_client.so"
loadmodule "htable.so"
... 
modparam("htable", "htable", "ipban=>size=8;autoexpire=600;")
... 
if (!pike_check_req()) {
  xlog("L_ALERT","ALERT: pike blocking $rm from $fu (IP:$si:$sp)\n");
  $sht(ipban=>$si) = 1;
  http_client_query("http://localhost:8082/addip/$si", "$var(apinfo)");
  exit;
}
... 
event_route[htable:expired:ipban] {
  xlog("mytable record expired $shtrecord(key) => $shtrecord(value)\n");
  http_client_query("http://localhost:8082/removeip/$shtrecord(key)", "$var(apinfo)");
}
```

## API Usage

### Add/Block IP

Add an IP to iptables. iptables or ip6tables will be chosen based on the IP.

* **URL**: `/addip/[ipaddress]` or `/blockip/[ipaddress]`
* **METHOD**: `GET`
* **Auth**: None
* **RESPONSE**: 200/4xx/5xx

or

* **URL**: `/`
* **METHOD**: `POST`
* **Auth**: None
* **RESPONSE**: 200/4xx/5xx

#### Add/Block Success Examples

* GET `/addip/1.2.3.4`  
* RESPONSE `200 OK`

```json
{"success":"added"}
```

* GET `/blockip/2001:db8:3333:4444:5555:6666:7777:8888`
* RESPONSE `200 OK`

```json
{"success":"added"}
```

* POST `/` with `{"ipaddress":"1.2.3.4"}`  
* RESPONSE `200 OK`

```json
{"success":"added"}
```

#### Add/Block Error Examples

* GET `/addip/1.2.3`
* RESPONSE `400 Bad Request`

```json
{"error":"only valid ip addresses supported"}
```

* GET `/blockip/2001:db8:3333:4444:5555:6666:8888`
* RESPONSE `400 Bad Request`

```json
{"error":"only valid ip addresses supported"}
```

* POST `/` with `{"address":"1.2.3.4"}`  
* RESPONSE `400 Bad Request`

```json
{"error":"ipaddress is missing. "}
```

### Remove/Unblock IP

Remove an IP from iptables. iptables or ip6tables will be chosen based on the IP.

* **URL**: `/removeip/[ipaddress]` or `/unblockip/[ipaddress]`
* **METHOD**: `GET`
* **Auth**: None
* **RESPONSE**: 200/4xx/5xx

#### Remove/Unblock Success Examples

* GET `/removeip/1.2.3.4`  
* RESPONSE `200 OK`

```json
{"success":"deleted"}
```

* GET `/unblockip/2001:db8:3333:4444:5555:6666:7777:8888`
* RESPONSE `200 OK`

```json
{"success":"deleted"}
```

* DELETE `/` with `{"ipaddress":"1.2.3.4"}`  
* RESPONSE `200 OK`

```json
{"success":"deleted"}
```

#### Remove/Unblock Error Examples

* GET `/removeip/1.2.3`
* RESPONSE `400 Bad Request`

```json
{"error":"only valid ip addresses supported"}
```

* GET `/unblockip/2001:db8:3333:4444:5555:6666:8888`
* RESPONSE `400 Bad Request`

```json
{"error":"only valid ip addresses supported"}
```

* DELETE `/` with `{"address":"1.2.3.4"}`  
* RESPONSE `400 Bad Request`

```json
{"error":"ipaddress is missing. "}
```

### Flush APIBANLOCAL chain

Flushes the iptables and ip6tables APIBANLOCAL chain.

* **URL**: `/flushchain`
* **METHOD**: `GET`
* **Auth**: None
* **RESPONSE**: 200/4xx/5xx

#### Flush Success Example

* GET `/flushchain`  
* RESPONSE `200 OK`

```json
{"result":"ipv4 flushed. ipv6 flushed. "}
```

#### Flush Error Examples

* GET `/flushchain`
* RESPONSE `500 Internal Server Error`

```json
{"error":"error initializing iptables"}
```

* GET `/flushchain`  
* RESPONSE `200 OK`

```json
{"result":"ipv4 error. ipv6 flushed. "}
```

## License / Warranty

iptables-api is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version

iptables-api is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
