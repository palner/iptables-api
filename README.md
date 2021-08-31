# iptables-api

Very simple API for managing local iptables chain: `APIBANLOCAL`

Simple `GET` actions of add, remove, and flush.

## Usage

`./iptables-api`

Defaults:

* port: `8082`
* log: `/var/log/iptables-api.log`
* target: `REJECT`

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

## License / Warranty

iptables-api is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version

iptables-api is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
