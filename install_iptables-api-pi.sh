#!/bin/bash
#-- install script for iptables-api

#-- pgpx.io
echo ""
echo ""
echo ""
echo ""
echo ""
echo ""
echo ""
echo " ppppp   ppppppppp      ggggggggg   ggggg"
echo " p::::ppp:::::::::p    g:::::::::ggg::::g"
echo " p:::::::::::::::::p  g:::::::::::::::::g"
echo " pp::::::ppppp::::::pg::::::ggggg::::::gg"
echo "  p:::::p     p:::::pg:::::g     g:::::g "
echo "  p:::::p     p:::::pg:::::g     g:::::g "
echo "  p:::::p     p:::::pg:::::g     g:::::g "
echo "  p:::::p    p::::::pg::::::g    g:::::g "
echo "  p:::::ppppp:::::::pg:::::::ggggg:::::g "
echo "  p::::::::::::::::p  g::::::::::::::::g "
echo "  p::::::::::::::pp    gg::::::::::::::g "
echo "  p::::::pppppppp        gggggggg::::::g "
echo "  p:::::p                        g:::::g "
echo "  p:::::p            gggggg      g:::::g "
echo " p:::::::p           g:::::gg   gg:::::g "
echo " p:::::::p            g::::::ggg:::::::g "
echo " p:::::::p             gg:::::::::::::g  "
echo " ppppppppp               ggg::::::ggg    "
echo "                            gggggg       "
echo ""
echo ""
echo ""
echo " need support? https://palner.com"
echo ""
echo " Copyright (C) 2021	The Palner Group, Inc. (palner.com)"
echo ""
echo " iptables-api is free software; you can redistribute it and/or modify"
echo " it under the terms of the GNU General Public License as published by"
echo " the Free Software Foundation; either version 2 of the License, or"
echo " (at your option) any later version"
echo ""
echo " iptables-api is distributed in the hope that it will be useful,"
echo " but WITHOUT ANY WARRANTY; without even the implied warranty of"
echo " MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the"
echo " GNU General Public License for more details."
echo ""
echo " You should have received a copy of the GNU General Public License"
echo " along with this program; if not, write to the Free Software"
echo " Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA"
echo ""

#-- download iptables
echo ""
echo " -> downloading iptables-api"
mkdir /usr/local/src/iptables-api
cd /usr/local/src/iptables-api
wget https://github.com/palner/iptables-api/raw/main/iptables-api-arm &>/dev/null
if [ "$?" -eq "0" ]
then
  echo "  -o downloaded"
else
  echo "  -x download FAILED!!"
  exit 1
fi

#-- make local folder and service
echo ""
echo " -> making run directory and service"
mkdir /usr/local/iptables-api
cp /usr/local/src/iptables-api/iptables-api-arm /usr/local/iptables-api/iptables-api
chmod 755 /usr/local/iptables-api/iptables-api
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

#-- log rotate
echo " -> set up log rotate"
cat > /etc/logrotate.d/iptables-api << EOF
/var/log/iptables-api.log {
        daily
        copytruncate
        rotate 12
        compress
}
EOF

#-- reload / start service
echo " -> start service"
systemctl daemon-reload &>/dev/null
systemctl enable iptables-api &>/dev/null
systemctl start iptables-api &>/dev/null
