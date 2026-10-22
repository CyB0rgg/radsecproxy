# MikroTik RouterOS 7.23 (long-term) as a HotSpot NAS reaching the ANP proxy over RadSec.
# The router connects out to port 2083 and receives CoA-Request / Disconnect-Request on
# that same connection. /radius incoming (unsolicited requests on UDP 3799) is not needed
# for this; it was tested off and on, see docs/testing/mikrotik-routeros-hotspot.md.

/certificate
# import the client certificate and key issued for this router, and the CA

# With protocol=radsec RouterOS 7.23 connects to port 2083 whatever the port fields say,
# and it verifies the proxy's certificate against the address given here (an IP address
# must be in the certificate's subjectAltName).
/radius
add service=hotspot address=<anp-proxy-address> authentication-port=2083 \
    accounting-port=2083 protocol=radsec certificate=<client-certificate-name> \
    require-message-auth=yes-for-request-resp timeout=5s \
    comment="ANP proxy, reverse CoA"

# To see the CoA arrive and the queue change:
#   /log print where topics~"radius"
#   /queue simple print detail
#   /ip hotspot active print detail
