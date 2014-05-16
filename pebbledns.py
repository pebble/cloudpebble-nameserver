#!/usr/bin/python
from dnslib import DNSRecord, RR, A, RCODE, QTYPE
from dnslib.server import DNSHandler, DNSServer
import re
import settings


class PebbleResolver(object):
    def resolve(self, request, handler):
        """
        @type request: DNSRecord
        @type handler: DNSHandler
        """

        def nxdomain():
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        def refused():
            reply = request.reply()
            reply.header.rcode = RCODE.REFUSED
            return reply

        name = request.q.qname

        # If they requested something other than our root domain that would be ~recursive, which we REFUSE.
        if not name.matchSuffix(settings.ROOT_DOMAIN):
            return refused()

        name = str(name.stripSuffix(settings.ROOT_DOMAIN))

        match = re.match(r'ip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})', name)

        if match is None:
            return nxdomain()

        ip = tuple(map(int, match.groups()))

        for octet in ip:
            if octet > 255:
                return nxdomain()

        # Now we return an empty response for not-A, or an actual response for A.
        # This is because we should not NXDOMAIN for domains that exist but have no records of
        # the specified type, so we have to go through the motions of checking validity first.
        reply = request.reply()
        if request.q.qtype == QTYPE.A:
            reply.add_answer(RR(request.q.qname, ttl=settings.TTL, rdata=A('%d.%d.%d.%d' % ip)))

        return reply


if __name__ == "__main__":
    server = DNSServer(PebbleResolver(), port=settings.PORT)
    server.start()
