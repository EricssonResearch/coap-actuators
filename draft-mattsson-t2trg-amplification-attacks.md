---
stand_alone: true
ipr: trust200902
docname: draft-mattsson-t2trg-amplification-attacks-latest
cat: info
submissiontype: IRTF
pi:
  strict: 'yes'
  toc: 'yes'
  tocdepth: '3'
  symrefs: 'yes'
  sortrefs: 'yes'
  compact: 'yes'
  subcompact: 'no'
  iprnotified: 'no'
title: Amplification Attacks Using the Constrained Application Protocol (CoAP)
abbrev: CoAP Amplification Attacks
area: ''
wg: ''
kw: ''
author:
- name: John Preuß Mattsson
  initials: J.
  surname: Preuß Mattsson
  org: Ericsson AB
  abbrev: Ericsson
  street: SE-164 80 Stockholm
  country: Sweden
  email: john.mattsson@ericsson.com
- name: Göran Selander
  surname: Selander
  org: Ericsson AB
  abbrev: Ericsson
  street: SE-164 80 Stockholm
  country: Sweden
  email: goran.selander@ericsson.com
- name: Christian Amsüss
  surname: Amsüss
  org: Energy Harvesting Solutions
  email: c.amsuess@energyharvesting.at
informative:
  RFC6347:
  RFC7252:
  RFC7641:
  RFC8152:
  RFC8323:
  RFC8446:
  RFC8613:
  RFC9000:
  I-D.ietf-core-groupcomm-bis:
  I-D.ietf-core-echo-request-tag:
  I-D.ietf-core-oscore-groupcomm:
  I-D.ietf-core-conditional-attributes:
  I-D.ietf-lake-edhoc:
  I-D.ietf-tls-dtls13:

  CoAP-Wild:
    target: https://www.netscout.com/blog/asert/coap-attacks-wild
    title: "CoAP Attacks In The Wild"
    seriesinfo:
      "Netscout"
    date: January 2019

  CoAP-Report:
    target: https://www.shadowserver.org/news/accessible-coap-report-scanning-for-exposed-constrained-application-protocol-services/
    title: "Accessible CoAP Report"
    seriesinfo:
      "Shadowserver Foundation"
    date: June 2020

venue:
  group: Thing-to-Thing (t2trg)
  mail: t2trg@irtf.org
  github: EricssonResearch/coap-actuators


--- abstract

Protecting Internet of Things (IoT) devices against attacks is not enough.
IoT deployments need to make sure that they are not used for
Distributed Denial-of-Service (DDoS) attacks. DDoS attacks are
typically done with compromised devices or with amplification attacks
using a spoofed source address.
This document summarizes different amplification attacks using the
Constrained Application Protocol (CoAP). The goal with this document is
to motivate generic and protocol-specific recommendations on the usage of
CoAP. Some of the discussed attacks can be mitigated by not using
NoSec or by using the Echo option.

--- middle

# Introduction

One important protocol used to interact with Internet of Things (IoT)
sensors and actuators is the Constrained Application Protocol (CoAP) {{RFC7252}}.
CoAP can be used without security in the so called NoSec mode but any
Internet-of-Things (IoT) deployment valuing security and privacy would use a
security protocol such as DTLS {{I-D.ietf-tls-dtls13}}, TLS {{RFC8446}}, or OSCORE {{RFC8613}}
to protect CoAP, where the choice of security protocol depends on the transport
protocol and the presence of intermediaries. The use of CoAP over UDP and DTLS is
specified in {{RFC7252}} and the use of CoAP over TCP and TLS is specified in {{RFC8323}}.
OSCORE protects CoAP end-to-end with the use of COSE {{RFC8152}} and the CoAP
Object-Security option {{RFC8613}}, and can therefore be used over any
transport. Group OSCORE {{ I-D.ietf-core-oscore-groupcomm}} can be used to
protect CoAP Group Communication {{I-D.ietf-core-oscore-groupcomm}}.

Protecting Internet of Things (IoT) devices against attacks is not enough.
IoT deployments need to make sure that they are not used for
Distributed Denial-of-Service (DDoS) attacks. DDoS attacks are
typically done with compromised devices or with amplification attacks
using a spoofed source address.
The document summarizes different amplification attacks using CoAP.
When transported over UDP, the CoAP NoSec mode is susceptible to source
IP address spoofing and as a single request can result in multiple responses
from multiple servers, CoAP can have very large amplification factors.
The goal with this document is to motivate generic and protocol-specific
recommendations on the usage of CoAP. 

Some of the discussed attacks can be mitigated by not using
NoSec or by using the Echo option {{I-D.ietf-core-echo-request-tag}}.

# Amplification Attacks using CoAP {#dos}

In a Denial-of-Service (DoS) attack, an attacker sends a large number of requests
or responses to a target endpoint. The denial-of-service might be caused by
the target endpoint receiving a large amount of data, sending a large amount
of data, doing heavy processing, or using too much memory, etc. In a Distributed
Denial-of-Service (DDoS) attack, the request or responses come from a large
number of sources.

In an amplification attack, the amplification factor is the ratio between the
total size of the data sent to the target and the total size of the data
sent by the attacker. In the attacks described in this section, the
attacker sends one or more requests, and the target receives one or more
responses. An amplification attack alone can be a denial-of-service attack
on a server by making it send a large amount of data. But often amplification
attacks are combined with the attacker spoofing the
source IP address of the targeted victim. By requesting as much information
as possible from several servers an attacker can multiply the amount of
traffic and create a distributed denial-of-service attack on the target.
When transported over UDP, the CoAP NoSec
mode is susceptible to source IP address spoofing.

Amplification attacks with CoAP unfortunately are not only theory, amplification
factors of 10-100 are commonly reported from NoSec deployments. {{CoAP-Report}} and
{{CoAP-Wild}} report average amplification factors of 27 and 34 respectively
from a single response to a GET request for /.well-known/core to the default UDP port 5683.
NoSec CoAP servers accessible over the Internet are mostly concentrated to a few countries
and a few implementations, which do not follow the recommendations in Section
11.3 of [RFC7252].

An amplification attack using a single response is illustrated in {{ampsingle}}.
If the response is c times larger than the request, the amplification factor is c.

~~~~
Client   Foe   Server
   |      |      |
   |      +----->|      Code: 0.01 (GET)
   |      | GET  |  Uri-Path: random quote
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |   Payload: "just because you own half the county
   |      |      |             doesn't mean that you have the power
   |      |      |             to run the rest of us. For twenty-
   |      |      |             three years, I've been dying to tell
   |      |      |             you what I thought of you! And now...
   |      |      |             well, being a Christian woman, I can't
   |      |      |             say it!"
~~~~
{: #ampsingle title='Amplification attack using a single response' artwork-align="center"}

An attacker can increase the bandwidth by sending several GET requests. An attacker can
also increase or control the amplification factor by creating or updating resources.
By creating new resources, an attacker can increase the size of /.well-known/core.
An amplification attack where the attacker influences the amplification factor
is illustrated in {{ampmulti_post}}.

~~~~
Client   Foe   Server
   |      |      |
   |      +----->|      Code: 0.02 (POST)
   |      | POST |  Uri-Path: /member/
   |      |      |   Payload: hampsterdance.hevc
   |      |      |
     ....   ....
   |      +----->|      Code: 0.02 (GET)
   |      | GET  |  Uri-Path: /member/
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |   Payload: hampsterdance.hevc
   |      |      |
   |      +----->|      Code: 0.02 (GET)
   |      | GET  |  Uri-Path: /member/
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |   Payload: hampsterdance.hevc
     ....   ....
~~~~
{: #ampmulti_post title='Amplification attack using several requests and a chosen amplification factor' artwork-align="center"}

Amplification factors can be significantly worse when combined with
observe {{RFC7641}} and group requests {{I-D.ietf-core-groupcomm-bis}}. As a single
request can result in multiple responses from multiple servers, the amplification
factors can be very large.

An amplification attack using observe is illustrated in
{{ampmulti_nk}}. If each notification response is c times larger than the registration
request and each request results in n notifications, the amplification factor is c * n.
By registering the same client several times using different Tokens or port numbers,
the bandwidth can be increased. By updating the observed resource, the attacker
may trigger notifications and increase the size of the notifications. By using
conditional attributes {{I-D.ietf-core-conditional-attributes}} an attacker may increase the frequency of
notifications and therefore the amplification factor. The maximum period attribute pmax
indicates the maximum time, in seconds, between two consecutive notifications (whether or not the
resource state has changed). If it is predictable when notifications
are sent as confirmable and which Message ID are used the acknowledgements may be spoofed.

~~~~
Client   Foe   Server
   |      |      |
   |      +----->|      Code: 0.01 (GET)
   |      | GET  |     Token: 0x83
   |      |      |   Observe: 0
   |      |      |  Uri-Path: temperature
   |      |      |  Uri-Query: pmax="0.1"
   |      |      |
   |      +----->|      Code: 0.01 (GET)
   |      | GET  |     Token: 0x84
   |      |      |   Observe: 0
   |      |      |  Uri-Path: temperature
   |      |      |  Uri-Query: pmax="0.1"
   |      |      |
     ....   ....
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x83
   |      |      |   Observe: 217362
   |      |      |   Payload: "299.7 K"
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x84
   |      |      |   Observe: 217362
   |      |      |   Payload: "299.7 K"
   |      |      |
     ....   ....
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x83
   |      |      |   Observe: 217363
   |      |      |   Payload: "299.7 K"
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x84
   |      |      |   Observe: 217363
   |      |      |   Payload: "299.7 K"
     ....   ....
~~~~
{: #ampmulti_nk title='Amplification attack using observe, registering the same client several times, and requesting notifications at least 10 times every second' artwork-align="center"}

An amplification attack using a group request is illustrated in
{{ampmulti_m}}. The group request is sent over multicast or broadcast
and in this case a single request results in m responses
from m different servers. If each response is c times larger than the request,
the amplification factor is c * m. Note that the servers usually do not know
the variable m.


~~~~
Client   Foe   Server
   |      |      |
   |      +----->|      Code: 0.01 (GET)
   |      | GET  |     Token: 0x69
   |      |      |  Uri-Path: </c>
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x69
   |      |      |   Payload: { 1721 : { ...
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x69
   |      |      |   Payload: { 1721 : { ...
   |      |      |
     ....   ....
~~~~
{: #ampmulti_m title='Amplification attack using multicast' artwork-align="center"}

An amplification attack using a multicast request and observe is
illustrated in {{ampmulti_mn}}. In this case a single request results
in n responses each from m different servers giving a total of n \* m
responses. If each response is c times larger than the request,
the amplification factor is c * n * m.


~~~~
Client   Foe   Server
   |      |      |
   |      +----->|      Code: 0.01 (GET)
   |      | GET  |     Token: 0x44
   |      |      |   Observe: 0
   |      |      |  Uri-Path: temperature
   |      |      |  Uri-Query: pmax="0.1"
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x44
   |      |      |   Observe: 217
   |      |      |   Payload: "301.2 K"
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x44
   |      |      |   Observe: 363
   |      |      |   Payload: "293.4 K"
   |      |      |
     ....   ....
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x44
   |      |      |   Observe: 218
   |      |      |   Payload: "301.2 K"
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x44
   |      |      |   Observe: 364
   |      |      |   Payload: "293.4 K"
   |      |      |
     ....   ....
~~~~
{: #ampmulti_mn title='Amplification attack using multicast and observe' artwork-align="center"}

CoAP has always considered amplification attacks, but most of the requirements in 
{{RFC7252}}, {{RFC7641}}, {{I-D.ietf-core-echo-request-tag}}, and
{{I-D.ietf-core-groupcomm-bis}} are "SHOULD" instead of "MUST", it is
undefined what a "large amplification factor" is, {{RFC7641}} does not specify
how many notifications that can be sent before a potentially spoofable
acknowledgement must be sent, and in several cases the "SHOULD" level is
further softened by “If possible" and "generally". {{I-D.ietf-core-conditional-attributes}}
does not have any amplification attack considerations.

QUIC {{RFC9000}} mandates that ”an endpoint MUST limit the amount of data it sends
to the unvalidated address to three times the amount of data received from that
address” without any exceptions. This approach should be seen as current best practice.

While it is clear when an QUIC implementation violates the requirement in {{RFC9000}}, it
is not clear when an CoAP implementation violates the requirement in {{RFC7252}},
{{RFC7641}}, {{I-D.ietf-core-echo-request-tag}}, and {{I-D.ietf-core-groupcomm-bis}}.

In CoAP, an address can be validated with a security protocol like DTLS, TLS, OSCORE, or by using the Echo Option {{I-D.ietf-core-echo-request-tag}}. Restricting the bandwidth per server is not enough as the number of servers the attacker can use is typically unknown. For multicast requests, anti-amplification limits and the Echo Option do not really work unless the number of servers sending responses is known. Even if the responses have the same size as the request, the amplification factor from m servers is m, where m is typically unknown. While DoS attacks from CoAP servers accessible over the Internet pose the largest threat, an attacker on a local network might use local CoAP servers to attack targets on the Internet or on the local network.

# Security Considerations

The whole document can be seen as security considerations for CoAP.


# IANA Considerations

This document has no actions for IANA.

--- back

# Acknowledgements
{: numbered="false"}

The authors would like to thank
{{{Carsten Bormann}}},
{{{Klaus Hartke}}},
{{{Jaime Jiménez}}},
{{{Ari Keränen}}},
{{{Matthias Kovatsch}}},
{{{Achim Kraus}}},
{{{Sandeep Kumar}}},
and
{{{András Méhes}}}
for their valuable comments and feedback.
