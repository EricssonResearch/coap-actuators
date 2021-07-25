---
stand_alone: true
ipr: trust200902
docname: draft-mattsson-core-coap-attacks-00
cat: info
pi:
  strict: 'yes'
  toc: 'yes'
  tocdepth: '3'
  symrefs: 'yes'
  sortrefs: 'yes'
  compact: 'yes'
  subcompact: 'no'
  iprnotified: 'no'
title: CoAP Attacks
abbrev: CoAP Attacks
area: ''
wg: ''
kw: ''
author:
- name: John Preuß Mattsson
  surname: Preuß Mattsson
  org: Ericsson AB
  abbrev: Ericsson
  street: SE-164 80 Stockholm
  country: Sweden
  email: john.mattsson@ericsson.com
- name: John Fornehed
  surname: Fornehed
  org: Ericsson AB
  abbrev: Ericsson
  street: SE-164 80 Stockholm
  country: Sweden
  email: john.fornehed@ericsson.com
- name: Göran Selander
  surname: Selander
  org: Ericsson AB
  abbrev: Ericsson
  street: SE-164 80 Stockholm
  country: Sweden
  email: goran.selander@ericsson.com
- name: Francesca Palombini
  surname: Palombini
  org: Ericsson AB
  abbrev: Ericsson
  street: SE-164 80 Stockholm
  country: Sweden
  email: francesca.palombini@ericsson.com
- name: Christian Amsüss
  surname: Amsüss
  org: Energy Harvesting Solutions
  email: c.amsuess@energyharvesting.at
normative:
  RFC2119:
  RFC8174:
  RFC7252:
  RFC7641:
  I-D.ietf-core-echo-request-tag:
  I-D.ietf-core-coap-pubsub:
  I-D.ietf-core-groupcomm-bis:
informative:
  RFC6347:
  RFC8152:
  RFC8323:
  RFC8446:
  RFC8613:
  RFC9000:
  I-D.liu-core-coap-delay-attacks:
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
    
--- abstract

Being able to securely read information from sensors, to securely control actuators, and
to not enable distributed denial-of-service attacks are essential in a world of
connected and networking things interacting with
the physical world. This document summarizes a number of known attacks on CoAP and
show that just using CoAP with a security protocol like DTLS, TLS, or OSCORE is not
enough for secure operation. The document also summarizes different denial-of-service
attacks where CoAP deployments are used attack other networks or services.
The goal with this document is motivating generic
and protocol-specific recommendations on the usage of CoAP. Several of the
discussed attacks can be mitigated with the solutions in
draft-ietf-core-echo-request-tag.

--- middle

# Introduction

Being able to securely read information from sensors and to securely control actuators
are essential in a world of connected and networking things interacting with
the physical world. One protocol used to interact with sensors and actuators
is the Constrained Application Protocol (CoAP) {{RFC7252}}. Any
Internet-of-Things (IoT) deployment valuing security and privacy would
use a security protocol such as DTLS {{I-D.ietf-tls-dtls13}}, TLS {{RFC8446}}, or
OSCORE {{RFC8613}} to protect CoAP, where the choice of security
protocol depends on the transport protocol and the presence of intermediaries.
The use of CoAP over UDP and DTLS is specified in {{RFC7252}} and the
use of CoAP over TCP and TLS is specified in {{RFC8323}}. OSCORE
protects CoAP end-to-end with the use of COSE {{RFC8152}} and the CoAP
Object-Security option {{RFC8613}}, and can therefore be used over any
transport.

The Constrained Application Protocol (CoAP) {{RFC7252}} was designed
with the assumption that security could be provided on a separate
layer, in particular by using DTLS {{RFC6347}}. The four properties
traditionally provided by security protocols are:

* Data confidentiality

* Data origin authentication

* Data integrity checking

* Replay protection

In this document we show that protecting CoAP with a security protocol on
another layer is not nearly enough to securely control actuators (and in
many cases sensors) and that secure operation often demands far more than
the four properties traditionally provided by security protocols. We describe
several serious attacks any on-path attacker (i.e., not only "trusted intermediaries")
can do and discusses tougher requirements and mechanisms to mitigate the
attacks. In general, secure operation of actuators also requires the three
properties:

* Data-to-Data binding

* Data-to-space binding

* Data-to-time binding

"Data-to-Data binding" is e.g., binding of responses to a request or binding
of data fragments to each other. "Data-to-space binding" is the binding of
data to an absolute or relative point in space (i.e., a location) and may
in the relative case be referred to as proximity. "Data-to-time binding"
is the binding of data to an absolute or relative point in time and may in
the relative case be referred to as freshness. The two last properties may
be bundled together as "Data-to-spacetime binding".

The request delay attack (valid for DTLS, TLS, and OSCORE and
described in {{reqdelay}}) lets an attacker control an actuator at a
much later time than the client anticipated. The response delay and
mismatch attack (valid for DTLS and TLS and described in {{resdelay}})
lets an attacker respond to a client with a response meant for an
older request. The request fragment rearrangement attack (valid for
DTLS, TLS, and OSCORE and described in {{fragment}}) lets an attacker
cause unauthorized operations to be performed on the server, and
responses to unauthorized operations to be mistaken for responses to
authorized operations.

Protecting the CoAP deployment itself is not enough. CoAP deployments
need to make sure that they are not used for distributed denial-of-service
attacks on other networks and services. {{dos}} summarizes different
denial-of-service attacks using CoAP. When transported over UDP, the CoAP
NoSec mode is susceptible to source IP address spoofing and as a single
request can result in multiple responses from multiple servers, CoAP
can have very large amplification factors.

The goal with this document is motivating generic
and protocol-specific recommendations on the usage of CoAP.
Mechanisms mitigating some of the attacks discussed in this document can
be found in {{I-D.ietf-core-echo-request-tag}}.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

# Attacks on CoAP

Internet-of-Things (IoT) deployments valuing security and privacy, MUST use
a security protocol such as DTLS, TLS, or OSCORE to protect CoAP. This is
especially true for deployments of actuators where attacks often (but not
always) have serious consequences. The attacks described in this section
are made under the assumption that CoAP is already protected with a security
protocol such as DTLS, TLS, or OSCORE, as an attacker otherwise can easily
forge false requests and responses.

##  The Block Attack

An on-path attacker can block the delivery of any number of requests or responses.
The attack can also be performed by an attacker jamming the lower layer radio
protocol. This is true even if a security protocol like DTLS, TLS, or OSCORE
is used. Encryption makes selective blocking of messages harder, but not
impossible or even infeasible. With DTLS and TLS, proxies have access to
the complete CoAP message, and with OSCORE, the CoAP header and several CoAP
options are not encrypted. In both security protocols, the IP-addresses,
ports, and CoAP message lengths are available to all on-path attackers, which
may be enough to determine the server, resource, and command.  The block
attack is illustrated in Figures {{blockreq}}{: format="counter"} and {{blockres}}{: format="counter"}.


~~~~
Client   Foe   Server
   |      |      |
   +----->X      |      Code: 0.03 (PUT)
   | PUT  |      |     Token: 0x47
   |      |      |  Uri-Path: lock
   |      |      |   Payload: 1 (Lock)
   |      |      |
~~~~
{: #blockreq title='Blocking a request' artwork-align="center"}

Where 'X' means the attacker is blocking delivery of the message.


~~~~
Client   Foe   Server
   |      |      |
   +------------>|      Code: 0.03 (PUT)
   |      | PUT  |     Token: 0x47
   |      |      |  Uri-Path: lock
   |      |      |   Payload: 1 (Lock)
   |      |      |
   |      X<-----+      Code: 2.04 (Changed)
   |      | 2.04 |     Token: 0x47
   |      |      |
~~~~
{: #blockres title='Blocking a response' artwork-align="center"}

While blocking requests to, or responses from, a sensor is just a denial
of service attack, blocking a request to, or a response from, an actuator
results in the client losing information about the server's status. If the
actuator e.g. is a lock (door, car, etc.), the attack results in the client
not knowing (except by using out-of-band information) whether the lock is
unlocked or locked, just like the observer in the famous Schrodinger’s cat
thought experiment. Due to the nature of the attack, the client cannot distinguish
the attack from connectivity problems, offline servers, or unexpected behavior
from middle boxes such as NATs and firewalls.

Remedy: Any IoT deployment of actuators where confirmation is important MUST
notify the user upon reception of the response, or warn the user when a response
is not received.


##  The Request Delay Attack {#reqdelay}

An on-path attacker may not only block packets, but can also delay the delivery
of any packet (request or response) by a chosen amount of time. If CoAP is
used over a reliable and ordered transport such as TCP with TLS or OSCORE,
no messages can be delivered before the delayed message. If CoAP is used
over an unreliable and unordered transport such as UDP with DTLS, or OSCORE,
other messages can be delivered before the delayed message as long as the
delayed packet is delivered inside the replay window. When CoAP is used over
UDP, both DTLS and OSCORE allow out-of-order delivery and uses sequence numbers
together with a replay window to protect against replay attacks. The replay
window has a default length of 64 in DTLS and 32 in OSCORE. The attacker
can control the replay window by blocking some or all other packets. By first
delaying a request, and then later, after delivery, blocking the response
to the request, the client is not made aware of the delayed delivery except
by the missing response. The server has in general, no way of knowing that
the request was delayed and will therefore happily process the request.
Note that delays can also happen for other reasons than a malicious attacker.

If some wireless low-level protocol is used, the attack can also be performed
by the attacker simultaneously recording what the client transmits while
at the same time jamming the server. The request delay attack is illustrated
in {{delayreq}}.


~~~~
Client   Foe   Server
   |      |      |
   +----->@      |      Code: 0.03 (PUT)
   | PUT  |      |     Token: 0x9c
   |      |      |  Uri-Path: lock
   |      |      |   Payload: 0 (Unlock)
   |      |      |
     ....   ....
   |      |      |
   |      @----->|      Code: 0.03 (PUT)
   |      | PUT  |     Token: 0x9c
   |      |      |  Uri-Path: lock
   |      |      |   Payload: 0 (Unlock)
   |      |      |
   |      X<-----+      Code: 2.04 (Changed)
   |      | 2.04 |     Token: 0x9c
   |      |      |
~~~~
{: #delayreq title='Delaying a request' artwork-align="center"}

Where '@' means the attacker is storing and later forwarding the message
(@ may alternatively be seen as a wormhole connecting two points in time).

While an attacker delaying a request to a sensor is often not a security
problem, an attacker delaying a request to an actuator performing an action
is often a serious problem. A request to an actuator (for example a request
to unlock a lock) is often only meant to be valid for a short time frame,
and if the request does not reach the actuator during this short timeframe,
the request should not be fulfilled. In the unlock example, if the client
does not get any response and does not physically see the lock opening, the
user is likely to walk away, calling the locksmith (or the IT-support).

If a non-zero replay window is used (the default when CoAP is used
over UDP), the attacker can let the client interact with the actuator
before delivering the delayed request to the server (illustrated in
{{delayreqreorder}}).  In the lock example, the attacker may store the
first "unlock" request for later use.  The client will likely resend
the request with the same token.  If DTLS is used, the resent packet
will have a different sequence number and the attacker can forward
it. If OSCORE is used, resent packets will have the same sequence
number and the attacker must block them all until the client sends a
new message with a new sequence number (not shown in
{{delayreqreorder}}). After a while when the client has locked the
door again, the attacker can deliver the delayed "unlock" message to
the door, a very serious attack.

~~~~
Client   Foe   Server
   |      |      |
   +----->@      |      Code: 0.03 (PUT)
   | PUT  |      |     Token: 0x9c
   |      |      |  Uri-Path: lock
   |      |      |   Payload: 0 (Unlock)
   |      |      |
   +------------>|      Code: 0.03 (PUT)
   | PUT  |      |     Token: 0x9c
   |      |      |  Uri-Path: lock
   |      |      |   Payload: 0 (Unlock)
   |      |      |
   <-------------+      Code: 2.04 (Changed)
   |      | 2.04 |     Token: 0x9c
   |      |      |
     ....   ....
   |      |      |
   +------------>|      Code: 0.03 (PUT)
   | PUT  |      |     Token: 0x7a
   |      |      |  Uri-Path: lock
   |      |      |   Payload: 1 (Lock)
   |      |      |
   <-------------+      Code: 2.04 (Changed)
   |      | 2.04 |     Token: 0x7a
   |      |      |
   |      @----->|      Code: 0.03 (PUT)
   |      | PUT  |     Token: 0x9c
   |      |      |  Uri-Path: lock
   |      |      |   Payload: 0 (Unlock)
   |      |      |
   |      X<-----+      Code: 2.04 (Changed)
   |      | 2.04 |     Token: 0x9c
   |      |      |
~~~~
{: #delayreqreorder title='Delaying request with reordering' artwork-align="center"}

While the second attack ({{delayreqreorder}}) can be mitigated by
using a replay window of length zero, the first attack ({{delayreq}})
cannot. A solution must enable the server to verify that the request
was received within a certain time frame after it was sent or enable
the server to securely determine an absolute point in time when the
request is to be executed. This can be accomplished with either a
challenge-response pattern, by exchanging timestamps between client
and server, or by only allowing requests a short period after client
authentication.

Requiring a fresh client authentication (such as a new TLS/DTLS handshake
or an EDHOC key exchange {{I-D.ietf-lake-edhoc}}) mitigates the
problem, but requires larger messages and more processing
than a dedicated solution. Security solutions based on exchanging timestamps
require exactly synchronized time between client and server, and this may
be hard to control with complications such as time zones and daylight saving.
Wall clock time SHOULD NOT be used as it is not monotonic, may reveal that
the endpoints will accept expired certificates, or reveal the endpoint's
location. Use of non-monotonic clocks is not secure as the server will accept
requests if the clock is moved backward and reject requests if the clock
is moved forward. Even if the clocks are synchronized at one point in time,
they may easily get out-of-sync and an attacker may even be able to affect
the client or the server time in various ways such as setting up a fake NTP
server, broadcasting false time signals to radio controlled clocks, or expose
one of them to a strong gravity field. As soon as client falsely believes
it is time synchronized with the server, delay attacks are possible. A challenge
response mechanism where the server does not need to synchronize its time
with the client is easier to analyze but require more roundtrips. The challenges,
responses, and timestamps may be sent in a CoAP option or in the CoAP payload.

Remedy: The mechanisms specified in {{I-D.ietf-core-echo-request-tag}}
or {{I-D.liu-core-coap-delay-attacks}} SHALL be used for controlling
actuators unless another application specific
challenge-response or timestamp mechanism is used.


##  The Response Delay and Mismatch Attack {#resdelay}

The following attack can be performed if CoAP is protected by a security
protocol where the response is not bound to the request in any way except
by the CoAP token. This would include most general security protocols, such
as DTLS, TLS, and IPsec, but not OSCORE. CoAP {{RFC7252}} uses a
client generated token that the server echoes to match responses to
request, but does not give any guidelines for the use of token with DTLS
and TLS, except that the tokens currently "in use" SHOULD (not SHALL) be
unique. The attacker performs the attack by delaying delivery of a response
until the client sends a request with the same token, the response will be
accepted by the client as a valid response to the later request. If CoAP
is used over a reliable and ordered transport such as TCP with TLS, no messages
can be delivered before the delayed message. If CoAP is used over an unreliable
and unordered transport such as UDP with DTLS, other messages can be delivered
before the delayed message as long as the delayed packet is delivered inside
the replay window. Note that mismatches can also happen for other reasons
than a malicious attacker, e.g. delayed delivery or a server sending notifications
to an uninterested client.

The attack can be performed by an attacker on the wire, or an attacker simultaneously
recording what the server transmits while at the same time jamming the client.
The response delay and mismatch attack is illustrated in {{delayresPUT}}.


~~~~
Client   Foe   Server
   |      |      |
   +------------>|      Code: 0.03 (PUT)
   | PUT  |      |     Token: 0x77
   |      |      |  Uri-Path: lock
   |      |      |   Payload: 0 (Unlock)
   |      |      |
   |      @<-----+      Code: 2.04 (Changed)
   |      | 2.04 |     Token: 0x77
   |      |      |
     ....   ....
   |      |      |
   +----->X      |      Code: 0.03 (PUT)
   | PUT  |      |     Token: 0x77
   |      |      |  Uri-Path: lock
   |      |      |   Payload: 0 (Lock)
   |      |      |
   <------@      |      Code: 2.04 (Changed)
   | 2.04 |      |     Token: 0x77
   |      |      |
~~~~
{: #delayresPUT title='Delaying and mismatching response to PUT' artwork-align="center"}

If we once again take a lock as an example, the security consequences may
be severe as the client receives a response message likely to be interpreted
as confirmation of a locked door, while the received response message is
in fact confirming an earlier unlock of the door. As the client is likely
to leave the (believed to be locked) door unattended, the attacker may enter
the home, enterprise, or car protected by the lock.

The same attack may be performed on sensors, also this with serious consequences.
As illustrated in {{delayresGET}}, an attacker may convince the client
that the lock is locked, when it in fact is not. The "Unlock" request
may be also be sent by another client authorized to control the lock.

~~~~
Client   Foe   Server
   |      |      |
   +------------>|      Code: 0.01 (GET)
   | GET  |      |     Token: 0x77
   |      |      |  Uri-Path: lock
   |      |      |
   |      @<-----+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x77
   |      |      |   Payload: 1 (Locked)
   |      |      |
   +------------>|      Code: 0.03 (PUT)
   | PUT  |      |     Token: 0x34
   |      |      |  Uri-Path: lock
   |      |      |   Payload: 1 (Unlock)
   |      |      |
   |      X<-----+      Code: 2.04 (Changed)
   |      | 2.04 |     Token: 0x34
   |      |      |
   +----->X      |      Code: 0.01 (GET)
   | GET  |      |     Token: 0x77
   |      |      |  Uri-Path: lock
   |      |      |
   <------@      |      Code: 2.05 (Content)
   | 2.05 |      |     Token: 0x77
   |      |      |   Payload: 1 (Locked)
   |      |      |
~~~~
{: #delayresGET title='Delaying and mismatching response to GET' artwork-align="center"}

As illustrated in {{delayresother}}, an attacker may even mix
responses from different resources as long as the two resources share
the same (D)TLS connection on some part of the path towards the
client. This can happen if the resources are located behind a common
gateway, or are served by the same CoAP proxy. An on-path attacker
(not necessarily a (D)TLS endpoint such as a proxy) may e.g. deceive a
client that the living room is on fire by responding with an earlier
delayed response from the oven (temperatures in degree Celsius).

~~~~
Client   Foe   Server
   |      |      |
   +------------>|      Code: 0.01 (GET)
   | GET  |      |     Token: 0x77
   |      |      |  Uri-Path: oven/temperature
   |      |      |
   |      @<-----+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x77
   |      |      |   Payload: 225
   |      |      |
     ....   ....
   |      |      |
   +----->X      |      Code: 0.01 (GET)
   | GET  |      |     Token: 0x77
   |      |      |  Uri-Path: livingroom/temperature
   |      |      |
   <------@      |      Code: 2.05 (Content)
   | 2.05 |      |     Token: 0x77
   |      |      |   Payload: 225
   |      |      |
~~~~
{: #delayresother title='Delaying and mismatching response from other resource' artwork-align="center"}

Remedy: If CoAP is protected with a security protocol not providing bindings
between requests and responses (e.g. DTLS and TLS) the client MUST NOT reuse
any tokens until the traffic keys have been replaced. The easiest way to
accomplish this is to implement the Token as a counter, this approach SHOULD
be followed.


##  The Relay Attack

Yet another type of attack can be performed in deployments where actuator
actions are triggered automatically based on proximity and without any user
interaction, e.g. a car (the client) constantly polling for the car key (the
server) and unlocking both doors and engine as soon as the car key responds.
An attacker (or pair of attackers) may simply relay the CoAP messages out-of-band,
using for examples some other radio technology. By doing this, the actuator
(i.e. the car) believes that the client is close by and performs actions
based on that false assumption. The attack is illustrated in
{{relay}}. In this example the car is using an application specific
challenge-response mechanism transferred as CoAP payloads.


~~~~
Client   Foe         Foe   Server
   |      |           |      |
   +----->| ......... +----->|      Code: 0.02 (POST)
   | POST |           | POST |     Token: 0x3a
   |      |           |      |  Uri-Path: lock
   |      |           |      |   Payload: JwePR2iCe8b0ux (Challenge)
   |      |           |      |
   |<-----+ ......... |<-----+      Code: 2.04 (Changed)
   | 2.04 |           | 2.04 |     Token: 0x3a
   |      |           |      |   Payload: RM8i13G8D5vfXK (Response)
   |      |           |      |
~~~~
{: #relay title='Relay attack (the client is the actuator)' artwork-align="center"}

The consequences may be severe, and in the case of a car, lead to the attacker
unlocking and driving away with the car, an attack that unfortunately is
happening in practice.

Remedy: Getting a response over a short-range radio MUST NOT be taken as
proof of proximity and therefore MUST NOT be used to take actions based on
such proximity. Any automatically triggered mechanisms relying on proximity
MUST use other stronger mechanisms to guarantee proximity. Mechanisms that
MAY be used are: measuring the round-trip time and calculate the maximum
possible distance based on the speed of light, or using radio with an extremely
short range like NFC (centimeters instead of meters) that cannot be relayed
through e.g. clothes. Another option is to including geographical coordinates
(from e.g. GPS) in the messages and calculate proximity based on these, but
in this case the location measurements MUST be very precise and the system
MUST make sure that an attacker cannot influence the location estimation,
something that is very hard in practice.


## The Request Fragment Rearrangement Attack {#fragment}

These attack scenarios show that the Request Delay and Block Attacks can
be
used against blockwise transfers to cause unauthorized operations to be
performed on the server, and responses to unauthorized operations to be
mistaken for responses to authorized operations.
The combination of these attacks is described as a separate attack because
it makes the Request Delay Attack
relevant to systems that are otherwise not time-dependent, which means that
they could disregard the Request Delay Attack.

This attack works even if the individual request/response pairs are encrypted,
authenticated and protected against the Response Delay and Mismatch Attack,
provided the attacker is on the network path and can correctly guess which
operations the respective packages belong to.

### Completing an Operation with an Earlier Final Block

In this scenario (illustrated in {{promotevaljean}}), blocks from two
operations on a POST-accepting resource are combined to make the
server execute an action that was not intended by the authorized
client. This works only if the client attempts a second operation
after the first operation failed (due to what the attacker made appear
like a network outage) within the replay window. The client does not
receive a confirmation on the second operation either, but, by the
time the client acts on it, the server has already executed the
unauthorized action.

~~~~
Client   Foe   Server
   |      |      |
   +------------->    POST "incarcerate" (Block1: 0, more to come)
   |      |      |
   <-------------+    2.31 Continue (Block1: 0 received, send more)
   |      |      |
   +----->@      |    POST "valjean" (Block1: 1, last block)
   |      |      |
   +----->X      |    All retransmissions dropped
   |      |      |

(Client: Odd, but let's go on and promote Javert)

   |      |      |
   +------------->    POST "promote" (Block1: 0, more to come)
   |      |      |
   |      X<-----+    2.31 Continue (Block1: 0 received, send more)
   |      |      |
   |      @------>    POST "valjean" (Block1: 1, last block)
   |      |      |
   |      X<-----+    2.04 Valjean Promoted
   |      |      |
~~~~
{: #promotevaljean title='Completing an operation with an earlier final block'}

Remedy: If a client starts new blockwise operations on a security
context that has lost packages, it needs to label the fragments in
such a way that the server will not mix them up.

A mechanism to that effect is described as Request-Tag
{{I-D.ietf-core-echo-request-tag}}. Had it been in place in the
example and used for body integrity protection, the client would have
set the Request-Tag option in the "promote" request.
Depending on the server's capabilities and setup, either of four
outcomes could have occurred:

1. The server could have processed the reinjected POST "valjean" as belonging
   to the original "incarcerate" block; that's the expected case when the server
   can handle simultaneous block transfers.

1. The server could respond 5.03 Service Unavailable, including a Max-Age option
   indicating how
   long it prefers not to take any requests that force it to overwrite the state
   kept for the "incarcerate" request.

1. The server could decide to drop the state kept for the
   "incarcerate" request's state, and process the "promote"
   request. The reinjected POST "valjean" will then fail with 4.08
   Request Entity incomplete, indicating that the server does not have
   the start of the operation any more.

### Injecting a Withheld First Block

If the first block of a request is withheld by the attacker for later use,
it can be used to have the server process a different request body than
intended by the client. Unlike in the previous scenario, it will return a
response based on that body to the client.

Again, a first operation (that would go like “Homeless stole
apples. What shall we do with him?” – “Set him free.”) is aborted by
the proxy, and a part of that operation is later used in a different
operation to prime the server for responding leniently to another
operation that would originally have been “Hitman killed someone. What
shall we do with him?” – “Hang him.”. The attack is illustrated in
{{freethehitman}}.


~~~~
Client   Foe   Server
   |      |      |
   +----->@      |    POST "Homeless stole apples. Wh"
   |      |      |        (Block1: 0, more to come)

(Client: We'll try that one later again; for now, we have something
more urgent:)

   |      |      |
   +------------->    POST "Hitman killed someone. Wh"
   |      |      |        (Block1: 0, more to come)
   |      |      |
   |      @<-----+    2.31 Continue (Block1: 0 received, send more)
   |      |      |
   |      @------>    POST "Homeless stole apples. Wh"
   |      |      |        (Block1: 0, more to come)
   |      |      |
   |      X<-----+    2.31 Continue (Block1: 0 received, send more)
   |      |      |
   <------@      |    2.31 Continue (Block1: 0 received, send more)
   |      |      |
   +------------->    POST "at shall we do with him?"
   |      |      |        (Block1: 1, last block)
   |      |      |
   <-------------+    2.05 "Set him free."
   |      |      |        (Block1: 1 received and this is the result)
~~~~
{: #freethehitman title='Injecting a withheld first block'}



# Attacks using CoAP

## Denial-of-Service Attacks {#dos}

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
requests. An amplification attack alone can be denial-of-service attack on a server,
but often amplification attacks are combined with the attacker spoofing the
source IP address of the targeted victim. By requesting as much information
as possible from several servers an attacker can multiply the amount of
traffic and create a distributed denial-of-service attack on the target.
When transported over UDP, the CoAP NoSec
mode is susceptible to source IP address spoofing.

Amplification attacks with CoAP is unfortunately not only theory, amplification
factors of 10-100 are commonly reported from NoSec deployments. {{CoAP-Report}} and
{{CoAP-Wild}} report average amplification factor of 27 and 34 respectively
from a single response to a GET request for /.well-known/core to the default UDP port 5693.
NoSec CoAP servers accessible over the Internet are mostly concentrated to a few countries
and a few implementations, which do not follow the recommendations in Section
11.3 of [RFC7252] (but the requirements are a bit soft). 

An amplification attack using a single response is illustrated in {{ampsingle}}.
If the response is a times larger than the request, the amplification factor is a.

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
   |      |      |
~~~~
{: #ampsingle title='Amplification attack using a single response' artwork-align="center"}

An attacker can increase the bandwidth by sending several requests. An attacker can
also increase or control the amplification factor by creating or updating resources.
An amplification attack where the attacker influences the amplification factor
is illustrated in {{ampmulti_post}}.

~~~~
Client   Foe   Server
   |      |      |
   |      +----->|      Code: 0.02 (POST)
   |      | POST |  Uri-Path: /member/
   |      |      |   Payload: hampsterdance.hevc
   |      |      |
   |<------------+      Code: 2.04 (Changed)
   |      | 2.04 |
   |      |      |
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
   |      |      |
     ....   ....
~~~~
{: #ampmulti_post title='Amplification attack using a single response' artwork-align="center"}

Amplification factors can be significantly worse when combined with
observe {{RFC7641}}, publish-subscribe {{I-D.ietf-core-coap-pubsub}},
and multicast {{I-D.ietf-core-groupcomm-bis}}.

An amplification attack using observe is illustrated in
{{ampmulti_n}}. In this case a single request results in n responses
from a single server. If each response is a times larger than the request,
the amplification factor is a * n. If it is predictable when
notifications are sent in non-confirmable and which Message ID are used
the acknolegements can be spoofed.

~~~~
Client   Foe   Server
   |      |      |
   |      +----->|      Code: 0.01 (GET)
   |      | GET  |     Token: 0x83
   |      |      |   Observe: 0
   |      |      |  Uri-Path: stock market index 1 min
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x83
   |      |      |   Observe: 217362
   |      |      |   Payload: 3749.7
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x83
   |      |      |   Observe: 217363
   |      |      |   Payload: 3745.33
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x83
   |      |      |   Observe: 217364
   |      |      |   Payload: 3747.65
   |      |      |
     ....   ....
~~~~
{: #ampmulti_n title='Amplification attack using observe' artwork-align="center"}

By registering the same client several times, the bandwidth can be increased.
An amplification attack using several observe registrations is illustrated in
{{ampmulti_nk}}. If the attacker registers the same client k times, each
notification results in k responses to the same client. If each response
is a times larger than the request, and the server sends n notifications,
the amplification factor is still a * n.

~~~~
Client   Foe   Server
   |      |      |
   |      +----->|      Code: 0.01 (GET)
   |      | GET  |     Token: 0x83
   |      |      |   Observe: 0
   |      |      |  Uri-Path: stock market index 1 min
   |      |      |
   |      +----->|      Code: 0.01 (GET)
   |      | GET  |     Token: 0x84
   |      |      |   Observe: 0
   |      |      |  Uri-Path: stock market index 1 min
     ....   ....
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x83
   |      |      |   Observe: 217362
   |      |      |   Payload: 3749.7
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x84
   |      |      |   Observe: 217362
   |      |      |   Payload: 3749.7
   |      |      |
     ....   ....
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x83
   |      |      |   Observe: 217363
   |      |      |   Payload: 3745.33
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x84
   |      |      |   Observe: 217363
   |      |      |   Payload: 3745.33
   |      |      |
     ....   ....
~~~~
{: #ampmulti_nk title='Amplification attack using observe' artwork-align="center"}

With publish-subscribe {{I-D.ietf-core-coap-pubsub}} an
attacker gets increased control over the attack and can create an arbitrary
large amplification factor. An amplification attack using publish-subscribe
is illustrated in {{ampmulti_ps}}. If each response is a times larger than the request,
the attacker sends k subscriptions, and then publishes n times, the amplification factor
is larger than k * a * n / (k + a * n). Note that the attacker controls the variables a,
k, and n.

~~~~
Client   Foe   Server
   |      |      |
   |      +----->|      SUBSCRIBE
   |      +----->|      SUBSCRIBE
   |      +----->|      SUBSCRIBE
     ....   ....
   |      +----->|      PUBLISH
   |<------------+      2.05 Content
   |<------------+      2.05 Content
   |<------------+      2.05 Content
     ....   ....
   |      +----->|      PUBLISH
   |<------------+      2.05 Content
   |<------------+      2.05 Content
   |<------------+      2.05 Content
     ....   ....
   |      +----->|      PUBLISH
   |<------------+      2.05 Content
   |<------------+      2.05 Content
   |<------------+      2.05 Content
     ....   ....
~~~~
{: #ampmulti_ps title='Amplification attack using observe' artwork-align="center"}

An amplification attack using a multicast request is illustrated in
{{ampmulti_m}}. In this case a single request results in m responses
from m different servers. If each response is a times larger than the request,
the amplification factor is a * m. Note that the servers usually do not know
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
responses. If each response is a times larger than the request,
the amplification factor is a * n * m.


~~~~
Client   Foe   Server
   |      |      |
   |      +----->|      Code: 0.01 (GET)
   |      | GET  |     Token: 0x44
   |      |      |   Observe: 0
   |      |      |  Uri-Path: temperature
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
   |      |      |   Payload: "301.5 K"
   |      |      |
   |<------------+      Code: 2.05 (Content)
   |      | 2.05 |     Token: 0x44
   |      |      |   Observe: 364
   |      |      |   Payload: "293.6 K"
   |      |      |
     ....   ....
~~~~
{: #ampmulti_mn title='Amplification attack using multicast and observe' artwork-align="center"}

While CoAP has always considered amplification attacks, the recommendations
in {{RFC7252}}, {{RFC7641}}, and {{I-D.ietf-core-groupcomm-bis}} are a bit soft.
Most of the requirements are "SHOULD" instead of "MUST", it is undefined what a
"large amplification factor" is, {{RFC7641}} requires validation but with spoofable messages, and
in several cases the "SHOULD" level is further softened by “If possible" and "generally".
{{I-D.ietf-core-coap-pubsub}} does not have any amplification attack considerations.

QUIC {{RFC9000}} mandates that ”an endpoint MUST limit the amount of data it sends to the unvalidated address to three times the amount of data received from that address” without any exceptions. This approach should be seen as current best practice.

Remedy: {{RFC7252}}, {{RFC7641}}, and {{I-D.ietf-core-groupcomm-bis}} should be augmented with strict normative requirements (MUST) on implementations similar to QUIC with a specified anti-amplification limit. It should be clear that any devices used
in DDoS attacks are violating IETF requirements. 

# Security Considerations

The whole document can be seen as security considerations for CoAP.


# IANA Considerations

This document has no actions for IANA.


--- back

# Acknowledgements
{: numbered="false"}

The authors would like to thank Carsten Bormann, Klaus Hartke, Ari Keränen,
Matthias Kovatsch, Achim Kraus, Sandeep Kumar, and András Méhes for their valuable comments
and feedback.
