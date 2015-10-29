---
layout: post
---

##MTOM

Message Transmission Optimisation Mechanism (MTOM) is a standard that is developed by W3C. MTOM describes mechanism for optimising the transmission or wire format of a SOAP message by selectively re-encoding portions of the message while still presenting an XML information set to the SOAP application.

There are different ways we may want to send binary attachments:
1. Ecoding with base64 inline in the SOAP payload. However, encoding inline tends to enlarge the size of the SOAP message. Note that the base64 encoding might double the size of the binary data.
2. Encoding the messages by using SOAP with attachments and follow the webservices Interoperability Organisation (WS-I)
3. Providing optimisation of binary message transportation by using XML-binary optimised packaging (XOP). Optimisation is available only for binary data or content.  MTOM uses XOP in the context of SOAP and MIME over HTTP.

