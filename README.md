# TSAConnector
Java connector to the timestamp authority (TSA). It should work with any RFC 3161 compliant TSA server.

### Description
It is able to create a request from any arbitrary file (reads binary data), send a request to TSA and receive a response, parse and save the response, verify whether the timestamp corresponds to given file, read and validate certificates included inside the timestamp and also validate certificates provided from external file (untested).

The TSA's address and hashing algorithm are configurable.

### Prerequisities
- Java 1.8
- BouncyCastle 1.58
- Log4J 2.5
