# tart-transport-tls

_Stability: 1 - [Experimental](https://github.com/tristanls/stability-index#stability-1---experimental)_

[![NPM version](https://badge.fury.io/js/tart-transport-tls.png)](http://npmjs.org/package/tart-transport-tls)

TLS transport implementation for [Tiny Actor Run-Time in JavaScript](https://github.com/organix/tartjs).

## Contributors

[@dalnefre](https://github.com/dalnefre), [@tristanls](https://github.com/tristanls)

## Overview

An implementation of a TLS transport for [Tiny Actor Run-Time in JavaScript](https://github.com/organix/tartjs).

  * [Usage](#usage)
  * [Tests](#tests)
  * [Documentation](#documentation)
  * [Sources](#sources)

## Usage

To run the below example run:

    npm run readme

```javascript
"use strict";

var fs = require('fs');
var path = require('path');
var tart = require('tart');
var tls = require('tls');
var transport = require('../index.js');

var sponsor = tart.minimal();

var send = sponsor(transport.sendBeh);

var receivedMessageCount = 0;
var receptionist = sponsor(function (message) {
    console.log('received message:', message);
    receivedMessageCount++;
    if (receivedMessageCount >= 2) {
        close(); // close listening server
    }
});

var serverCapabilities = transport.server(receptionist);
var close = sponsor(serverCapabilities.closeBeh);
var listen = sponsor(serverCapabilities.listenBeh);

var fail = sponsor(function (error) {
    console.dir(error);
});

var listenAck = sponsor(function listenAckBeh(message) {
    console.log('transport listening on tcp://' + message.host + ':' + message.port);
    send({
        address: 'tcp://localhost:7847/#t5YM5nxnJ/xkPTo3gtHEyLdwMRFIwyJOv5kvcFs+FoMGdyoDNgSLolq0',
        content: '{"some":{"json":"content"},"foo":true}',

        key: fs.readFileSync(path.normalize(path.join(__dirname, 'readme/client-key.pem'))),
        cert: fs.readFileSync(path.normalize(path.join(__dirname, 'readme/client-cert.pem'))),
        rejectUnauthorized: true,
        secureProtocol: "TLSv1_method",
        ca: [fs.readFileSync(path.normalize(path.join(__dirname, 'readme/server-cert.pem')))],

        fail: fail,
        ok: function () {
            console.log('foo sent');
        }
    });
    send({
        address: 'tcp://localhost:7847/#I0InGCVn0ApX0YBnF5+JFMheKOajHkaTrNthYRI2hOj4GrM5IaWO1Cv0',
        content: '{"some":{"json":"content"},"bar":true}',

        key: fs.readFileSync(path.normalize(path.join(__dirname, 'readme/client-key.pem'))),
        cert: fs.readFileSync(path.normalize(path.join(__dirname, 'readme/client-cert.pem'))),
        rejectUnauthorized: true,
        secureProtocol: "TLSv1_method",
        ca: [fs.readFileSync(path.normalize(path.join(__dirname, 'readme/server-cert.pem')))],

        fail: fail,
        ok: function () {
            console.log('bar sent');
        }
    });    
});

listen({
    host: 'localhost', 
    port: 7847, 

    // TLS options

    key: fs.readFileSync(path.normalize(path.join(__dirname, 'readme/server-key.pem'))),
    cert: fs.readFileSync(path.normalize(path.join(__dirname, 'readme/server-cert.pem'))),
    rejectUnauthorized: true,
    secureProtocol: "TLSv1_method",
    // This is necessary only if using the client certificate authentication.
    requestCert: true,
    // This is necessary only if the client uses the self-signed certificate.
    ca: [fs.readFileSync(path.normalize(path.join(__dirname, 'readme/client-cert.pem')))],

    // customers

    ok: listenAck,
    fail: fail
});
```

## Tests

    npm test

## Documentation

**Public API**

  * [transport.sendBeh](#transportsendbeh)
  * [transport.server(receptionist)](#transportserverreceptionist)
  * [serverCapabilities.closeBeh](#servercapabilitiesclosebeh)
  * [serverCapabilities.listenBeh](#servercapabilitieslistenbeh)

### transport.sendBeh

Actor behavior that will attempt to send messages over TLS.

Message format:

  * `address`: _String_ TCP address in URI format. Scheme, host, and port are required. Framgment is optional but usually necessary. For example: `tcp://localhost:7847/#t5YM5nxnJ/xkPTo...`. 
  * `content`: _String_ JSON content to be sent.
  * `fail`: _Actor_ `function (error) {}` _(Default: undefined)_ Optional actor to report `error` (if any).
  * `ok`: _Actor_ `function () {}` _(Default: undefined)_ Optional actor to report successful send to the destination.

_TLS Options_:

  * `pfx`: See [TLS connect options](http://nodejs.org/api/tls.html#tls_tls_connect_options_callback).
  * `key`: See [TLS connect options](http://nodejs.org/api/tls.html#tls_tls_connect_options_callback).
  * `passhprase`: See [TLS connect options](http://nodejs.org/api/tls.html#tls_tls_connect_options_callback).
  * `cert`: See [TLS connect options](http://nodejs.org/api/tls.html#tls_tls_connect_options_callback).
  * `ca`: See [TLS connect options](http://nodejs.org/api/tls.html#tls_tls_connect_options_callback).
  * `rejectUnauthorized`: See [TLS connect options](http://nodejs.org/api/tls.html#tls_tls_connect_options_callback).
  * `NPNProtocols`: See [TLS connect options](http://nodejs.org/api/tls.html#tls_tls_connect_options_callback).
  * `servername`: See [TLS connect options](http://nodejs.org/api/tls.html#tls_tls_connect_options_callback).
  * `secureProtocol`: See [TLS connect options](http://nodejs.org/api/tls.html#tls_tls_connect_options_callback).

```javascript
var send = sponsor(transport.sendBeh);
send({
    address: 'tcp://localhost:7847/#ZkiLrAwGX7N1eeOXXMAeoVp7vsYJKeISjfT5fESfkRiZOIpkPx1bAS8y', 
    content: '{"some":{"json":"content"}}',
    key: fs.readFileSync('client-key.pem'),
    cert: fs.readFileSync('client-cert.pem'),
    rejectUnauthorized: true,
    secureProtocol: "TLSv1_method",
    ca: [fs.readFileSync('server-cert.pem')]
});
```

### transport.server(receptionist)

  * `receptionist`: _Actor_ `function (message) {}` Actor to forward traffic received by this server in `{address: <URI>, contents: <json>}` format.
  * Return: _Object_ An object containing behaviors for listen and close capabilities.
    * `closeBeh`: [serverCapabilities.closeBeh](#servercapabilitiesclosebeh)
    * `listenBeh`: [serverCapabilities.listenBeh](#servercapabilitieslistenbeh)

Creates an entangled pair of capabilities that will control a single TLS server.

### serverCapabilities.closeBeh

Actor behavior that will close a listening server.

Message is an `ack` _Actor_ `function () {}`, an actor that will be sent an empty message once the server closes.

```javascript
var serverCapabilities = transport.server(receptionist);
var close = sponsor(serverCapabilities.closeBeh);
close(sponsor(function ack() {
    console.log('acked close'); 
});
```

### serverCapabilities.listenBeh

Actor behavior that will create a new listening TLS server.

Message format:

  * `host`: _String_ TLS host to listen on.
  * `port`: _Number_ TLS port to listen on.
  * `ok`: _Actor_ `function (message) {}` Optional actor to receive acknowledgment once the server is listening.
  * `fail`: _Actor_ `function (error) {}` Optional actor to receive any errors when starting the TLS transport.

_TLS Options_:

  * `pfx`: See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
  * `key`: See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
  * `passphrase`: See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
  * `cert`: See See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
  * `ca`: See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
  * `crl`: See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
  * `ciphers`: See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
  * `handshakeTimeout`: See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
  * `honorCipherOrder`: See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
  * `requestCert`: See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
  * `rejectUnauthorized`: See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
  * `NPNProtocols`: See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
  * `sessionIdContext`: See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
  * `secureProtocol`: See [TLS server options](http://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).

```javascript
var serverCapabilities = transport.server(receptionist);
var listen = sponsor(serverCapabilities.listenBeh);
listen({
    host: 'localhost',
    port: 7847,

    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    rejectUnauthorized: true,
    secureProtocol: "TLSv1_method",
    // This is necessary only if using the client certificate authentication.
    requestCert: true,
    // This is necessary only if the client uses the self-signed certificate.
    ca: [fs.readFileSync('client-cert.pem')],

    ok: sponsor(function listenAckBeh(message) {
        console.log('transport listening on tcp://' + message.host + ':' + message.port);
    }),
    fail: sponsor(function failBeh(message) {
        console.error(message);
    })
});
```

## Sources

  * [Tiny Actor Run-Time (JavaScript)](https://github.com/organix/tartjs)