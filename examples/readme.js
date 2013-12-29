/*

readme.js - example from the README

The MIT License (MIT)

Copyright (c) 2013 Tristan Slominski

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

*/
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