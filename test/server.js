/*

server.js - server test

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
var tls = require('tls');
var tart = require('tart-tracing');
var transport = require('../index.js');

var test = module.exports = {};

test["listen capability starts the server if it isn't listening"] = function (test) {
    test.expect(4);
    var tracing = tart.tracing();
    var sponsor = tracing.sponsor;

    var receptionist = sponsor(function () {});
    var serverCaps = transport.server(receptionist);
    var close = sponsor(serverCaps.closeBeh);
    var listen = sponsor(serverCaps.listenBeh);

    var fail = sponsor(function (error) {
        test.ok(false, error);
    });

    var listenAck = sponsor(function listenAckBeh(message) {
        var options = {
            host: message.host,
            port: message.port,
            key: fs.readFileSync(path.normalize(path.join(__dirname, 'certs/client-key.pem'))),
            cert: fs.readFileSync(path.normalize(path.join(__dirname, 'certs/client-cert.pem'))),
            rejectUnauthorized: true,
            secureProtocol: "TLSv1_method",
            requestCert: true,
            ca: [fs.readFileSync(path.normalize(path.join(__dirname, 'certs/server-cert.pem')))]
        };
        var client = tls.connect(options, function () {
            test.ok(true); // connected!
            client.end();
            close(sponsor(function () {
                test.done();
            }));
        })
    });

    listen({
        host: 'localhost', 
        port: 8888, 

        key: fs.readFileSync(path.normalize(path.join(__dirname, 'certs/server-key.pem'))),
        cert: fs.readFileSync(path.normalize(path.join(__dirname, 'certs/server-cert.pem'))),
        rejectUnauthorized: true,
        secureProtocol: "TLSv1_method",
        requestCert: true,
        ca: [fs.readFileSync(path.normalize(path.join(__dirname, 'certs/client-cert.pem')))],

        ok: listenAck,
        fail: fail
    });

    // expect 4 bursts of messages
    // first, to start listening
    // second, after server is listening, to deliver the ack
    // third, deliver message to "close"
    // fourth, ack after closing server
    var bursts = 4;
    var drainEventLoop = function drainEventLoop() {
        if (bursts-- > 0) {
            test.ok(tracing.eventLoop());
            setTimeout(drainEventLoop, 100);
        }
    };
    drainEventLoop();
};

test["listening server sends received messages to receptionist"] = function (test) {
    test.expect(6);
    var tracing = tart.tracing();
    var sponsor = tracing.sponsor;

    var address = 'tcp://localhost:8888/#some-token';
    var content = '{"some":{"json":"content"}}';

    var receptionist = sponsor(function (message) {
        test.equal(message.address, address);
        test.equal(message.content, content);
        close(sponsor(function () {
            test.done();
        }));
    });
    var serverCaps = transport.server(receptionist);
    var close = sponsor(serverCaps.closeBeh);
    var listen = sponsor(serverCaps.listenBeh);

    var fail = sponsor(function (error) {
        test.ok(false, error);
    });

    var listenAckBeh = function listenAckBeh(message) {
        var options = {
            host: message.host,
            port: message.port,
            key: fs.readFileSync(path.normalize(path.join(__dirname, 'certs/client-key.pem'))),
            cert: fs.readFileSync(path.normalize(path.join(__dirname, 'certs/client-cert.pem'))),
            rejectUnauthorized: true,
            secureProtocol: "TLSv1_method",
            requestCert: true,
            ca: [fs.readFileSync(path.normalize(path.join(__dirname, 'certs/server-cert.pem')))]
        };
        var client = tls.connect(options, function () {
            test.ok(true); // connected
            client.write(address + '\r\n');
            client.end(content + '\r\n');
        })        
    };

    listen({
        host: 'localhost', 
        port: 8888, 

        key: fs.readFileSync(path.normalize(path.join(__dirname, 'certs/server-key.pem'))),
        cert: fs.readFileSync(path.normalize(path.join(__dirname, 'certs/server-cert.pem'))),
        rejectUnauthorized: true,
        secureProtocol: "TLSv1_method",
        requestCert: true,
        ca: [fs.readFileSync(path.normalize(path.join(__dirname, 'certs/client-cert.pem')))],

        ok: sponsor(listenAckBeh),
        fail: fail
    });

    // expect 4 bursts of messages
    // first, send message to "listen"
    // second, when server is listening, deliver "ack"
    // third, deliver messages to receptionists and send out "close"
    // fourth, ack after closing server
    var bursts = 4;
    var drainEventLoop = function drainEventLoop() {
        if (bursts-- > 0) {
            test.ok(tracing.eventLoop());
            setTimeout(drainEventLoop, 100);
        }
    };
    drainEventLoop();
};