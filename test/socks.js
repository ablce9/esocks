"use strict";

var net = require("net");
// var tls = require("tls");
// var URL = require("url").URL;
var EventEmitter = require("events").EventEmitter;

var socks5Command = {
    connect:   0x01,
    bind:      0x02,
    associate: 0x03,
};

// var socks5Reply = {
//     granted:             0x00,
//     failure:             0x01,
//     notallowed:          0x02,
//     networkunreachable:  0x03,
//     hostunreachable:     0x04,
//     connectionrefused:   0x05,
//     ttlexpired:          0x06,
//     commandnotsupported: 0x07,
//     addressnotsupported: 0x08,
// };

const init      =  1 << 0;
const connected =  1 << 1;
const reading   =  1 << 2;
const writing   =  1 << 3;
const destroyed =  1 << 4;
const waiting   =  1 << 5;

class Socks5Client extends EventEmitter {
    constructor (options) {
        super();
        this._options = Object.assign({}, options);
        this.state |= init;
    };

    /**
     * createConnection creates a new socks5 connection.
     *
     * @param options { Socks5ClientOptions } Options.
     * @param callback { Function } An optional callback function.
     * @returns { Promise }
     **/
    static createConnection (options) {
        return new Promise((resolve, reject) => {
            const client = new Socks5Client(options);
            client.connect();
            client.once('established', (conn) => {
                resolve(conn);
            });
            client.once('error', (err) => {
                reject(err);
            });
        });
    };

    /**
     * connect connects to socks5 server
     *
     * @param options { Object }
     **/
    connect () {
        const done = (err) => {
            if (this._socket) {
                this._socket.destroy();
                this._socket = null;
                this.emit('error', err);
            };
        };
        let hostname, port, buf;
        hostname = this._options.hostname;
        port = this._options.port;

        if (!this._socket) {
            this._socket = new net.Socket();
        }

        // Set up options
        this._options.timeout = this._options.timeout || 3000 * 100;
        this._options.socks5Command = this._options.socks5Command || socks5Command.Connect;

        this._socket.setTimeout(this._options.timeout, () => {
            done(new Error('timeout'));
        });

        // events
        this._socket.once('close', () => {
            done(new Error('socket closed'));
        });
        this._socket.once('error', (err) => {
            done(err);
        });
        this._socket.once('connect', () => {
            this.state |= (connected | writing | reading);
            // Negotiate socks5 server.
            // No support for socks authentications.
            buf = new Buffer([0x05, 0x01, 0x00]);
            this._socket.write(buf);
        });
        this._socket.once('data', (data) => {
            if (this.state & init) {
                if (!(data[0] === 0x05 && data[1] === 0x00)) {
                    done(new Error("Wrong response from server"));
                    this.state &= init;
                }
            };
            if (this.state & connected) {
                // write some data here...
                this.emit('established', this._socket);
            };
        });

        // connect
        this._socket.connect(port, hostname);
    }
};

exports.Socks5Client = Socks5Client;
exports.State = {init, connected, reading, writing, destroyed, waiting};
