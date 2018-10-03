'use strict';

var net = require('net');
// var tls = require('tls');
// var URL = require('url').URL;
var EventEmitter = require('events').EventEmitter;

var socks5Command = {
    connect:   0x01,
    bind:      0x02,
    associate: 0x03,
};

var aType = {
    ipv4:   0x01,
    domain: 0x03,
    ipv6:   0x04,
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


module.exports.parseAddress = ({address}) => {
    var ret = net.isIP(address);
    let ip = 0;
    switch (ret) {
        case 0:
            ip = new Error('invalid address');
            break;
        case 4:
            var raw = address.split('.').map(e => parseInt(e, 10));
            ip += raw[0] << 24;
            ip += raw[1] << 16 & 0xff;
            ip += raw[2] << 8  & 0xff;
            ip += raw[3]       & 0xff;
            break;
        case 6:
            // TODO
            break;
    };
    return ip;
};

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
            client.connect(options);
            client.once('established', (conn) => {
                resolve(conn);
            });
            client.once('error', (err) => {
                client.removeAllListeners();
                reject(err);
            });
        });
    };

    /**
     * connect connects to socks5 server
     *
     * @param options { Object }
     **/
    connect (options) {
        const done = (err) => {
            if (this._socket && this.state) {
                this._socket.destroy();
                this._socket = null;
            };
            throw err;
        };
        let hostname, port, buf;
        hostname = this._options.hostname;
        port = this._options.port;

        if (!this._socket)
            this._socket = new net.Socket();

        // Set up options
        this._options.timeout = this._options.timeout || 3000 * 100;
        this._options.socks5Command = this._options.socks5Command || socks5Command.connect;

        this._socket.setTimeout(this._options.timeout, () => {
            done(new Error('timeout'));
        });

        // events
        this._socket.once('close', () =>
            done(new Error('socket closed'))
        );
        this._socket.once('error', (err) => {
            done(err);
        });
        this._socket.once('connect', () => {
            this.state |= (connected | writing | reading);
            // Negotiate to socks5 server.
            // No support for socks authentications.
            buf = new Buffer([0x05, 0x01, 0x00]);
            this._socket.write(buf);
        });
        this._socket.once('data', (data) => {
            if (this.state & init)
                if (!(data[0] === 0x05 && data[1] === 0x00)) {
                    console.log(data);
                    done(new Error('Wrong response from server'));
                    this.state &= init;
                    this.state |= destroyed;

                } else if (this.state & connected)
                    console.log('have some data for you ', data);


            if (this.state & writing) {
                // TODO: v6
                switch (net.isIP) {
                    case 4:
                        this._options.atype = aType.ipv4;
                        break;
                    case 6:
                        this._options.atype.atype = aType.ipv6;
                        throw new Error('not supported');
                        break;
                    case 0:
                        this._options.atype = domain;
                        break;
                };
                const atype = this._options.atype;
                var destAddr = options.destAddr, destPort = options.destPort || 80;

                if (atype === aType.ipv4) {
                    buf = Buffer.allocUnsafe(4+4+2);
                    var a = destAddr.split('.').map(e => parseInt(e, 10));
                    var p = [destPort >> 8, destPort & 0xff];
                    let offset = 0;
                    buf.writeUInt8(0x05, offset);
                    offset++;
                    buf.writeUInt8(this._options.socks5Command, offset);
                    offset++;
                    buf.writeUInt8(0x00, offset);
                    offset++;
                    buf.writeUInt8(atype, offset);
                    offset++;
                    a.forEach(e => {
                        buf.writeUInt8(e, offset);
                        offset++;
                    });
                    p.forEach(e => {
                        buf.writeUInt8(e, offset);
                        offset++;
                    });
                    this.state &= init;
                }
                this._socket.write(buf);

            };
            this.emit('established', this._socket);
        });

        // connect
        this._socket.connect(port, hostname);
    }
};

exports.Socks5Client = Socks5Client;
exports.Command = socks5Command;
exports.State = {init, connected, reading, writing, destroyed, waiting};
exports.aType = aType;
