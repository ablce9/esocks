const assert = require('assert');
const net = require('net');

const mocha = require('mocha');

const socks = require('./socks');
const setup = require('./setup');

var defaultSocksOptions = {
    hostname: '127.0.0.1',
    port: 1080,
    socks5Command: socks.Command.connect,
    destAddr: '127.0.0.1',
    destPort: 8080,
};

var defaultSandboxServerOptions = {
    port: 8080,
};

mocha.describe('socks5', () => {
    let a, b;
    setup.echoServer(defaultSandboxServerOptions);
    mocha.before(() => {
        a = setup.setUpServer(setup.getEsocks(), ['-p', '1081']);
        b = setup.setUpServer(setup.getEsocks(), ['-j', '1081']);
    });
    mocha.after(() => {
        setTimeout(() => {
            [a, b].forEach((pid) => {
                process.kill(pid, 'SIGTERM');
            });
        }, 1000);
    });

    mocha.it('connects with ipv4', () => {
        socks.Socks5Client.createConnection(defaultSocksOptions)
             .then((conn) => {
                 assert.ok(conn !== null);
                 const buf = Buffer.allocUnsafe(1024);
                 conn.write(buf);
             });
    });
    mocha.it('connects with ipv6', () => {
                const options = Object.assign({}, {destAddr: 'fe80::2fca:e754:769d:a8f9'},
                                              defaultSandboxServerOptions);
        socks.Socks5Client.createConnection(options)
             .then((conn) => {
                 assert.ok(conn !== null);
                 const buf = Buffer.allocUnsafe(1024);
                 conn.write(buf);
             });
    });
    mocha.it('connects with domain', () => {
        const options = Object.assign({}, {destAddr: 'google.com'},
                                      defaultSandboxServerOptions);
        socks.Socks5Client.createConnection(options)
             .then((conn) => {
                 assert.ok(conn !== null);
                 const buf = Buffer.allocUnsafe(1024);
                 conn.write(buf);
             });
    });
});
