const assert = require('assert');

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
    const procs = [];
    setup.echoServer(defaultSandboxServerOptions);
    mocha.before(() => {
        procs.push(setup.setUpServer(setup.getEsocks(), ['-p', '1081']));
        procs.push(setup.setUpServer(setup.getEsocks(), ['-j', '1081']));
    });
    mocha.after(() => {
        setTimeout(() => {
            procs.forEach((pid) => {
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
    mocha.it('connects with domain', () => {
        const options = Object.assign({}, defaultSocksOptions,
            {destAddr: 'google.com', destPort: 80});
        socks.Socks5Client.createConnection(options)
            .then((conn) => {
                assert.ok(conn !== null);
                conn.write('GET / HTTP/1.1');
            });
    });
});
