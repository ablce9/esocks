var mocha = require('mocha');
var assert = require('assert');
var socks = require('./socks');

var defaultOptions = {
    hostname: '127.0.0.1',
    port: 1080,
    socks5Command: socks.Command.connect,
};

mocha.describe('socks5', () => {
    mocha.it('connects', () => {
        const client = new socks.Socks5Client(defaultOptions);
        client.connect({destAddr: '127.0.0.1', destPort: 8080});
        assert.equal(client.state, socks.State.init);
    });

    mocha.it('creates conection', () => {
        socks.Socks5Client.createConnection({
            hostname: '127.0.0.1', port: 1080, destAddr: '127.0.0.1', destPort: 8080,
        }).then((conn) => {
            assert.ok(conn !== null);
            conn.write('hello');
        }).catch((err) => {
            throw ('error:', err);
        });
    });
});
