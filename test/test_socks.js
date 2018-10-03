const assert = require('assert');
const mocha = require('mocha');

const socks = require('./socks');
const setup = require('./setup');

var defaultOptions = {
    hostname: '127.0.0.1',
    port: 1080,
    socks5Command: socks.Command.connect,
};

mocha.describe('socks5', () => {
    let a, b;
    mocha.before(function () {
        a = setup.setUpServer(setup.getEsocks(), ['-p', '1081']);
        b = setup.setUpServer(setup.getEsocks(), ['-j', '1081']);
    });
    mocha.after(function () {
        setTimeout(function () {
	    [a, b].forEach(function (pid) {
                process.kill(pid, 'SIGTERM');
	    });
        }, 1000);
    });

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
