var mocha = require('mocha');
var assert = require('assert');
var socks = require('./socks');

mocha.describe('socks5', () => {
    mocha.describe('createConnection', () => {
        const client = socks.Socks5Client.createConnection({
	    hostname: '127.0.0.1', port: 1080,
        }).then((conn) => {
	    assert.ok(conn !== null);
	    conn.write(client);
        }).catch((err) => {
	    throw ('error:', err);
        });
    });
});
