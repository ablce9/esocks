const assert = require('assert');

const mocha = require('mocha');

const socks = require('./socks');
const setup = require('./setup');

var defaultSocksOptions = {
    hostname: '127.0.0.1',
    port: 2080,
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
      procs.push(setup.setUpServer(
	setup.getEsocks(),
	  ['-p', '2081', '-k', 'mypassword', '-P', 'p1']));
      procs.push(setup.setUpServer(
	setup.getEsocks(),
	  ['-s', '127.0.0.1', '-j', '2081', '-p', '2080', '-k', 'mypassword', '-P', 'p2']));
    });
    mocha.after(() => {
	setTimeout(() => {
	    procs.forEach((pid) => {
		process.kill(pid, 'SIGTERM');
	    });
	}, 1000);
    });

    mocha.it('connects with ipv4', () => {
	return socks.Socks5Client.createConnection(defaultSocksOptions)
	    .then((conn) => {
		assert.ok(conn !== null);
		const buf = Buffer.allocUnsafe(1024);
		conn.write(buf);
		conn.on('data', (data) => {
		    // At least 1024 bytes I have.
		    // If data length is less than 1024, then a drain event
		    // is emitted and should I also check that???
		    assert.ok(data.length <= 1024);
		});
	    });
    });

    mocha.it('connects with domain', () => {
	const options = Object.assign({}, defaultSocksOptions,
	    {destAddr: 'google.com', destPort: 80});
	return socks.Socks5Client.createConnection(options)
	    .then((conn) => {
		assert.ok(conn !== null);
		conn.write('GET / HTTP/1.1');
		conn.on('data', (data) => {
		    assert.ok(data.length);
		});
	    });
    });
});
