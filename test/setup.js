const assert = require('assert');
const net = require('net');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

function echoServer (options) {
    const server = new net.Server();
    server.on('error', function (err) {
        throw err;
    });
    server.on('connection', function (conn) {
        conn.on('data', function (data) {
            conn.write(data);
        });
    });
    server.listen(options, function() {
        console.log('sandbox server is up and running');
    });
}

function getEsocks () {
    const bin = path.join(process.cwd(), '../esocks');
    if (fs.existsSync(bin))
        return bin;

    console.error('esocks doesn\'t exist!');
    return 1;
}

/**
 * setUpServer sets up esocks
 *
 * @param bin      { String } path to binary
 * @param args     { Array  } args for the binary
 * @param options  { Object } options for child_process
 * @return         { Int    } pid
 */
function setUpServer (bin, args, options) {
    const _options = Object.assign({}, {detached: true}, options);
    const proc  = cp.spawn(bin, args, _options);
    proc.stderr.pipe(process.stdout);
    proc.on('exit', function (err) {
        assert.equal(err, 0);
        console.error('exit with:', err);
        return err;
    });

    return proc.pid;
};

module.exports = {
    getEsocks: getEsocks,
    setUpServer: setUpServer,
    echoServer: echoServer,
};
