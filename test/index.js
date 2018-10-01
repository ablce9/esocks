const assert = require('assert');
const cp = require("child_process");

async function main () {
    const proc0 = cp.spawn('../esocks', ['-p', '1081'], {
        detached: true,
    });
    proc0.stderr.pipe(process.stdout);
    proc0.on('exit', function (err) {
        assert.equal(err, 0);
        console.error('exit with: ', err);
        return err;
    });

    const proc1 = cp.spawn('../esocks', ['-j', '1081'], {
        detached: true,
    });
    proc1.stderr.pipe(process.stdout);
    proc1.on('exit', function (err) {
        assert.equal(err, 0);
        console.error('exit with: ', err);
        return err;
    });

    return 0;
}

main().then(res => {
    console.error('started');
}).catch(err => {
    process.exit(err);
});
