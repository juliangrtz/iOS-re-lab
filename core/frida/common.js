// This will be appended to the user's script.
// Essentially we want to turn console.* calls into send() calls such that we can receive the logged data on the Python side.
(function () {
    let _orig = {
        log: console.log,
        error: console.error,
        warn: console.warn,
        info: console.info
    };

    function safeSerialize(value) {
        try {
            return JSON.stringify(value);
        } catch (e) {
            try {
                return String(value);
            } catch (e2) {
                return "<unserializable>";
            }
        }
    }

    function argsToArray(args) {
        return Array.prototype.slice.call(args).map(safeSerialize);
    }

    function makeHandler(level) {
        return function () {
            try {
                send({
                    type: "console",
                    level: level,
                    args: argsToArray(arguments),
                    stack: (new Error()).stack
                });
            } catch (e) {
            }
            try {
                _orig[level].apply(console, arguments);
            } catch (_) {
            }
        };
    }

    ["log", "error", "warn", "info"].forEach(function (m) {
        if (console && console[m]) {
            console[m] = makeHandler(m);
        } else {
            console = console || {};
            console[m] = makeHandler(m);
        }
    });
})();
