"use strict";

// Standard-library API denial for the installed checker, not an OS sandbox.
// Throw before callbacks, promises, DNS resolution, or socket creation can run.
function denyNetwork() {
    const error = new Error("OFFLINE Pyright: Node network APIs are disabled");
    error.code = "ERR_OFFLINE_NETWORK";
    throw error;
}

function block(owner, names) {
    for (const name of names) {
        if (typeof owner[name] === "function") owner[name] = denyNetwork;
    }
}

const net = require("node:net");
block(net, ["connect", "createConnection", "createServer"]);
block(net.Socket.prototype, ["connect"]);
block(net.Server.prototype, ["listen"]);

const tls = require("node:tls");
block(tls, ["connect", "createServer", "TLSSocket"]);

for (const name of ["http", "https"]) {
    const api = require("node:" + name);
    block(api, ["request", "get", "createServer"]);
    block(api.Agent.prototype, ["createConnection"]);
    block(api.globalAgent, ["createConnection"]);
}
block(require("node:http2"), ["connect", "createServer", "createSecureServer"]);

const dgram = require("node:dgram");
block(dgram.Socket.prototype, [
    "bind", "connect", "send", "sendto", "addMembership", "addSourceSpecificMembership"
]);
block(dgram, ["createSocket", "Socket"]);

const dns = require("node:dns");
for (const api of [dns, dns.promises, dns.Resolver.prototype, dns.promises.Resolver.prototype]) {
    block(api, Object.getOwnPropertyNames(api).filter(name => /^(lookup|resolve|reverse)/.test(name)));
}
block(globalThis, ["fetch", "WebSocket", "EventSource"]);

// Also update named ESM exports, including node:dns/promises aliases.
require("node:module").syncBuiltinESMExports();
