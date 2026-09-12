/*
 * Copyright (c) 2026 Azzar Budiyanto / LilyOpenCMS.
 * Licensed under the MIT License.
 *
 * SSRF-safe URL validation — blocks dangerous schemes, private IPs,
 * DNS rebinding, cloud metadata endpoints, and credential URLs.
 */
const { URL } = require('url');
const dns = require('dns');
const net = require('net');

const BLOCKED_SCHEMES = new Set([
    'file', 'data', 'javascript', 'chrome', 'chrome-extension',
    'about', 'view-source', 'ws', 'wss', 'ftp', 'blob',
    'vbscript', 'mailto', 'tel', 'gopher', 'vnc',
]);

const BLOCKED_HOSTS = new Set([
    'localhost', '127.0.0.1', '::1', '0.0.0.0',
    'metadata.google.internal', '169.254.169.254',
    'local', 'internal', 'localdomain',
]);

const PRIVATE_RANGES = [
    { start: '10.0.0.0', end: '10.255.255.255' },
    { start: '172.16.0.0', end: '172.31.255.255' },
    { start: '192.168.0.0', end: '192.168.255.255' },
    { start: '169.254.0.0', end: '169.254.255.255' },
    { start: '127.0.0.0', end: '127.255.255.255' },
    { start: '100.64.0.0', end: '100.127.255.255' },
    { start: 'fc00::', end: 'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', ipv6: true },
    { start: 'fe80::', end: 'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff', ipv6: true },
    { start: '::1', end: '::1', ipv6: true },
];

function ipToLong(ip) {
    const parts = ip.split('.').map(Number);
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function isPrivateIP(ipStr) {
    // Check IPv4
    if (net.isIPv4(ipStr)) {
        const ip = ipToLong(ipStr);
        for (const range of PRIVATE_RANGES) {
            if (range.ipv6) continue;
            const start = ipToLong(range.start);
            const end = ipToLong(range.end);
            if (ip >= start && ip <= end) return true;
        }
        // Also check standard library
        const parts = ipStr.split('.').map(Number);
        if (parts[0] === 10) return true;
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
        if (parts[0] === 192 && parts[1] === 168) return true;
        if (parts[0] === 127) return true;
        if (parts[0] === 169 && parts[1] === 254) return true;
        return false;
    }

    // Check IPv6
    if (net.isIPv6(ipStr)) {
        const lower = ipStr.toLowerCase();
        if (lower === '::1') return true;
        if (lower.startsWith('fc00:') || lower.startsWith('fd00:')) return true;
        if (lower.startsWith('fe80:')) return true;
        if (lower.startsWith('::ffff:127.')) return true;
        if (lower.startsWith('::ffff:10.')) return true;
        if (lower.startsWith('::ffff:172.16.') || lower.startsWith('::ffff:172.17.') ||
            lower.startsWith('::ffff:172.18.') || lower.startsWith('::ffff:172.19.') ||
            lower.startsWith('::ffff:172.2') || lower.startsWith('::ffff:172.3')) return true;
        if (lower.startsWith('::ffff:192.168.')) return true;
        return false;
    }

    return false;
}

function validateURL(urlStr, { allowPrivate = false, allowAllSchemes = false } = {}) {
    let parsed;
    try {
        parsed = new URL(urlStr);
    } catch {
        throw new Error(`Invalid URL: ${urlStr}`);
    }

    const scheme = parsed.protocol.replace(':', '').toLowerCase();
    if (!allowAllSchemes && BLOCKED_SCHEMES.has(scheme)) {
        throw new Error(`Forbidden scheme: ${scheme}`);
    }
    if (!allowAllSchemes && scheme !== 'http' && scheme !== 'https') {
        throw new Error(`Unsupported scheme: ${scheme} (use http or https)`);
    }

    if (parsed.username || parsed.password) {
        throw new Error('URLs containing credentials (user:pass@) are not allowed');
    }

    const hostname = parsed.hostname;
    if (!hostname) {
        throw new Error('Missing hostname in URL');
    }

    const lowered = hostname.toLowerCase();
    if (BLOCKED_HOSTS.has(lowered) || lowered.endsWith('.local') || lowered.endsWith('.internal')) {
        if (!allowPrivate) {
            throw new Error(`Access to ${hostname} is blocked (private/internal)`);
        }
    }

    if (!allowPrivate && isPrivateIP(hostname)) {
        throw new Error(`Private IP targets are blocked: ${hostname}`);
    }
}

async function resolveAndValidate(hostname, { allowPrivate = false } = {}) {
    if (allowPrivate) return;
    if (!hostname) throw new Error('Missing hostname for DNS validation');

    const lower = hostname.toLowerCase();
    if (BLOCKED_HOSTS.has(lower) || lower.endsWith('.local') || lower.endsWith('.internal')) {
        throw new Error(`Access to ${hostname} is blocked (private/internal)`);
    }

    if (isPrivateIP(hostname)) {
        throw new Error(`Private IP targets are blocked: ${hostname}`);
    }

    return new Promise((resolve, reject) => {
        dns.lookup(hostname, { all: true }, (err, addresses) => {
            if (err) {
                // If hostname cannot be resolved, allow subsequent network call to handle error
                resolve();
                return;
            }
            for (const item of addresses) {
                const addr = typeof item === 'string' ? item : item.address;
                if (isPrivateIP(addr)) {
                    reject(new Error(`DNS resolved to private IP ${addr} for ${hostname}`));
                    return;
                }
            }
            resolve();
        });
    });
}

module.exports = { validateURL, resolveAndValidate, isPrivateIP, BLOCKED_SCHEMES, BLOCKED_HOSTS };

