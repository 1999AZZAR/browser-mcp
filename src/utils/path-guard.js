/*
 * Copyright (c) 2026 Azzar Budiyanto / LilyOpenCMS.
 * Licensed under the MIT License.
 *
 * Cytosol Path Guard (P0-A2) — Workspace containment and secret handling for
 * browser export paths, sessions, and downloads.
 */

const path = require('path');
const fs = require('fs');

class PolicyDeniedError extends Error {
    constructor(filePath, reason = 'escapes configured workspace roots') {
        super(`Path '${filePath}' ${reason}`);
        this.name = 'PolicyDeniedError';
    }
}

const FORBIDDEN_PREFIXES = [
    '/etc', '/bin', '/sbin', '/usr', '/boot', '/dev',
    '/proc', '/sys', '/lib', '/lib64', '/var/run',
];

function getWorkspaceRoots() {
    const raw = (process.env.HELA_ALLOWED_ROOTS || process.env.ALLOWED_ROOTS || '').trim();
    if (!raw) return null;
    return raw.split(':').map(r => r.trim()).filter(Boolean).map(r => path.resolve(r));
}

function safeFilename(name) {
    if (!name || typeof name !== 'string') {
        throw new Error('Invalid name parameter');
    }
    if (name.includes('/') || name.includes('\\') || name.includes('\0') || name.includes('..')) {
        throw new Error(`Invalid name '${name}': directory traversal characters not allowed`);
    }
    const trimmed = name.trim();
    if (!trimmed || trimmed === '.' || trimmed === '..') {
        throw new Error(`Invalid name '${name}'`);
    }
    return trimmed;
}

function canonicalSync(target) {
    const abs = path.isAbsolute(target) ? target : path.resolve(target);
    try {
        return fs.realpathSync(abs);
    } catch (_) {
        // Walk up to nearest existing ancestor
        const missing = [];
        let cursor = abs;
        while (true) {
            try {
                const realCursor = fs.realpathSync(cursor);
                return path.resolve(realCursor, ...missing);
            } catch {
                const parent = path.resolve(cursor, '..');
                missing.unshift(path.basename(cursor));
                if (parent === cursor) {
                    return path.resolve(cursor, ...missing);
                }
                cursor = parent;
            }
        }
    }
}

function checkOutputPath(targetPath) {
    if (!targetPath || typeof targetPath !== 'string') {
        throw new Error('Invalid output path');
    }

    const resolved = canonicalSync(targetPath);
    const roots = getWorkspaceRoots();

    if (roots && roots.length > 0) {
        const ok = roots.some(root => {
            const rel = path.relative(root, resolved);
            return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
        });
        if (!ok) {
            throw new PolicyDeniedError(targetPath, 'escapes configured workspace roots');
        }
    } else {
        for (const prefix of FORBIDDEN_PREFIXES) {
            if (resolved === prefix || resolved.startsWith(prefix + path.sep)) {
                throw new PolicyDeniedError(targetPath, `targets protected system path (${prefix})`);
            }
        }
    }

    return resolved;
}

module.exports = {
    checkOutputPath,
    safeFilename,
    PolicyDeniedError,
    getWorkspaceRoots,
};
