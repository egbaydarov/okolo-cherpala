(function webpackUniversalModuleDefinition(root, factory) {
	if(typeof exports === 'object' && typeof module === 'object')
		module.exports = factory();
	else if(typeof define === 'function' && define.amd)
		define([], factory);
	else if(typeof exports === 'object')
		exports["GramJs"] = factory();
	else
		root["GramJs"] = factory();
})(self, () => {
return /******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "./node_modules/@cryptography/aes/dist/es/aes.js":
/*!*******************************************************!*\
  !*** ./node_modules/@cryptography/aes/dist/es/aes.js ***!
  \*******************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   CTR: () => (/* binding */ AES_IGE$1),
/* harmony export */   IGE: () => (/* binding */ AES_IGE),
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
var S = new Uint8Array(256);
var Si = new Uint8Array(256);
var T1 = new Uint32Array(256);
var T2 = new Uint32Array(256);
var T3 = new Uint32Array(256);
var T4 = new Uint32Array(256);
var T5 = new Uint32Array(256);
var T6 = new Uint32Array(256);
var T7 = new Uint32Array(256);
var T8 = new Uint32Array(256);
function computeTables() {
    var d = new Uint8Array(256);
    var t = new Uint8Array(256);
    var x2;
    var x4;
    var x8;
    var s;
    var tEnc;
    var tDec;
    var x = 0;
    var xInv = 0;
    // Compute double and third tables
    for (var i = 0; i < 256; i++) {
        d[i] = i << 1 ^ (i >> 7) * 283;
        t[d[i] ^ i] = i;
    }
    for (; !S[x]; x ^= x2 || 1) {
        // Compute sbox
        s = xInv ^ xInv << 1 ^ xInv << 2 ^ xInv << 3 ^ xInv << 4;
        s = s >> 8 ^ s & 255 ^ 99;
        S[x] = s;
        Si[s] = x;
        // Compute MixColumns
        x8 = d[x4 = d[x2 = d[x]]];
        tDec = x8 * 0x1010101 ^ x4 * 0x10001 ^ x2 * 0x101 ^ x * 0x1010100;
        tEnc = d[s] * 0x101 ^ s * 0x1010100;
        T1[x] = tEnc = tEnc << 24 ^ tEnc >>> 8;
        T2[x] = tEnc = tEnc << 24 ^ tEnc >>> 8;
        T3[x] = tEnc = tEnc << 24 ^ tEnc >>> 8;
        T4[x] = tEnc = tEnc << 24 ^ tEnc >>> 8;
        T5[s] = tDec = tDec << 24 ^ tDec >>> 8;
        T6[s] = tDec = tDec << 24 ^ tDec >>> 8;
        T7[s] = tDec = tDec << 24 ^ tDec >>> 8;
        T8[s] = tDec = tDec << 24 ^ tDec >>> 8;
        xInv = t[xInv] || 1;
    }
}

/**
 * Gets a uint32 from string in big-endian order order
 */
function s2i(str, pos) {
    return (str.charCodeAt(pos) << 24
        ^ str.charCodeAt(pos + 1) << 16
        ^ str.charCodeAt(pos + 2) << 8
        ^ str.charCodeAt(pos + 3));
}

/* eslint-disable import/prefer-default-export */
/**
 * Helper function for transforming string key to Uint32Array
 */
function getWords(key) {
    if (key instanceof Uint32Array) {
        return key;
    }
    if (typeof key === 'string') {
        if (key.length % 4 !== 0)
            for (var i = key.length % 4; i <= 4; i++)
                key += '\0x00';
        var buf = new Uint32Array(key.length / 4);
        for (var i = 0; i < key.length; i += 4)
            buf[i / 4] = s2i(key, i);
        return buf;
    }
    if (key instanceof Uint8Array) {
        var buf = new Uint32Array(key.length / 4);
        for (var i = 0; i < key.length; i += 4) {
            buf[i / 4] = (key[i] << 24
                ^ key[i + 1] << 16
                ^ key[i + 2] << 8
                ^ key[i + 3]);
        }
        return buf;
    }
    throw new Error('Unable to create 32-bit words');
}
function xor(left, right, to) {
    if (to === void 0) { to = left; }
    for (var i = 0; i < left.length; i++)
        to[i] = left[i] ^ right[i];
}

computeTables();
/**
 * Low-level AES Cipher
 */
var AES = /** @class */ (function () {
    function AES(_key) {
        var key = getWords(_key);
        if (key.length !== 4 && key.length !== 6 && key.length !== 8) {
            throw new Error('Invalid key size');
        }
        this.encKey = new Uint32Array(4 * key.length + 28);
        this.decKey = new Uint32Array(4 * key.length + 28);
        this.encKey.set(key);
        var rcon = 1;
        var i = key.length;
        var tmp;
        // schedule encryption keys
        for (; i < 4 * key.length + 28; i++) {
            tmp = this.encKey[i - 1];
            // apply sbox
            if (i % key.length === 0 || (key.length === 8 && i % key.length === 4)) {
                tmp = S[tmp >>> 24] << 24 ^ S[(tmp >> 16) & 255] << 16 ^ S[(tmp >> 8) & 255] << 8 ^ S[tmp & 255];
                // shift rows and add rcon
                if (i % key.length === 0) {
                    tmp = tmp << 8 ^ tmp >>> 24 ^ (rcon << 24);
                    rcon = rcon << 1 ^ (rcon >> 7) * 283;
                }
            }
            this.encKey[i] = this.encKey[i - key.length] ^ tmp;
        }
        // schedule decryption keys
        for (var j = 0; i; j++, i--) {
            tmp = this.encKey[j & 3 ? i : i - 4];
            if (i <= 4 || j < 4) {
                this.decKey[j] = tmp;
            }
            else {
                this.decKey[j] = (T5[S[tmp >>> 24]]
                    ^ T6[S[(tmp >> 16) & 255]]
                    ^ T7[S[(tmp >> 8) & 255]]
                    ^ T8[S[tmp & 255]]);
            }
        }
    }
    AES.prototype.encrypt = function (_message) {
        var message = getWords(_message);
        var out = new Uint32Array(4);
        var a = message[0] ^ this.encKey[0];
        var b = message[1] ^ this.encKey[1];
        var c = message[2] ^ this.encKey[2];
        var d = message[3] ^ this.encKey[3];
        var rounds = this.encKey.length / 4 - 2;
        var k = 4;
        var a2;
        var b2;
        var c2;
        // Inner rounds.  Cribbed from OpenSSL.
        for (var i = 0; i < rounds; i++) {
            a2 = T1[a >>> 24] ^ T2[(b >> 16) & 255] ^ T3[(c >> 8) & 255] ^ T4[d & 255] ^ this.encKey[k];
            b2 = T1[b >>> 24] ^ T2[(c >> 16) & 255] ^ T3[(d >> 8) & 255] ^ T4[a & 255] ^ this.encKey[k + 1];
            c2 = T1[c >>> 24] ^ T2[(d >> 16) & 255] ^ T3[(a >> 8) & 255] ^ T4[b & 255] ^ this.encKey[k + 2];
            d = T1[d >>> 24] ^ T2[(a >> 16) & 255] ^ T3[(b >> 8) & 255] ^ T4[c & 255] ^ this.encKey[k + 3];
            a = a2;
            b = b2;
            c = c2;
            k += 4;
            // console.log(a, b, c, d);
        }
        // Last round.
        for (var i = 0; i < 4; i++) {
            out[i] = (S[a >>> 24] << 24
                ^ S[(b >> 16) & 255] << 16
                ^ S[(c >> 8) & 255] << 8
                ^ S[d & 255]
                ^ this.encKey[k++]);
            a2 = a;
            a = b;
            b = c;
            c = d;
            d = a2;
        }
        return out;
    };
    AES.prototype.decrypt = function (_message) {
        var message = getWords(_message);
        var out = new Uint32Array(4);
        var a = message[0] ^ this.decKey[0];
        var b = message[3] ^ this.decKey[1];
        var c = message[2] ^ this.decKey[2];
        var d = message[1] ^ this.decKey[3];
        var rounds = this.decKey.length / 4 - 2;
        var a2;
        var b2;
        var c2;
        var k = 4;
        // Inner rounds.  Cribbed from OpenSSL.
        for (var i = 0; i < rounds; i++) {
            a2 = T5[a >>> 24] ^ T6[(b >> 16) & 255] ^ T7[(c >> 8) & 255] ^ T8[d & 255] ^ this.decKey[k];
            b2 = T5[b >>> 24] ^ T6[(c >> 16) & 255] ^ T7[(d >> 8) & 255] ^ T8[a & 255] ^ this.decKey[k + 1];
            c2 = T5[c >>> 24] ^ T6[(d >> 16) & 255] ^ T7[(a >> 8) & 255] ^ T8[b & 255] ^ this.decKey[k + 2];
            d = T5[d >>> 24] ^ T6[(a >> 16) & 255] ^ T7[(b >> 8) & 255] ^ T8[c & 255] ^ this.decKey[k + 3];
            a = a2;
            b = b2;
            c = c2;
            k += 4;
        }
        // Last round.
        for (var i = 0; i < 4; i++) {
            out[3 & -i] = (Si[a >>> 24] << 24
                ^ Si[(b >> 16) & 255] << 16
                ^ Si[(c >> 8) & 255] << 8
                ^ Si[d & 255]
                ^ this.decKey[k++]);
            a2 = a;
            a = b;
            b = c;
            c = d;
            d = a2;
        }
        return out;
    };
    return AES;
}());

/**
 * AES-IGE mode.
 */
var AES_IGE = /** @class */ (function () {
    function AES_IGE(key, iv, blockSize) {
        if (blockSize === void 0) { blockSize = 16; }
        this.key = getWords(key);
        this.iv = getWords(iv);
        this.cipher = new AES(key);
        this.blockSize = blockSize / 4;
    }
    /**
     * Encrypts plain text with AES-IGE mode.
     */
    AES_IGE.prototype.encrypt = function (message, buf) {
        var text = getWords(message);
        var cipherText = buf || new Uint32Array(text.length);
        var prevX = this.iv.subarray(this.blockSize, this.iv.length);
        var prevY = this.iv.subarray(0, this.blockSize);
        var yXOR = new Uint32Array(this.blockSize);
        for (var i = 0; i < text.length; i += this.blockSize) {
            var x = text.subarray(i, i + this.blockSize);
            xor(x, prevY, yXOR);
            var y = this.cipher.encrypt(yXOR);
            xor(y, prevX);
            prevX = x;
            prevY = y;
            for (var j = i, k = 0; j < text.length && k < 4; j++, k++)
                cipherText[j] = y[k];
        }
        return cipherText;
    };
    /**
     * Decrypts cipher text with AES-IGE mode.
     */
    AES_IGE.prototype.decrypt = function (message, buf) {
        var cipherText = getWords(message);
        var text = buf || new Uint32Array(cipherText.length);
        var prevY = this.iv.subarray(this.blockSize, this.iv.length);
        var prevX = this.iv.subarray(0, this.blockSize);
        var yXOR = new Uint32Array(this.blockSize);
        for (var i = 0; i < text.length; i += this.blockSize) {
            var x = cipherText.subarray(i, i + this.blockSize);
            xor(x, prevY, yXOR);
            var y = this.cipher.decrypt(yXOR);
            xor(y, prevX);
            prevX = x;
            prevY = y;
            for (var j = i, k = 0; j < text.length && k < 4; j++, k++)
                text[j] = y[k];
        }
        return text;
    };
    return AES_IGE;
}());

/**
 * AES-IGE mode.
 */
var AES_IGE$1 = /** @class */ (function () {
    function AES_IGE(key, counter, blockSize) {
        if (blockSize === void 0) { blockSize = 16; }
        this.offset = 0;
        this.key = getWords(key);
        this.counter = getWords(counter);
        this.cipher = new AES(key);
        this.blockSize = blockSize / 4;
        if (this.counter.length !== 4) {
            throw new Error('AES-CTR mode counter must be 16 bytes length');
        }
    }
    /**
     * Encrypts plain text with AES-IGE mode.
     */
    AES_IGE.prototype.encrypt = function (message, buf) {
        var text = getWords(message);
        var cipherText = buf || new Uint32Array(text.length);
        var offset = this.offset;
        for (var i = 0; i < text.length; i += this.blockSize) {
            var x = this.cipher.encrypt(this.counter);
            for (var j = i, k = offset; j < text.length && k < this.blockSize; j++, k++)
                cipherText[j] = x[k] ^ text[j];
            if (text.length - i >= this.blockSize)
                this.incrementCounter();
            if (offset) {
                i -= offset;
                offset = 0;
            }
        }
        this.offset = (this.offset + (text.length % 4)) % 4;
        return cipherText;
    };
    /**
     * Decrypts cipher text with AES-IGE mode.
     */
    AES_IGE.prototype.decrypt = function (message, buf) {
        return this.encrypt(message, buf);
    };
    AES_IGE.prototype.incrementCounter = function () {
        // increment counter
        for (var carry = this.counter.length - 1; carry >= 0; carry--) {
            if (++this.counter[carry] < 0xFFFFFFFF)
                break; // If overflowing, it'll be 0 and we'll have to continue propagating the carry
        }
    };
    return AES_IGE;
}());

/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (AES);



/***/ }),

/***/ "./node_modules/async-mutex/index.mjs":
/*!********************************************!*\
  !*** ./node_modules/async-mutex/index.mjs ***!
  \********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   E_ALREADY_LOCKED: () => (/* binding */ E_ALREADY_LOCKED),
/* harmony export */   E_CANCELED: () => (/* binding */ E_CANCELED),
/* harmony export */   E_TIMEOUT: () => (/* binding */ E_TIMEOUT),
/* harmony export */   Mutex: () => (/* binding */ Mutex),
/* harmony export */   Semaphore: () => (/* binding */ Semaphore),
/* harmony export */   tryAcquire: () => (/* binding */ tryAcquire),
/* harmony export */   withTimeout: () => (/* binding */ withTimeout)
/* harmony export */ });
const E_TIMEOUT = new Error('timeout while waiting for mutex to become available');
const E_ALREADY_LOCKED = new Error('mutex already locked');
const E_CANCELED = new Error('request for lock canceled');

var __awaiter$2 = ( false) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
class Semaphore {
    constructor(_value, _cancelError = E_CANCELED) {
        this._value = _value;
        this._cancelError = _cancelError;
        this._queue = [];
        this._weightedWaiters = [];
    }
    acquire(weight = 1, priority = 0) {
        if (weight <= 0)
            throw new Error(`invalid weight ${weight}: must be positive`);
        return new Promise((resolve, reject) => {
            const task = { resolve, reject, weight, priority };
            const i = findIndexFromEnd(this._queue, (other) => priority <= other.priority);
            if (i === -1 && weight <= this._value) {
                // Needs immediate dispatch, skip the queue
                this._dispatchItem(task);
            }
            else {
                this._queue.splice(i + 1, 0, task);
            }
        });
    }
    runExclusive(callback_1) {
        return __awaiter$2(this, arguments, void 0, function* (callback, weight = 1, priority = 0) {
            const [value, release] = yield this.acquire(weight, priority);
            try {
                return yield callback(value);
            }
            finally {
                release();
            }
        });
    }
    waitForUnlock(weight = 1, priority = 0) {
        if (weight <= 0)
            throw new Error(`invalid weight ${weight}: must be positive`);
        if (this._couldLockImmediately(weight, priority)) {
            return Promise.resolve();
        }
        else {
            return new Promise((resolve) => {
                if (!this._weightedWaiters[weight - 1])
                    this._weightedWaiters[weight - 1] = [];
                insertSorted(this._weightedWaiters[weight - 1], { resolve, priority });
            });
        }
    }
    isLocked() {
        return this._value <= 0;
    }
    getValue() {
        return this._value;
    }
    setValue(value) {
        this._value = value;
        this._dispatchQueue();
    }
    release(weight = 1) {
        if (weight <= 0)
            throw new Error(`invalid weight ${weight}: must be positive`);
        this._value += weight;
        this._dispatchQueue();
    }
    cancel() {
        this._queue.forEach((entry) => entry.reject(this._cancelError));
        this._queue = [];
    }
    _dispatchQueue() {
        this._drainUnlockWaiters();
        while (this._queue.length > 0 && this._queue[0].weight <= this._value) {
            this._dispatchItem(this._queue.shift());
            this._drainUnlockWaiters();
        }
    }
    _dispatchItem(item) {
        const previousValue = this._value;
        this._value -= item.weight;
        item.resolve([previousValue, this._newReleaser(item.weight)]);
    }
    _newReleaser(weight) {
        let called = false;
        return () => {
            if (called)
                return;
            called = true;
            this.release(weight);
        };
    }
    _drainUnlockWaiters() {
        if (this._queue.length === 0) {
            for (let weight = this._value; weight > 0; weight--) {
                const waiters = this._weightedWaiters[weight - 1];
                if (!waiters)
                    continue;
                waiters.forEach((waiter) => waiter.resolve());
                this._weightedWaiters[weight - 1] = [];
            }
        }
        else {
            const queuedPriority = this._queue[0].priority;
            for (let weight = this._value; weight > 0; weight--) {
                const waiters = this._weightedWaiters[weight - 1];
                if (!waiters)
                    continue;
                const i = waiters.findIndex((waiter) => waiter.priority <= queuedPriority);
                (i === -1 ? waiters : waiters.splice(0, i))
                    .forEach((waiter => waiter.resolve()));
            }
        }
    }
    _couldLockImmediately(weight, priority) {
        return (this._queue.length === 0 || this._queue[0].priority < priority) &&
            weight <= this._value;
    }
}
function insertSorted(a, v) {
    const i = findIndexFromEnd(a, (other) => v.priority <= other.priority);
    a.splice(i + 1, 0, v);
}
function findIndexFromEnd(a, predicate) {
    for (let i = a.length - 1; i >= 0; i--) {
        if (predicate(a[i])) {
            return i;
        }
    }
    return -1;
}

var __awaiter$1 = ( false) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
class Mutex {
    constructor(cancelError) {
        this._semaphore = new Semaphore(1, cancelError);
    }
    acquire() {
        return __awaiter$1(this, arguments, void 0, function* (priority = 0) {
            const [, releaser] = yield this._semaphore.acquire(1, priority);
            return releaser;
        });
    }
    runExclusive(callback, priority = 0) {
        return this._semaphore.runExclusive(() => callback(), 1, priority);
    }
    isLocked() {
        return this._semaphore.isLocked();
    }
    waitForUnlock(priority = 0) {
        return this._semaphore.waitForUnlock(1, priority);
    }
    release() {
        if (this._semaphore.isLocked())
            this._semaphore.release();
    }
    cancel() {
        return this._semaphore.cancel();
    }
}

var __awaiter = ( false) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
function withTimeout(sync, timeout, timeoutError = E_TIMEOUT) {
    return {
        acquire: (weightOrPriority, priority) => {
            let weight;
            if (isSemaphore(sync)) {
                weight = weightOrPriority;
            }
            else {
                weight = undefined;
                priority = weightOrPriority;
            }
            if (weight !== undefined && weight <= 0) {
                throw new Error(`invalid weight ${weight}: must be positive`);
            }
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                let isTimeout = false;
                const handle = setTimeout(() => {
                    isTimeout = true;
                    reject(timeoutError);
                }, timeout);
                try {
                    const ticket = yield (isSemaphore(sync)
                        ? sync.acquire(weight, priority)
                        : sync.acquire(priority));
                    if (isTimeout) {
                        const release = Array.isArray(ticket) ? ticket[1] : ticket;
                        release();
                    }
                    else {
                        clearTimeout(handle);
                        resolve(ticket);
                    }
                }
                catch (e) {
                    if (!isTimeout) {
                        clearTimeout(handle);
                        reject(e);
                    }
                }
            }));
        },
        runExclusive(callback, weight, priority) {
            return __awaiter(this, void 0, void 0, function* () {
                let release = () => undefined;
                try {
                    const ticket = yield this.acquire(weight, priority);
                    if (Array.isArray(ticket)) {
                        release = ticket[1];
                        return yield callback(ticket[0]);
                    }
                    else {
                        release = ticket;
                        return yield callback();
                    }
                }
                finally {
                    release();
                }
            });
        },
        release(weight) {
            sync.release(weight);
        },
        cancel() {
            return sync.cancel();
        },
        waitForUnlock: (weightOrPriority, priority) => {
            let weight;
            if (isSemaphore(sync)) {
                weight = weightOrPriority;
            }
            else {
                weight = undefined;
                priority = weightOrPriority;
            }
            if (weight !== undefined && weight <= 0) {
                throw new Error(`invalid weight ${weight}: must be positive`);
            }
            return new Promise((resolve, reject) => {
                const handle = setTimeout(() => reject(timeoutError), timeout);
                (isSemaphore(sync)
                    ? sync.waitForUnlock(weight, priority)
                    : sync.waitForUnlock(priority)).then(() => {
                    clearTimeout(handle);
                    resolve();
                });
            });
        },
        isLocked: () => sync.isLocked(),
        getValue: () => sync.getValue(),
        setValue: (value) => sync.setValue(value),
    };
}
function isSemaphore(sync) {
    return sync.getValue !== undefined;
}

// eslint-disable-next-lisne @typescript-eslint/explicit-module-boundary-types
function tryAcquire(sync, alreadyAcquiredError = E_ALREADY_LOCKED) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return withTimeout(sync, 0, alreadyAcquiredError);
}




/***/ }),

/***/ "./node_modules/base64-js/index.js":
/*!*****************************************!*\
  !*** ./node_modules/base64-js/index.js ***!
  \*****************************************/
/***/ ((__unused_webpack_module, exports) => {

"use strict";


exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  var i
  for (i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}


/***/ }),

/***/ "./node_modules/big-integer/BigInteger.js":
/*!************************************************!*\
  !*** ./node_modules/big-integer/BigInteger.js ***!
  \************************************************/
/***/ ((module, exports, __webpack_require__) => {

/* module decorator */ module = __webpack_require__.nmd(module);
var __WEBPACK_AMD_DEFINE_RESULT__;var bigInt = (function (undefined) {
    "use strict";

    var BASE = 1e7,
        LOG_BASE = 7,
        MAX_INT = 9007199254740992,
        MAX_INT_ARR = smallToArray(MAX_INT),
        DEFAULT_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";

    var supportsNativeBigInt = typeof BigInt === "function";

    function Integer(v, radix, alphabet, caseSensitive) {
        if (typeof v === "undefined") return Integer[0];
        if (typeof radix !== "undefined") return +radix === 10 && !alphabet ? parseValue(v) : parseBase(v, radix, alphabet, caseSensitive);
        return parseValue(v);
    }

    function BigInteger(value, sign) {
        this.value = value;
        this.sign = sign;
        this.isSmall = false;
    }
    BigInteger.prototype = Object.create(Integer.prototype);

    function SmallInteger(value) {
        this.value = value;
        this.sign = value < 0;
        this.isSmall = true;
    }
    SmallInteger.prototype = Object.create(Integer.prototype);

    function NativeBigInt(value) {
        this.value = value;
    }
    NativeBigInt.prototype = Object.create(Integer.prototype);

    function isPrecise(n) {
        return -MAX_INT < n && n < MAX_INT;
    }

    function smallToArray(n) { // For performance reasons doesn't reference BASE, need to change this function if BASE changes
        if (n < 1e7)
            return [n];
        if (n < 1e14)
            return [n % 1e7, Math.floor(n / 1e7)];
        return [n % 1e7, Math.floor(n / 1e7) % 1e7, Math.floor(n / 1e14)];
    }

    function arrayToSmall(arr) { // If BASE changes this function may need to change
        trim(arr);
        var length = arr.length;
        if (length < 4 && compareAbs(arr, MAX_INT_ARR) < 0) {
            switch (length) {
                case 0: return 0;
                case 1: return arr[0];
                case 2: return arr[0] + arr[1] * BASE;
                default: return arr[0] + (arr[1] + arr[2] * BASE) * BASE;
            }
        }
        return arr;
    }

    function trim(v) {
        var i = v.length;
        while (v[--i] === 0);
        v.length = i + 1;
    }

    function createArray(length) { // function shamelessly stolen from Yaffle's library https://github.com/Yaffle/BigInteger
        var x = new Array(length);
        var i = -1;
        while (++i < length) {
            x[i] = 0;
        }
        return x;
    }

    function truncate(n) {
        if (n > 0) return Math.floor(n);
        return Math.ceil(n);
    }

    function add(a, b) { // assumes a and b are arrays with a.length >= b.length
        var l_a = a.length,
            l_b = b.length,
            r = new Array(l_a),
            carry = 0,
            base = BASE,
            sum, i;
        for (i = 0; i < l_b; i++) {
            sum = a[i] + b[i] + carry;
            carry = sum >= base ? 1 : 0;
            r[i] = sum - carry * base;
        }
        while (i < l_a) {
            sum = a[i] + carry;
            carry = sum === base ? 1 : 0;
            r[i++] = sum - carry * base;
        }
        if (carry > 0) r.push(carry);
        return r;
    }

    function addAny(a, b) {
        if (a.length >= b.length) return add(a, b);
        return add(b, a);
    }

    function addSmall(a, carry) { // assumes a is array, carry is number with 0 <= carry < MAX_INT
        var l = a.length,
            r = new Array(l),
            base = BASE,
            sum, i;
        for (i = 0; i < l; i++) {
            sum = a[i] - base + carry;
            carry = Math.floor(sum / base);
            r[i] = sum - carry * base;
            carry += 1;
        }
        while (carry > 0) {
            r[i++] = carry % base;
            carry = Math.floor(carry / base);
        }
        return r;
    }

    BigInteger.prototype.add = function (v) {
        var n = parseValue(v);
        if (this.sign !== n.sign) {
            return this.subtract(n.negate());
        }
        var a = this.value, b = n.value;
        if (n.isSmall) {
            return new BigInteger(addSmall(a, Math.abs(b)), this.sign);
        }
        return new BigInteger(addAny(a, b), this.sign);
    };
    BigInteger.prototype.plus = BigInteger.prototype.add;

    SmallInteger.prototype.add = function (v) {
        var n = parseValue(v);
        var a = this.value;
        if (a < 0 !== n.sign) {
            return this.subtract(n.negate());
        }
        var b = n.value;
        if (n.isSmall) {
            if (isPrecise(a + b)) return new SmallInteger(a + b);
            b = smallToArray(Math.abs(b));
        }
        return new BigInteger(addSmall(b, Math.abs(a)), a < 0);
    };
    SmallInteger.prototype.plus = SmallInteger.prototype.add;

    NativeBigInt.prototype.add = function (v) {
        return new NativeBigInt(this.value + parseValue(v).value);
    }
    NativeBigInt.prototype.plus = NativeBigInt.prototype.add;

    function subtract(a, b) { // assumes a and b are arrays with a >= b
        var a_l = a.length,
            b_l = b.length,
            r = new Array(a_l),
            borrow = 0,
            base = BASE,
            i, difference;
        for (i = 0; i < b_l; i++) {
            difference = a[i] - borrow - b[i];
            if (difference < 0) {
                difference += base;
                borrow = 1;
            } else borrow = 0;
            r[i] = difference;
        }
        for (i = b_l; i < a_l; i++) {
            difference = a[i] - borrow;
            if (difference < 0) difference += base;
            else {
                r[i++] = difference;
                break;
            }
            r[i] = difference;
        }
        for (; i < a_l; i++) {
            r[i] = a[i];
        }
        trim(r);
        return r;
    }

    function subtractAny(a, b, sign) {
        var value;
        if (compareAbs(a, b) >= 0) {
            value = subtract(a, b);
        } else {
            value = subtract(b, a);
            sign = !sign;
        }
        value = arrayToSmall(value);
        if (typeof value === "number") {
            if (sign) value = -value;
            return new SmallInteger(value);
        }
        return new BigInteger(value, sign);
    }

    function subtractSmall(a, b, sign) { // assumes a is array, b is number with 0 <= b < MAX_INT
        var l = a.length,
            r = new Array(l),
            carry = -b,
            base = BASE,
            i, difference;
        for (i = 0; i < l; i++) {
            difference = a[i] + carry;
            carry = Math.floor(difference / base);
            difference %= base;
            r[i] = difference < 0 ? difference + base : difference;
        }
        r = arrayToSmall(r);
        if (typeof r === "number") {
            if (sign) r = -r;
            return new SmallInteger(r);
        } return new BigInteger(r, sign);
    }

    BigInteger.prototype.subtract = function (v) {
        var n = parseValue(v);
        if (this.sign !== n.sign) {
            return this.add(n.negate());
        }
        var a = this.value, b = n.value;
        if (n.isSmall)
            return subtractSmall(a, Math.abs(b), this.sign);
        return subtractAny(a, b, this.sign);
    };
    BigInteger.prototype.minus = BigInteger.prototype.subtract;

    SmallInteger.prototype.subtract = function (v) {
        var n = parseValue(v);
        var a = this.value;
        if (a < 0 !== n.sign) {
            return this.add(n.negate());
        }
        var b = n.value;
        if (n.isSmall) {
            return new SmallInteger(a - b);
        }
        return subtractSmall(b, Math.abs(a), a >= 0);
    };
    SmallInteger.prototype.minus = SmallInteger.prototype.subtract;

    NativeBigInt.prototype.subtract = function (v) {
        return new NativeBigInt(this.value - parseValue(v).value);
    }
    NativeBigInt.prototype.minus = NativeBigInt.prototype.subtract;

    BigInteger.prototype.negate = function () {
        return new BigInteger(this.value, !this.sign);
    };
    SmallInteger.prototype.negate = function () {
        var sign = this.sign;
        var small = new SmallInteger(-this.value);
        small.sign = !sign;
        return small;
    };
    NativeBigInt.prototype.negate = function () {
        return new NativeBigInt(-this.value);
    }

    BigInteger.prototype.abs = function () {
        return new BigInteger(this.value, false);
    };
    SmallInteger.prototype.abs = function () {
        return new SmallInteger(Math.abs(this.value));
    };
    NativeBigInt.prototype.abs = function () {
        return new NativeBigInt(this.value >= 0 ? this.value : -this.value);
    }


    function multiplyLong(a, b) {
        var a_l = a.length,
            b_l = b.length,
            l = a_l + b_l,
            r = createArray(l),
            base = BASE,
            product, carry, i, a_i, b_j;
        for (i = 0; i < a_l; ++i) {
            a_i = a[i];
            for (var j = 0; j < b_l; ++j) {
                b_j = b[j];
                product = a_i * b_j + r[i + j];
                carry = Math.floor(product / base);
                r[i + j] = product - carry * base;
                r[i + j + 1] += carry;
            }
        }
        trim(r);
        return r;
    }

    function multiplySmall(a, b) { // assumes a is array, b is number with |b| < BASE
        var l = a.length,
            r = new Array(l),
            base = BASE,
            carry = 0,
            product, i;
        for (i = 0; i < l; i++) {
            product = a[i] * b + carry;
            carry = Math.floor(product / base);
            r[i] = product - carry * base;
        }
        while (carry > 0) {
            r[i++] = carry % base;
            carry = Math.floor(carry / base);
        }
        return r;
    }

    function shiftLeft(x, n) {
        var r = [];
        while (n-- > 0) r.push(0);
        return r.concat(x);
    }

    function multiplyKaratsuba(x, y) {
        var n = Math.max(x.length, y.length);

        if (n <= 30) return multiplyLong(x, y);
        n = Math.ceil(n / 2);

        var b = x.slice(n),
            a = x.slice(0, n),
            d = y.slice(n),
            c = y.slice(0, n);

        var ac = multiplyKaratsuba(a, c),
            bd = multiplyKaratsuba(b, d),
            abcd = multiplyKaratsuba(addAny(a, b), addAny(c, d));

        var product = addAny(addAny(ac, shiftLeft(subtract(subtract(abcd, ac), bd), n)), shiftLeft(bd, 2 * n));
        trim(product);
        return product;
    }

    // The following function is derived from a surface fit of a graph plotting the performance difference
    // between long multiplication and karatsuba multiplication versus the lengths of the two arrays.
    function useKaratsuba(l1, l2) {
        return -0.012 * l1 - 0.012 * l2 + 0.000015 * l1 * l2 > 0;
    }

    BigInteger.prototype.multiply = function (v) {
        var n = parseValue(v),
            a = this.value, b = n.value,
            sign = this.sign !== n.sign,
            abs;
        if (n.isSmall) {
            if (b === 0) return Integer[0];
            if (b === 1) return this;
            if (b === -1) return this.negate();
            abs = Math.abs(b);
            if (abs < BASE) {
                return new BigInteger(multiplySmall(a, abs), sign);
            }
            b = smallToArray(abs);
        }
        if (useKaratsuba(a.length, b.length)) // Karatsuba is only faster for certain array sizes
            return new BigInteger(multiplyKaratsuba(a, b), sign);
        return new BigInteger(multiplyLong(a, b), sign);
    };

    BigInteger.prototype.times = BigInteger.prototype.multiply;

    function multiplySmallAndArray(a, b, sign) { // a >= 0
        if (a < BASE) {
            return new BigInteger(multiplySmall(b, a), sign);
        }
        return new BigInteger(multiplyLong(b, smallToArray(a)), sign);
    }
    SmallInteger.prototype._multiplyBySmall = function (a) {
        if (isPrecise(a.value * this.value)) {
            return new SmallInteger(a.value * this.value);
        }
        return multiplySmallAndArray(Math.abs(a.value), smallToArray(Math.abs(this.value)), this.sign !== a.sign);
    };
    BigInteger.prototype._multiplyBySmall = function (a) {
        if (a.value === 0) return Integer[0];
        if (a.value === 1) return this;
        if (a.value === -1) return this.negate();
        return multiplySmallAndArray(Math.abs(a.value), this.value, this.sign !== a.sign);
    };
    SmallInteger.prototype.multiply = function (v) {
        return parseValue(v)._multiplyBySmall(this);
    };
    SmallInteger.prototype.times = SmallInteger.prototype.multiply;

    NativeBigInt.prototype.multiply = function (v) {
        return new NativeBigInt(this.value * parseValue(v).value);
    }
    NativeBigInt.prototype.times = NativeBigInt.prototype.multiply;

    function square(a) {
        //console.assert(2 * BASE * BASE < MAX_INT);
        var l = a.length,
            r = createArray(l + l),
            base = BASE,
            product, carry, i, a_i, a_j;
        for (i = 0; i < l; i++) {
            a_i = a[i];
            carry = 0 - a_i * a_i;
            for (var j = i; j < l; j++) {
                a_j = a[j];
                product = 2 * (a_i * a_j) + r[i + j] + carry;
                carry = Math.floor(product / base);
                r[i + j] = product - carry * base;
            }
            r[i + l] = carry;
        }
        trim(r);
        return r;
    }

    BigInteger.prototype.square = function () {
        return new BigInteger(square(this.value), false);
    };

    SmallInteger.prototype.square = function () {
        var value = this.value * this.value;
        if (isPrecise(value)) return new SmallInteger(value);
        return new BigInteger(square(smallToArray(Math.abs(this.value))), false);
    };

    NativeBigInt.prototype.square = function (v) {
        return new NativeBigInt(this.value * this.value);
    }

    function divMod1(a, b) { // Left over from previous version. Performs faster than divMod2 on smaller input sizes.
        var a_l = a.length,
            b_l = b.length,
            base = BASE,
            result = createArray(b.length),
            divisorMostSignificantDigit = b[b_l - 1],
            // normalization
            lambda = Math.ceil(base / (2 * divisorMostSignificantDigit)),
            remainder = multiplySmall(a, lambda),
            divisor = multiplySmall(b, lambda),
            quotientDigit, shift, carry, borrow, i, l, q;
        if (remainder.length <= a_l) remainder.push(0);
        divisor.push(0);
        divisorMostSignificantDigit = divisor[b_l - 1];
        for (shift = a_l - b_l; shift >= 0; shift--) {
            quotientDigit = base - 1;
            if (remainder[shift + b_l] !== divisorMostSignificantDigit) {
                quotientDigit = Math.floor((remainder[shift + b_l] * base + remainder[shift + b_l - 1]) / divisorMostSignificantDigit);
            }
            // quotientDigit <= base - 1
            carry = 0;
            borrow = 0;
            l = divisor.length;
            for (i = 0; i < l; i++) {
                carry += quotientDigit * divisor[i];
                q = Math.floor(carry / base);
                borrow += remainder[shift + i] - (carry - q * base);
                carry = q;
                if (borrow < 0) {
                    remainder[shift + i] = borrow + base;
                    borrow = -1;
                } else {
                    remainder[shift + i] = borrow;
                    borrow = 0;
                }
            }
            while (borrow !== 0) {
                quotientDigit -= 1;
                carry = 0;
                for (i = 0; i < l; i++) {
                    carry += remainder[shift + i] - base + divisor[i];
                    if (carry < 0) {
                        remainder[shift + i] = carry + base;
                        carry = 0;
                    } else {
                        remainder[shift + i] = carry;
                        carry = 1;
                    }
                }
                borrow += carry;
            }
            result[shift] = quotientDigit;
        }
        // denormalization
        remainder = divModSmall(remainder, lambda)[0];
        return [arrayToSmall(result), arrayToSmall(remainder)];
    }

    function divMod2(a, b) { // Implementation idea shamelessly stolen from Silent Matt's library http://silentmatt.com/biginteger/
        // Performs faster than divMod1 on larger input sizes.
        var a_l = a.length,
            b_l = b.length,
            result = [],
            part = [],
            base = BASE,
            guess, xlen, highx, highy, check;
        while (a_l) {
            part.unshift(a[--a_l]);
            trim(part);
            if (compareAbs(part, b) < 0) {
                result.push(0);
                continue;
            }
            xlen = part.length;
            highx = part[xlen - 1] * base + part[xlen - 2];
            highy = b[b_l - 1] * base + b[b_l - 2];
            if (xlen > b_l) {
                highx = (highx + 1) * base;
            }
            guess = Math.ceil(highx / highy);
            do {
                check = multiplySmall(b, guess);
                if (compareAbs(check, part) <= 0) break;
                guess--;
            } while (guess);
            result.push(guess);
            part = subtract(part, check);
        }
        result.reverse();
        return [arrayToSmall(result), arrayToSmall(part)];
    }

    function divModSmall(value, lambda) {
        var length = value.length,
            quotient = createArray(length),
            base = BASE,
            i, q, remainder, divisor;
        remainder = 0;
        for (i = length - 1; i >= 0; --i) {
            divisor = remainder * base + value[i];
            q = truncate(divisor / lambda);
            remainder = divisor - q * lambda;
            quotient[i] = q | 0;
        }
        return [quotient, remainder | 0];
    }

    function divModAny(self, v) {
        var value, n = parseValue(v);
        if (supportsNativeBigInt) {
            return [new NativeBigInt(self.value / n.value), new NativeBigInt(self.value % n.value)];
        }
        var a = self.value, b = n.value;
        var quotient;
        if (b === 0) throw new Error("Cannot divide by zero");
        if (self.isSmall) {
            if (n.isSmall) {
                return [new SmallInteger(truncate(a / b)), new SmallInteger(a % b)];
            }
            return [Integer[0], self];
        }
        if (n.isSmall) {
            if (b === 1) return [self, Integer[0]];
            if (b == -1) return [self.negate(), Integer[0]];
            var abs = Math.abs(b);
            if (abs < BASE) {
                value = divModSmall(a, abs);
                quotient = arrayToSmall(value[0]);
                var remainder = value[1];
                if (self.sign) remainder = -remainder;
                if (typeof quotient === "number") {
                    if (self.sign !== n.sign) quotient = -quotient;
                    return [new SmallInteger(quotient), new SmallInteger(remainder)];
                }
                return [new BigInteger(quotient, self.sign !== n.sign), new SmallInteger(remainder)];
            }
            b = smallToArray(abs);
        }
        var comparison = compareAbs(a, b);
        if (comparison === -1) return [Integer[0], self];
        if (comparison === 0) return [Integer[self.sign === n.sign ? 1 : -1], Integer[0]];

        // divMod1 is faster on smaller input sizes
        if (a.length + b.length <= 200)
            value = divMod1(a, b);
        else value = divMod2(a, b);

        quotient = value[0];
        var qSign = self.sign !== n.sign,
            mod = value[1],
            mSign = self.sign;
        if (typeof quotient === "number") {
            if (qSign) quotient = -quotient;
            quotient = new SmallInteger(quotient);
        } else quotient = new BigInteger(quotient, qSign);
        if (typeof mod === "number") {
            if (mSign) mod = -mod;
            mod = new SmallInteger(mod);
        } else mod = new BigInteger(mod, mSign);
        return [quotient, mod];
    }

    BigInteger.prototype.divmod = function (v) {
        var result = divModAny(this, v);
        return {
            quotient: result[0],
            remainder: result[1]
        };
    };
    NativeBigInt.prototype.divmod = SmallInteger.prototype.divmod = BigInteger.prototype.divmod;


    BigInteger.prototype.divide = function (v) {
        return divModAny(this, v)[0];
    };
    NativeBigInt.prototype.over = NativeBigInt.prototype.divide = function (v) {
        return new NativeBigInt(this.value / parseValue(v).value);
    };
    SmallInteger.prototype.over = SmallInteger.prototype.divide = BigInteger.prototype.over = BigInteger.prototype.divide;

    BigInteger.prototype.mod = function (v) {
        return divModAny(this, v)[1];
    };
    NativeBigInt.prototype.mod = NativeBigInt.prototype.remainder = function (v) {
        return new NativeBigInt(this.value % parseValue(v).value);
    };
    SmallInteger.prototype.remainder = SmallInteger.prototype.mod = BigInteger.prototype.remainder = BigInteger.prototype.mod;

    BigInteger.prototype.pow = function (v) {
        var n = parseValue(v),
            a = this.value,
            b = n.value,
            value, x, y;
        if (b === 0) return Integer[1];
        if (a === 0) return Integer[0];
        if (a === 1) return Integer[1];
        if (a === -1) return n.isEven() ? Integer[1] : Integer[-1];
        if (n.sign) {
            return Integer[0];
        }
        if (!n.isSmall) throw new Error("The exponent " + n.toString() + " is too large.");
        if (this.isSmall) {
            if (isPrecise(value = Math.pow(a, b)))
                return new SmallInteger(truncate(value));
        }
        x = this;
        y = Integer[1];
        while (true) {
            if (b & 1 === 1) {
                y = y.times(x);
                --b;
            }
            if (b === 0) break;
            b /= 2;
            x = x.square();
        }
        return y;
    };
    SmallInteger.prototype.pow = BigInteger.prototype.pow;

    NativeBigInt.prototype.pow = function (v) {
        var n = parseValue(v);
        var a = this.value, b = n.value;
        var _0 = BigInt(0), _1 = BigInt(1), _2 = BigInt(2);
        if (b === _0) return Integer[1];
        if (a === _0) return Integer[0];
        if (a === _1) return Integer[1];
        if (a === BigInt(-1)) return n.isEven() ? Integer[1] : Integer[-1];
        if (n.isNegative()) return new NativeBigInt(_0);
        var x = this;
        var y = Integer[1];
        while (true) {
            if ((b & _1) === _1) {
                y = y.times(x);
                --b;
            }
            if (b === _0) break;
            b /= _2;
            x = x.square();
        }
        return y;
    }

    BigInteger.prototype.modPow = function (exp, mod) {
        exp = parseValue(exp);
        mod = parseValue(mod);
        if (mod.isZero()) throw new Error("Cannot take modPow with modulus 0");
        var r = Integer[1],
            base = this.mod(mod);
        if (exp.isNegative()) {
            exp = exp.multiply(Integer[-1]);
            base = base.modInv(mod);
        }
        while (exp.isPositive()) {
            if (base.isZero()) return Integer[0];
            if (exp.isOdd()) r = r.multiply(base).mod(mod);
            exp = exp.divide(2);
            base = base.square().mod(mod);
        }
        return r;
    };
    NativeBigInt.prototype.modPow = SmallInteger.prototype.modPow = BigInteger.prototype.modPow;

    function compareAbs(a, b) {
        if (a.length !== b.length) {
            return a.length > b.length ? 1 : -1;
        }
        for (var i = a.length - 1; i >= 0; i--) {
            if (a[i] !== b[i]) return a[i] > b[i] ? 1 : -1;
        }
        return 0;
    }

    BigInteger.prototype.compareAbs = function (v) {
        var n = parseValue(v),
            a = this.value,
            b = n.value;
        if (n.isSmall) return 1;
        return compareAbs(a, b);
    };
    SmallInteger.prototype.compareAbs = function (v) {
        var n = parseValue(v),
            a = Math.abs(this.value),
            b = n.value;
        if (n.isSmall) {
            b = Math.abs(b);
            return a === b ? 0 : a > b ? 1 : -1;
        }
        return -1;
    };
    NativeBigInt.prototype.compareAbs = function (v) {
        var a = this.value;
        var b = parseValue(v).value;
        a = a >= 0 ? a : -a;
        b = b >= 0 ? b : -b;
        return a === b ? 0 : a > b ? 1 : -1;
    }

    BigInteger.prototype.compare = function (v) {
        // See discussion about comparison with Infinity:
        // https://github.com/peterolson/BigInteger.js/issues/61
        if (v === Infinity) {
            return -1;
        }
        if (v === -Infinity) {
            return 1;
        }

        var n = parseValue(v),
            a = this.value,
            b = n.value;
        if (this.sign !== n.sign) {
            return n.sign ? 1 : -1;
        }
        if (n.isSmall) {
            return this.sign ? -1 : 1;
        }
        return compareAbs(a, b) * (this.sign ? -1 : 1);
    };
    BigInteger.prototype.compareTo = BigInteger.prototype.compare;

    SmallInteger.prototype.compare = function (v) {
        if (v === Infinity) {
            return -1;
        }
        if (v === -Infinity) {
            return 1;
        }

        var n = parseValue(v),
            a = this.value,
            b = n.value;
        if (n.isSmall) {
            return a == b ? 0 : a > b ? 1 : -1;
        }
        if (a < 0 !== n.sign) {
            return a < 0 ? -1 : 1;
        }
        return a < 0 ? 1 : -1;
    };
    SmallInteger.prototype.compareTo = SmallInteger.prototype.compare;

    NativeBigInt.prototype.compare = function (v) {
        if (v === Infinity) {
            return -1;
        }
        if (v === -Infinity) {
            return 1;
        }
        var a = this.value;
        var b = parseValue(v).value;
        return a === b ? 0 : a > b ? 1 : -1;
    }
    NativeBigInt.prototype.compareTo = NativeBigInt.prototype.compare;

    BigInteger.prototype.equals = function (v) {
        return this.compare(v) === 0;
    };
    NativeBigInt.prototype.eq = NativeBigInt.prototype.equals = SmallInteger.prototype.eq = SmallInteger.prototype.equals = BigInteger.prototype.eq = BigInteger.prototype.equals;

    BigInteger.prototype.notEquals = function (v) {
        return this.compare(v) !== 0;
    };
    NativeBigInt.prototype.neq = NativeBigInt.prototype.notEquals = SmallInteger.prototype.neq = SmallInteger.prototype.notEquals = BigInteger.prototype.neq = BigInteger.prototype.notEquals;

    BigInteger.prototype.greater = function (v) {
        return this.compare(v) > 0;
    };
    NativeBigInt.prototype.gt = NativeBigInt.prototype.greater = SmallInteger.prototype.gt = SmallInteger.prototype.greater = BigInteger.prototype.gt = BigInteger.prototype.greater;

    BigInteger.prototype.lesser = function (v) {
        return this.compare(v) < 0;
    };
    NativeBigInt.prototype.lt = NativeBigInt.prototype.lesser = SmallInteger.prototype.lt = SmallInteger.prototype.lesser = BigInteger.prototype.lt = BigInteger.prototype.lesser;

    BigInteger.prototype.greaterOrEquals = function (v) {
        return this.compare(v) >= 0;
    };
    NativeBigInt.prototype.geq = NativeBigInt.prototype.greaterOrEquals = SmallInteger.prototype.geq = SmallInteger.prototype.greaterOrEquals = BigInteger.prototype.geq = BigInteger.prototype.greaterOrEquals;

    BigInteger.prototype.lesserOrEquals = function (v) {
        return this.compare(v) <= 0;
    };
    NativeBigInt.prototype.leq = NativeBigInt.prototype.lesserOrEquals = SmallInteger.prototype.leq = SmallInteger.prototype.lesserOrEquals = BigInteger.prototype.leq = BigInteger.prototype.lesserOrEquals;

    BigInteger.prototype.isEven = function () {
        return (this.value[0] & 1) === 0;
    };
    SmallInteger.prototype.isEven = function () {
        return (this.value & 1) === 0;
    };
    NativeBigInt.prototype.isEven = function () {
        return (this.value & BigInt(1)) === BigInt(0);
    }

    BigInteger.prototype.isOdd = function () {
        return (this.value[0] & 1) === 1;
    };
    SmallInteger.prototype.isOdd = function () {
        return (this.value & 1) === 1;
    };
    NativeBigInt.prototype.isOdd = function () {
        return (this.value & BigInt(1)) === BigInt(1);
    }

    BigInteger.prototype.isPositive = function () {
        return !this.sign;
    };
    SmallInteger.prototype.isPositive = function () {
        return this.value > 0;
    };
    NativeBigInt.prototype.isPositive = SmallInteger.prototype.isPositive;

    BigInteger.prototype.isNegative = function () {
        return this.sign;
    };
    SmallInteger.prototype.isNegative = function () {
        return this.value < 0;
    };
    NativeBigInt.prototype.isNegative = SmallInteger.prototype.isNegative;

    BigInteger.prototype.isUnit = function () {
        return false;
    };
    SmallInteger.prototype.isUnit = function () {
        return Math.abs(this.value) === 1;
    };
    NativeBigInt.prototype.isUnit = function () {
        return this.abs().value === BigInt(1);
    }

    BigInteger.prototype.isZero = function () {
        return false;
    };
    SmallInteger.prototype.isZero = function () {
        return this.value === 0;
    };
    NativeBigInt.prototype.isZero = function () {
        return this.value === BigInt(0);
    }

    BigInteger.prototype.isDivisibleBy = function (v) {
        var n = parseValue(v);
        if (n.isZero()) return false;
        if (n.isUnit()) return true;
        if (n.compareAbs(2) === 0) return this.isEven();
        return this.mod(n).isZero();
    };
    NativeBigInt.prototype.isDivisibleBy = SmallInteger.prototype.isDivisibleBy = BigInteger.prototype.isDivisibleBy;

    function isBasicPrime(v) {
        var n = v.abs();
        if (n.isUnit()) return false;
        if (n.equals(2) || n.equals(3) || n.equals(5)) return true;
        if (n.isEven() || n.isDivisibleBy(3) || n.isDivisibleBy(5)) return false;
        if (n.lesser(49)) return true;
        // we don't know if it's prime: let the other functions figure it out
    }

    function millerRabinTest(n, a) {
        var nPrev = n.prev(),
            b = nPrev,
            r = 0,
            d, t, i, x;
        while (b.isEven()) b = b.divide(2), r++;
        next: for (i = 0; i < a.length; i++) {
            if (n.lesser(a[i])) continue;
            x = bigInt(a[i]).modPow(b, n);
            if (x.isUnit() || x.equals(nPrev)) continue;
            for (d = r - 1; d != 0; d--) {
                x = x.square().mod(n);
                if (x.isUnit()) return false;
                if (x.equals(nPrev)) continue next;
            }
            return false;
        }
        return true;
    }

    // Set "strict" to true to force GRH-supported lower bound of 2*log(N)^2
    BigInteger.prototype.isPrime = function (strict) {
        var isPrime = isBasicPrime(this);
        if (isPrime !== undefined) return isPrime;
        var n = this.abs();
        var bits = n.bitLength();
        if (bits <= 64)
            return millerRabinTest(n, [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]);
        var logN = Math.log(2) * bits.toJSNumber();
        var t = Math.ceil((strict === true) ? (2 * Math.pow(logN, 2)) : logN);
        for (var a = [], i = 0; i < t; i++) {
            a.push(bigInt(i + 2));
        }
        return millerRabinTest(n, a);
    };
    NativeBigInt.prototype.isPrime = SmallInteger.prototype.isPrime = BigInteger.prototype.isPrime;

    BigInteger.prototype.isProbablePrime = function (iterations, rng) {
        var isPrime = isBasicPrime(this);
        if (isPrime !== undefined) return isPrime;
        var n = this.abs();
        var t = iterations === undefined ? 5 : iterations;
        for (var a = [], i = 0; i < t; i++) {
            a.push(bigInt.randBetween(2, n.minus(2), rng));
        }
        return millerRabinTest(n, a);
    };
    NativeBigInt.prototype.isProbablePrime = SmallInteger.prototype.isProbablePrime = BigInteger.prototype.isProbablePrime;

    BigInteger.prototype.modInv = function (n) {
        var t = bigInt.zero, newT = bigInt.one, r = parseValue(n), newR = this.abs(), q, lastT, lastR;
        while (!newR.isZero()) {
            q = r.divide(newR);
            lastT = t;
            lastR = r;
            t = newT;
            r = newR;
            newT = lastT.subtract(q.multiply(newT));
            newR = lastR.subtract(q.multiply(newR));
        }
        if (!r.isUnit()) throw new Error(this.toString() + " and " + n.toString() + " are not co-prime");
        if (t.compare(0) === -1) {
            t = t.add(n);
        }
        if (this.isNegative()) {
            return t.negate();
        }
        return t;
    };

    NativeBigInt.prototype.modInv = SmallInteger.prototype.modInv = BigInteger.prototype.modInv;

    BigInteger.prototype.next = function () {
        var value = this.value;
        if (this.sign) {
            return subtractSmall(value, 1, this.sign);
        }
        return new BigInteger(addSmall(value, 1), this.sign);
    };
    SmallInteger.prototype.next = function () {
        var value = this.value;
        if (value + 1 < MAX_INT) return new SmallInteger(value + 1);
        return new BigInteger(MAX_INT_ARR, false);
    };
    NativeBigInt.prototype.next = function () {
        return new NativeBigInt(this.value + BigInt(1));
    }

    BigInteger.prototype.prev = function () {
        var value = this.value;
        if (this.sign) {
            return new BigInteger(addSmall(value, 1), true);
        }
        return subtractSmall(value, 1, this.sign);
    };
    SmallInteger.prototype.prev = function () {
        var value = this.value;
        if (value - 1 > -MAX_INT) return new SmallInteger(value - 1);
        return new BigInteger(MAX_INT_ARR, true);
    };
    NativeBigInt.prototype.prev = function () {
        return new NativeBigInt(this.value - BigInt(1));
    }

    var powersOfTwo = [1];
    while (2 * powersOfTwo[powersOfTwo.length - 1] <= BASE) powersOfTwo.push(2 * powersOfTwo[powersOfTwo.length - 1]);
    var powers2Length = powersOfTwo.length, highestPower2 = powersOfTwo[powers2Length - 1];

    function shift_isSmall(n) {
        return Math.abs(n) <= BASE;
    }

    BigInteger.prototype.shiftLeft = function (v) {
        var n = parseValue(v).toJSNumber();
        if (!shift_isSmall(n)) {
            throw new Error(String(n) + " is too large for shifting.");
        }
        if (n < 0) return this.shiftRight(-n);
        var result = this;
        if (result.isZero()) return result;
        while (n >= powers2Length) {
            result = result.multiply(highestPower2);
            n -= powers2Length - 1;
        }
        return result.multiply(powersOfTwo[n]);
    };
    NativeBigInt.prototype.shiftLeft = function(v){
        v = parseValue(v)
        return new NativeBigInt(this.value << v.value)
    }
    SmallInteger.prototype.shiftLeft = BigInteger.prototype.shiftLeft;

    BigInteger.prototype.shiftRight = function (v) {
        var remQuo;
        var n = parseValue(v).toJSNumber();
        if (!shift_isSmall(n)) {
            throw new Error(String(n) + " is too large for shifting.");
        }
        if (n < 0) return this.shiftLeft(-n);
        var result = this;
        while (n >= powers2Length) {
            if (result.isZero() || (result.isNegative() && result.isUnit())) return result;
            remQuo = divModAny(result, highestPower2);
            result = remQuo[1].isNegative() ? remQuo[0].prev() : remQuo[0];
            n -= powers2Length - 1;
        }
        remQuo = divModAny(result, powersOfTwo[n]);
        return remQuo[1].isNegative() ? remQuo[0].prev() : remQuo[0];
    };
    NativeBigInt.prototype.shiftRight = function (v){
        v = parseValue(v)
        return new NativeBigInt(this.value >> v.value)
    }
    SmallInteger.prototype.shiftRight = BigInteger.prototype.shiftRight;

    function bitwise(x, y, fn) {
        y = parseValue(y);
        var xSign = x.isNegative(), ySign = y.isNegative();
        var xRem = xSign ? x.not() : x,
            yRem = ySign ? y.not() : y;
        var xDigit = 0, yDigit = 0;
        var xDivMod = null, yDivMod = null;
        var result = [];
        while (!xRem.isZero() || !yRem.isZero()) {
            xDivMod = divModAny(xRem, highestPower2);
            xDigit = xDivMod[1].toJSNumber();
            if (xSign) {
                xDigit = highestPower2 - 1 - xDigit; // two's complement for negative numbers
            }

            yDivMod = divModAny(yRem, highestPower2);
            yDigit = yDivMod[1].toJSNumber();
            if (ySign) {
                yDigit = highestPower2 - 1 - yDigit; // two's complement for negative numbers
            }

            xRem = xDivMod[0];
            yRem = yDivMod[0];
            result.push(fn(xDigit, yDigit));
        }
        var sum = fn(xSign ? 1 : 0, ySign ? 1 : 0) !== 0 ? bigInt(-1) : bigInt(0);
        for (var i = result.length - 1; i >= 0; i -= 1) {
            sum = sum.multiply(highestPower2).add(bigInt(result[i]));
        }
        return sum;
    }

    BigInteger.prototype.not = function () {
        return this.negate().prev();
    };
    NativeBigInt.prototype.not = SmallInteger.prototype.not = BigInteger.prototype.not;

    BigInteger.prototype.and = function (n) {
        return bitwise(this, n, function (a, b) { return a & b; });
    };
    NativeBigInt.prototype.and = SmallInteger.prototype.and = BigInteger.prototype.and;

    BigInteger.prototype.or = function (n) {
        return bitwise(this, n, function (a, b) { return a | b; });
    };
    NativeBigInt.prototype.or = SmallInteger.prototype.or = BigInteger.prototype.or;

    BigInteger.prototype.xor = function (n) {
        return bitwise(this, n, function (a, b) { return a ^ b; });
    };
    NativeBigInt.prototype.xor = SmallInteger.prototype.xor = BigInteger.prototype.xor;

    var LOBMASK_I = 1 << 30, LOBMASK_BI = (BASE & -BASE) * (BASE & -BASE) | LOBMASK_I;
    function roughLOB(n) { // get lowestOneBit (rough)
        // SmallInteger: return Min(lowestOneBit(n), 1 << 30)
        // BigInteger: return Min(lowestOneBit(n), 1 << 14) [BASE=1e7]
        var v = n.value,
            x = typeof v === "number" ? v | LOBMASK_I :
                typeof v === "bigint" ? v | BigInt(LOBMASK_I) :
                    v[0] + v[1] * BASE | LOBMASK_BI;
        return x & -x;
    }

    function integerLogarithm(value, base) {
        if (base.compareTo(value) <= 0) {
            var tmp = integerLogarithm(value, base.square(base));
            var p = tmp.p;
            var e = tmp.e;
            var t = p.multiply(base);
            return t.compareTo(value) <= 0 ? { p: t, e: e * 2 + 1 } : { p: p, e: e * 2 };
        }
        return { p: bigInt(1), e: 0 };
    }

    BigInteger.prototype.bitLength = function () {
        var n = this;
        if (n.compareTo(bigInt(0)) < 0) {
            n = n.negate().subtract(bigInt(1));
        }
        if (n.compareTo(bigInt(0)) === 0) {
            return bigInt(0);
        }
        return bigInt(integerLogarithm(n, bigInt(2)).e).add(bigInt(1));
    }
    NativeBigInt.prototype.bitLength = SmallInteger.prototype.bitLength = BigInteger.prototype.bitLength;

    function max(a, b) {
        a = parseValue(a);
        b = parseValue(b);
        return a.greater(b) ? a : b;
    }
    function min(a, b) {
        a = parseValue(a);
        b = parseValue(b);
        return a.lesser(b) ? a : b;
    }
    function gcd(a, b) {
        a = parseValue(a).abs();
        b = parseValue(b).abs();
        if (a.equals(b)) return a;
        if (a.isZero()) return b;
        if (b.isZero()) return a;
        var c = Integer[1], d, t;
        while (a.isEven() && b.isEven()) {
            d = min(roughLOB(a), roughLOB(b));
            a = a.divide(d);
            b = b.divide(d);
            c = c.multiply(d);
        }
        while (a.isEven()) {
            a = a.divide(roughLOB(a));
        }
        do {
            while (b.isEven()) {
                b = b.divide(roughLOB(b));
            }
            if (a.greater(b)) {
                t = b; b = a; a = t;
            }
            b = b.subtract(a);
        } while (!b.isZero());
        return c.isUnit() ? a : a.multiply(c);
    }
    function lcm(a, b) {
        a = parseValue(a).abs();
        b = parseValue(b).abs();
        return a.divide(gcd(a, b)).multiply(b);
    }
    function randBetween(a, b, rng) {
        a = parseValue(a);
        b = parseValue(b);
        var usedRNG = rng || Math.random;
        var low = min(a, b), high = max(a, b);
        var range = high.subtract(low).add(1);
        if (range.isSmall) return low.add(Math.floor(usedRNG() * range));
        var digits = toBase(range, BASE).value;
        var result = [], restricted = true;
        for (var i = 0; i < digits.length; i++) {
            var top = restricted ? digits[i] : BASE;
            var digit = truncate(usedRNG() * top);
            result.push(digit);
            if (digit < top) restricted = false;
        }
        return low.add(Integer.fromArray(result, BASE, false));
    }

    var parseBase = function (text, base, alphabet, caseSensitive) {
        alphabet = alphabet || DEFAULT_ALPHABET;
        text = String(text);
        if (!caseSensitive) {
            text = text.toLowerCase();
            alphabet = alphabet.toLowerCase();
        }
        var length = text.length;
        var i;
        var absBase = Math.abs(base);
        var alphabetValues = {};
        for (i = 0; i < alphabet.length; i++) {
            alphabetValues[alphabet[i]] = i;
        }
        for (i = 0; i < length; i++) {
            var c = text[i];
            if (c === "-") continue;
            if (c in alphabetValues) {
                if (alphabetValues[c] >= absBase) {
                    if (c === "1" && absBase === 1) continue;
                    throw new Error(c + " is not a valid digit in base " + base + ".");
                }
            }
        }
        base = parseValue(base);
        var digits = [];
        var isNegative = text[0] === "-";
        for (i = isNegative ? 1 : 0; i < text.length; i++) {
            var c = text[i];
            if (c in alphabetValues) digits.push(parseValue(alphabetValues[c]));
            else if (c === "<") {
                var start = i;
                do { i++; } while (text[i] !== ">" && i < text.length);
                digits.push(parseValue(text.slice(start + 1, i)));
            }
            else throw new Error(c + " is not a valid character");
        }
        return parseBaseFromArray(digits, base, isNegative);
    };

    function parseBaseFromArray(digits, base, isNegative) {
        var val = Integer[0], pow = Integer[1], i;
        for (i = digits.length - 1; i >= 0; i--) {
            val = val.add(digits[i].times(pow));
            pow = pow.times(base);
        }
        return isNegative ? val.negate() : val;
    }

    function stringify(digit, alphabet) {
        alphabet = alphabet || DEFAULT_ALPHABET;
        if (digit < alphabet.length) {
            return alphabet[digit];
        }
        return "<" + digit + ">";
    }

    function toBase(n, base) {
        base = bigInt(base);
        if (base.isZero()) {
            if (n.isZero()) return { value: [0], isNegative: false };
            throw new Error("Cannot convert nonzero numbers to base 0.");
        }
        if (base.equals(-1)) {
            if (n.isZero()) return { value: [0], isNegative: false };
            if (n.isNegative())
                return {
                    value: [].concat.apply([], Array.apply(null, Array(-n.toJSNumber()))
                        .map(Array.prototype.valueOf, [1, 0])
                    ),
                    isNegative: false
                };

            var arr = Array.apply(null, Array(n.toJSNumber() - 1))
                .map(Array.prototype.valueOf, [0, 1]);
            arr.unshift([1]);
            return {
                value: [].concat.apply([], arr),
                isNegative: false
            };
        }

        var neg = false;
        if (n.isNegative() && base.isPositive()) {
            neg = true;
            n = n.abs();
        }
        if (base.isUnit()) {
            if (n.isZero()) return { value: [0], isNegative: false };

            return {
                value: Array.apply(null, Array(n.toJSNumber()))
                    .map(Number.prototype.valueOf, 1),
                isNegative: neg
            };
        }
        var out = [];
        var left = n, divmod;
        while (left.isNegative() || left.compareAbs(base) >= 0) {
            divmod = left.divmod(base);
            left = divmod.quotient;
            var digit = divmod.remainder;
            if (digit.isNegative()) {
                digit = base.minus(digit).abs();
                left = left.next();
            }
            out.push(digit.toJSNumber());
        }
        out.push(left.toJSNumber());
        return { value: out.reverse(), isNegative: neg };
    }

    function toBaseString(n, base, alphabet) {
        var arr = toBase(n, base);
        return (arr.isNegative ? "-" : "") + arr.value.map(function (x) {
            return stringify(x, alphabet);
        }).join('');
    }

    BigInteger.prototype.toArray = function (radix) {
        return toBase(this, radix);
    };

    SmallInteger.prototype.toArray = function (radix) {
        return toBase(this, radix);
    };

    NativeBigInt.prototype.toArray = function (radix) {
        return toBase(this, radix);
    };

    BigInteger.prototype.toString = function (radix, alphabet) {
        if (radix === undefined) radix = 10;
        if (radix !== 10) return toBaseString(this, radix, alphabet);
        var v = this.value, l = v.length, str = String(v[--l]), zeros = "0000000", digit;
        while (--l >= 0) {
            digit = String(v[l]);
            str += zeros.slice(digit.length) + digit;
        }
        var sign = this.sign ? "-" : "";
        return sign + str;
    };

    SmallInteger.prototype.toString = function (radix, alphabet) {
        if (radix === undefined) radix = 10;
        if (radix != 10) return toBaseString(this, radix, alphabet);
        return String(this.value);
    };

    NativeBigInt.prototype.toString = SmallInteger.prototype.toString;

    NativeBigInt.prototype.toJSON = BigInteger.prototype.toJSON = SmallInteger.prototype.toJSON = function () { return this.toString(); }

    BigInteger.prototype.valueOf = function () {
        return parseInt(this.toString(), 10);
    };
    BigInteger.prototype.toJSNumber = BigInteger.prototype.valueOf;

    SmallInteger.prototype.valueOf = function () {
        return this.value;
    };
    SmallInteger.prototype.toJSNumber = SmallInteger.prototype.valueOf;
    NativeBigInt.prototype.valueOf = NativeBigInt.prototype.toJSNumber = function () {
        return parseInt(this.toString(), 10);
    }

    function parseStringValue(v) {
        if (isPrecise(+v)) {
            var x = +v;
            if (x === truncate(x))
                return supportsNativeBigInt ? new NativeBigInt(BigInt(x)) : new SmallInteger(x);
            throw new Error("Invalid integer: " + v);
        }
        var sign = v[0] === "-";
        if (sign) v = v.slice(1);
        var split = v.split(/e/i);
        if (split.length > 2) throw new Error("Invalid integer: " + split.join("e"));
        if (split.length === 2) {
            var exp = split[1];
            if (exp[0] === "+") exp = exp.slice(1);
            exp = +exp;
            if (exp !== truncate(exp) || !isPrecise(exp)) throw new Error("Invalid integer: " + exp + " is not a valid exponent.");
            var text = split[0];
            var decimalPlace = text.indexOf(".");
            if (decimalPlace >= 0) {
                exp -= text.length - decimalPlace - 1;
                text = text.slice(0, decimalPlace) + text.slice(decimalPlace + 1);
            }
            if (exp < 0) throw new Error("Cannot include negative exponent part for integers");
            text += (new Array(exp + 1)).join("0");
            v = text;
        }
        var isValid = /^([0-9][0-9]*)$/.test(v);
        if (!isValid) throw new Error("Invalid integer: " + v);
        if (supportsNativeBigInt) {
            return new NativeBigInt(BigInt(sign ? "-" + v : v));
        }
        var r = [], max = v.length, l = LOG_BASE, min = max - l;
        while (max > 0) {
            r.push(+v.slice(min, max));
            min -= l;
            if (min < 0) min = 0;
            max -= l;
        }
        trim(r);
        return new BigInteger(r, sign);
    }

    function parseNumberValue(v) {
        if (supportsNativeBigInt) {
            return new NativeBigInt(BigInt(v));
        }
        if (isPrecise(v)) {
            if (v !== truncate(v)) throw new Error(v + " is not an integer.");
            return new SmallInteger(v);
        }
        return parseStringValue(v.toString());
    }

    function parseValue(v) {
        if (typeof v === "number") {
            return parseNumberValue(v);
        }
        if (typeof v === "string") {
            return parseStringValue(v);
        }
        if (typeof v === "bigint") {
            return new NativeBigInt(v);
        }
        return v;
    }
    // Pre-define numbers in range [-999,999]
    for (var i = 0; i < 1000; i++) {
        Integer[i] = parseValue(i);
        if (i > 0) Integer[-i] = parseValue(-i);
    }
    // Backwards compatibility
    Integer.one = Integer[1];
    Integer.zero = Integer[0];
    Integer.minusOne = Integer[-1];
    Integer.max = max;
    Integer.min = min;
    Integer.gcd = gcd;
    Integer.lcm = lcm;
    Integer.isInstance = function (x) { return x instanceof BigInteger || x instanceof SmallInteger || x instanceof NativeBigInt; };
    Integer.randBetween = randBetween;

    Integer.fromArray = function (digits, base, isNegative) {
        return parseBaseFromArray(digits.map(parseValue), parseValue(base || 10), isNegative);
    };

    return Integer;
})();

// Node.js check
if ( true && module.hasOwnProperty("exports")) {
    module.exports = bigInt;
}

//amd check
if (true) {
    !(__WEBPACK_AMD_DEFINE_RESULT__ = (function () {
        return bigInt;
    }).call(exports, __webpack_require__, exports, module),
		__WEBPACK_AMD_DEFINE_RESULT__ !== undefined && (module.exports = __WEBPACK_AMD_DEFINE_RESULT__));
}


/***/ }),

/***/ "./node_modules/buffer/index.js":
/*!**************************************!*\
  !*** ./node_modules/buffer/index.js ***!
  \**************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */



const base64 = __webpack_require__(/*! base64-js */ "./node_modules/base64-js/index.js")
const ieee754 = __webpack_require__(/*! ieee754 */ "./node_modules/ieee754/index.js")
const customInspectSymbol =
  (typeof Symbol === 'function' && typeof Symbol['for'] === 'function') // eslint-disable-line dot-notation
    ? Symbol['for']('nodejs.util.inspect.custom') // eslint-disable-line dot-notation
    : null

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

const K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    const arr = new Uint8Array(1)
    const proto = { foo: function () { return 42 } }
    Object.setPrototypeOf(proto, Uint8Array.prototype)
    Object.setPrototypeOf(arr, proto)
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  const buf = new Uint8Array(length)
  Object.setPrototypeOf(buf, Buffer.prototype)
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayView(value)
  }

  if (value == null) {
    throw new TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof SharedArrayBuffer !== 'undefined' &&
      (isInstance(value, SharedArrayBuffer) ||
      (value && isInstance(value.buffer, SharedArrayBuffer)))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  const valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  const b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(value[Symbol.toPrimitive]('string'), encodingOrOffset, length)
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Object.setPrototypeOf(Buffer.prototype, Uint8Array.prototype)
Object.setPrototypeOf(Buffer, Uint8Array)

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpreted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  const length = byteLength(string, encoding) | 0
  let buf = createBuffer(length)

  const actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  const length = array.length < 0 ? 0 : checked(array.length) | 0
  const buf = createBuffer(length)
  for (let i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayView (arrayView) {
  if (isInstance(arrayView, Uint8Array)) {
    const copy = new Uint8Array(arrayView)
    return fromArrayBuffer(copy.buffer, copy.byteOffset, copy.byteLength)
  }
  return fromArrayLike(arrayView)
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  let buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(buf, Buffer.prototype)

  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    const len = checked(obj.length) | 0
    const buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  let x = a.length
  let y = b.length

  for (let i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  let i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  const buffer = Buffer.allocUnsafe(length)
  let pos = 0
  for (i = 0; i < list.length; ++i) {
    let buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      if (pos + buf.length > buffer.length) {
        if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf)
        buf.copy(buffer, pos)
      } else {
        Uint8Array.prototype.set.call(
          buffer,
          buf,
          pos
        )
      }
    } else if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    } else {
      buf.copy(buffer, pos)
    }
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  const len = string.length
  const mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  let loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  let loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coercion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  const i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  const len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (let i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  const len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (let i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  const len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (let i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  const length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  let str = ''
  const max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}
if (customInspectSymbol) {
  Buffer.prototype[customInspectSymbol] = Buffer.prototype.inspect
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  let x = thisEnd - thisStart
  let y = end - start
  const len = Math.min(x, y)

  const thisCopy = this.slice(thisStart, thisEnd)
  const targetCopy = target.slice(start, end)

  for (let i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [val], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  let indexSize = 1
  let arrLength = arr.length
  let valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  let i
  if (dir) {
    let foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      let found = true
      for (let j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  const remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  const strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  let i
  for (i = 0; i < length; ++i) {
    const parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  const remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  let loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
      case 'latin1':
      case 'binary':
        return asciiWrite(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  const res = []

  let i = start
  while (i < end) {
    const firstByte = buf[i]
    let codePoint = null
    let bytesPerSequence = (firstByte > 0xEF)
      ? 4
      : (firstByte > 0xDF)
          ? 3
          : (firstByte > 0xBF)
              ? 2
              : 1

    if (i + bytesPerSequence <= end) {
      let secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
const MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  const len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  let res = ''
  let i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  let ret = ''
  end = Math.min(buf.length, end)

  for (let i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  let ret = ''
  end = Math.min(buf.length, end)

  for (let i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  const len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  let out = ''
  for (let i = start; i < end; ++i) {
    out += hexSliceLookupTable[buf[i]]
  }
  return out
}

function utf16leSlice (buf, start, end) {
  const bytes = buf.slice(start, end)
  let res = ''
  // If bytes.length is odd, the last 8 bits must be ignored (same as node.js)
  for (let i = 0; i < bytes.length - 1; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  const len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  const newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(newBuf, Buffer.prototype)

  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUintLE =
Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  let val = this[offset]
  let mul = 1
  let i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUintBE =
Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  let val = this[offset + --byteLength]
  let mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUint8 =
Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUint16LE =
Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUint16BE =
Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUint32LE =
Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUint32BE =
Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readBigUInt64LE = defineBigIntMethod(function readBigUInt64LE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const lo = first +
    this[++offset] * 2 ** 8 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 24

  const hi = this[++offset] +
    this[++offset] * 2 ** 8 +
    this[++offset] * 2 ** 16 +
    last * 2 ** 24

  return BigInt(lo) + (BigInt(hi) << BigInt(32))
})

Buffer.prototype.readBigUInt64BE = defineBigIntMethod(function readBigUInt64BE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const hi = first * 2 ** 24 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    this[++offset]

  const lo = this[++offset] * 2 ** 24 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    last

  return (BigInt(hi) << BigInt(32)) + BigInt(lo)
})

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  let val = this[offset]
  let mul = 1
  let i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  let i = byteLength
  let mul = 1
  let val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  const val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  const val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readBigInt64LE = defineBigIntMethod(function readBigInt64LE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const val = this[offset + 4] +
    this[offset + 5] * 2 ** 8 +
    this[offset + 6] * 2 ** 16 +
    (last << 24) // Overflow

  return (BigInt(val) << BigInt(32)) +
    BigInt(first +
    this[++offset] * 2 ** 8 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 24)
})

Buffer.prototype.readBigInt64BE = defineBigIntMethod(function readBigInt64BE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const val = (first << 24) + // Overflow
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    this[++offset]

  return (BigInt(val) << BigInt(32)) +
    BigInt(this[++offset] * 2 ** 24 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    last)
})

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUintLE =
Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    const maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  let mul = 1
  let i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUintBE =
Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    const maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  let i = byteLength - 1
  let mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUint8 =
Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUint16LE =
Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUint16BE =
Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUint32LE =
Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUint32BE =
Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function wrtBigUInt64LE (buf, value, offset, min, max) {
  checkIntBI(value, min, max, buf, offset, 7)

  let lo = Number(value & BigInt(0xffffffff))
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  let hi = Number(value >> BigInt(32) & BigInt(0xffffffff))
  buf[offset++] = hi
  hi = hi >> 8
  buf[offset++] = hi
  hi = hi >> 8
  buf[offset++] = hi
  hi = hi >> 8
  buf[offset++] = hi
  return offset
}

function wrtBigUInt64BE (buf, value, offset, min, max) {
  checkIntBI(value, min, max, buf, offset, 7)

  let lo = Number(value & BigInt(0xffffffff))
  buf[offset + 7] = lo
  lo = lo >> 8
  buf[offset + 6] = lo
  lo = lo >> 8
  buf[offset + 5] = lo
  lo = lo >> 8
  buf[offset + 4] = lo
  let hi = Number(value >> BigInt(32) & BigInt(0xffffffff))
  buf[offset + 3] = hi
  hi = hi >> 8
  buf[offset + 2] = hi
  hi = hi >> 8
  buf[offset + 1] = hi
  hi = hi >> 8
  buf[offset] = hi
  return offset + 8
}

Buffer.prototype.writeBigUInt64LE = defineBigIntMethod(function writeBigUInt64LE (value, offset = 0) {
  return wrtBigUInt64LE(this, value, offset, BigInt(0), BigInt('0xffffffffffffffff'))
})

Buffer.prototype.writeBigUInt64BE = defineBigIntMethod(function writeBigUInt64BE (value, offset = 0) {
  return wrtBigUInt64BE(this, value, offset, BigInt(0), BigInt('0xffffffffffffffff'))
})

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    const limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  let i = 0
  let mul = 1
  let sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    const limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  let i = byteLength - 1
  let mul = 1
  let sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeBigInt64LE = defineBigIntMethod(function writeBigInt64LE (value, offset = 0) {
  return wrtBigUInt64LE(this, value, offset, -BigInt('0x8000000000000000'), BigInt('0x7fffffffffffffff'))
})

Buffer.prototype.writeBigInt64BE = defineBigIntMethod(function writeBigInt64BE (value, offset = 0) {
  return wrtBigUInt64BE(this, value, offset, -BigInt('0x8000000000000000'), BigInt('0x7fffffffffffffff'))
})

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  const len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      const code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  } else if (typeof val === 'boolean') {
    val = Number(val)
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  let i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    const bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    const len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// CUSTOM ERRORS
// =============

// Simplified versions from Node, changed for Buffer-only usage
const errors = {}
function E (sym, getMessage, Base) {
  errors[sym] = class NodeError extends Base {
    constructor () {
      super()

      Object.defineProperty(this, 'message', {
        value: getMessage.apply(this, arguments),
        writable: true,
        configurable: true
      })

      // Add the error code to the name to include it in the stack trace.
      this.name = `${this.name} [${sym}]`
      // Access the stack to generate the error message including the error code
      // from the name.
      this.stack // eslint-disable-line no-unused-expressions
      // Reset the name to the actual name.
      delete this.name
    }

    get code () {
      return sym
    }

    set code (value) {
      Object.defineProperty(this, 'code', {
        configurable: true,
        enumerable: true,
        value,
        writable: true
      })
    }

    toString () {
      return `${this.name} [${sym}]: ${this.message}`
    }
  }
}

E('ERR_BUFFER_OUT_OF_BOUNDS',
  function (name) {
    if (name) {
      return `${name} is outside of buffer bounds`
    }

    return 'Attempt to access memory outside buffer bounds'
  }, RangeError)
E('ERR_INVALID_ARG_TYPE',
  function (name, actual) {
    return `The "${name}" argument must be of type number. Received type ${typeof actual}`
  }, TypeError)
E('ERR_OUT_OF_RANGE',
  function (str, range, input) {
    let msg = `The value of "${str}" is out of range.`
    let received = input
    if (Number.isInteger(input) && Math.abs(input) > 2 ** 32) {
      received = addNumericalSeparator(String(input))
    } else if (typeof input === 'bigint') {
      received = String(input)
      if (input > BigInt(2) ** BigInt(32) || input < -(BigInt(2) ** BigInt(32))) {
        received = addNumericalSeparator(received)
      }
      received += 'n'
    }
    msg += ` It must be ${range}. Received ${received}`
    return msg
  }, RangeError)

function addNumericalSeparator (val) {
  let res = ''
  let i = val.length
  const start = val[0] === '-' ? 1 : 0
  for (; i >= start + 4; i -= 3) {
    res = `_${val.slice(i - 3, i)}${res}`
  }
  return `${val.slice(0, i)}${res}`
}

// CHECK FUNCTIONS
// ===============

function checkBounds (buf, offset, byteLength) {
  validateNumber(offset, 'offset')
  if (buf[offset] === undefined || buf[offset + byteLength] === undefined) {
    boundsError(offset, buf.length - (byteLength + 1))
  }
}

function checkIntBI (value, min, max, buf, offset, byteLength) {
  if (value > max || value < min) {
    const n = typeof min === 'bigint' ? 'n' : ''
    let range
    if (byteLength > 3) {
      if (min === 0 || min === BigInt(0)) {
        range = `>= 0${n} and < 2${n} ** ${(byteLength + 1) * 8}${n}`
      } else {
        range = `>= -(2${n} ** ${(byteLength + 1) * 8 - 1}${n}) and < 2 ** ` +
                `${(byteLength + 1) * 8 - 1}${n}`
      }
    } else {
      range = `>= ${min}${n} and <= ${max}${n}`
    }
    throw new errors.ERR_OUT_OF_RANGE('value', range, value)
  }
  checkBounds(buf, offset, byteLength)
}

function validateNumber (value, name) {
  if (typeof value !== 'number') {
    throw new errors.ERR_INVALID_ARG_TYPE(name, 'number', value)
  }
}

function boundsError (value, length, type) {
  if (Math.floor(value) !== value) {
    validateNumber(value, type)
    throw new errors.ERR_OUT_OF_RANGE(type || 'offset', 'an integer', value)
  }

  if (length < 0) {
    throw new errors.ERR_BUFFER_OUT_OF_BOUNDS()
  }

  throw new errors.ERR_OUT_OF_RANGE(type || 'offset',
                                    `>= ${type ? 1 : 0} and <= ${length}`,
                                    value)
}

// HELPER FUNCTIONS
// ================

const INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  let codePoint
  const length = string.length
  let leadSurrogate = null
  const bytes = []

  for (let i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  const byteArray = []
  for (let i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  let c, hi, lo
  const byteArray = []
  for (let i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  let i
  for (i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

// Create lookup table for `toString('hex')`
// See: https://github.com/feross/buffer/issues/219
const hexSliceLookupTable = (function () {
  const alphabet = '0123456789abcdef'
  const table = new Array(256)
  for (let i = 0; i < 16; ++i) {
    const i16 = i * 16
    for (let j = 0; j < 16; ++j) {
      table[i16 + j] = alphabet[i] + alphabet[j]
    }
  }
  return table
})()

// Return not function with Error if BigInt not supported
function defineBigIntMethod (fn) {
  return typeof BigInt === 'undefined' ? BufferBigIntNotDefined : fn
}

function BufferBigIntNotDefined () {
  throw new Error('BigInt not supported')
}


/***/ }),

/***/ "./node_modules/ieee754/index.js":
/*!***************************************!*\
  !*** ./node_modules/ieee754/index.js ***!
  \***************************************/
/***/ ((__unused_webpack_module, exports) => {

/*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}


/***/ }),

/***/ "./node_modules/os-browserify/browser.js":
/*!***********************************************!*\
  !*** ./node_modules/os-browserify/browser.js ***!
  \***********************************************/
/***/ ((__unused_webpack_module, exports) => {

exports.endianness = function () { return 'LE' };

exports.hostname = function () {
    if (typeof location !== 'undefined') {
        return location.hostname
    }
    else return '';
};

exports.loadavg = function () { return [] };

exports.uptime = function () { return 0 };

exports.freemem = function () {
    return Number.MAX_VALUE;
};

exports.totalmem = function () {
    return Number.MAX_VALUE;
};

exports.cpus = function () { return [] };

exports.type = function () { return 'Browser' };

exports.release = function () {
    if (typeof navigator !== 'undefined') {
        return navigator.appVersion;
    }
    return '';
};

exports.networkInterfaces
= exports.getNetworkInterfaces
= function () { return {} };

exports.arch = function () { return 'javascript' };

exports.platform = function () { return 'browser' };

exports.tmpdir = exports.tmpDir = function () {
    return '/tmp';
};

exports.EOL = '\n';

exports.homedir = function () {
	return '/'
};


/***/ }),

/***/ "./node_modules/pako/dist/pako_inflate.js":
/*!************************************************!*\
  !*** ./node_modules/pako/dist/pako_inflate.js ***!
  \************************************************/
/***/ (function(__unused_webpack_module, exports) {


/*! pako 2.1.0 https://github.com/nodeca/pako @license (MIT AND Zlib) */
(function (global, factory) {
   true ? factory(exports) :
  0;
})(this, (function (exports) { 'use strict';

  // Note: adler32 takes 12% for level 0 and 2% for level 6.
  // It isn't worth it to make additional optimizations as in original.
  // Small size is preferable.

  // (C) 1995-2013 Jean-loup Gailly and Mark Adler
  // (C) 2014-2017 Vitaly Puzrin and Andrey Tupitsin
  //
  // This software is provided 'as-is', without any express or implied
  // warranty. In no event will the authors be held liable for any damages
  // arising from the use of this software.
  //
  // Permission is granted to anyone to use this software for any purpose,
  // including commercial applications, and to alter it and redistribute it
  // freely, subject to the following restrictions:
  //
  // 1. The origin of this software must not be misrepresented; you must not
  //   claim that you wrote the original software. If you use this software
  //   in a product, an acknowledgment in the product documentation would be
  //   appreciated but is not required.
  // 2. Altered source versions must be plainly marked as such, and must not be
  //   misrepresented as being the original software.
  // 3. This notice may not be removed or altered from any source distribution.

  const adler32 = (adler, buf, len, pos) => {
    let s1 = (adler & 0xffff) |0,
        s2 = ((adler >>> 16) & 0xffff) |0,
        n = 0;

    while (len !== 0) {
      // Set limit ~ twice less than 5552, to keep
      // s2 in 31-bits, because we force signed ints.
      // in other case %= will fail.
      n = len > 2000 ? 2000 : len;
      len -= n;

      do {
        s1 = (s1 + buf[pos++]) |0;
        s2 = (s2 + s1) |0;
      } while (--n);

      s1 %= 65521;
      s2 %= 65521;
    }

    return (s1 | (s2 << 16)) |0;
  };


  var adler32_1 = adler32;

  // Note: we can't get significant speed boost here.
  // So write code to minimize size - no pregenerated tables
  // and array tools dependencies.

  // (C) 1995-2013 Jean-loup Gailly and Mark Adler
  // (C) 2014-2017 Vitaly Puzrin and Andrey Tupitsin
  //
  // This software is provided 'as-is', without any express or implied
  // warranty. In no event will the authors be held liable for any damages
  // arising from the use of this software.
  //
  // Permission is granted to anyone to use this software for any purpose,
  // including commercial applications, and to alter it and redistribute it
  // freely, subject to the following restrictions:
  //
  // 1. The origin of this software must not be misrepresented; you must not
  //   claim that you wrote the original software. If you use this software
  //   in a product, an acknowledgment in the product documentation would be
  //   appreciated but is not required.
  // 2. Altered source versions must be plainly marked as such, and must not be
  //   misrepresented as being the original software.
  // 3. This notice may not be removed or altered from any source distribution.

  // Use ordinary array, since untyped makes no boost here
  const makeTable = () => {
    let c, table = [];

    for (var n = 0; n < 256; n++) {
      c = n;
      for (var k = 0; k < 8; k++) {
        c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
      }
      table[n] = c;
    }

    return table;
  };

  // Create table on load. Just 255 signed longs. Not a problem.
  const crcTable = new Uint32Array(makeTable());


  const crc32 = (crc, buf, len, pos) => {
    const t = crcTable;
    const end = pos + len;

    crc ^= -1;

    for (let i = pos; i < end; i++) {
      crc = (crc >>> 8) ^ t[(crc ^ buf[i]) & 0xFF];
    }

    return (crc ^ (-1)); // >>> 0;
  };


  var crc32_1 = crc32;

  // (C) 1995-2013 Jean-loup Gailly and Mark Adler
  // (C) 2014-2017 Vitaly Puzrin and Andrey Tupitsin
  //
  // This software is provided 'as-is', without any express or implied
  // warranty. In no event will the authors be held liable for any damages
  // arising from the use of this software.
  //
  // Permission is granted to anyone to use this software for any purpose,
  // including commercial applications, and to alter it and redistribute it
  // freely, subject to the following restrictions:
  //
  // 1. The origin of this software must not be misrepresented; you must not
  //   claim that you wrote the original software. If you use this software
  //   in a product, an acknowledgment in the product documentation would be
  //   appreciated but is not required.
  // 2. Altered source versions must be plainly marked as such, and must not be
  //   misrepresented as being the original software.
  // 3. This notice may not be removed or altered from any source distribution.

  // See state defs from inflate.js
  const BAD$1 = 16209;       /* got a data error -- remain here until reset */
  const TYPE$1 = 16191;      /* i: waiting for type bits, including last-flag bit */

  /*
     Decode literal, length, and distance codes and write out the resulting
     literal and match bytes until either not enough input or output is
     available, an end-of-block is encountered, or a data error is encountered.
     When large enough input and output buffers are supplied to inflate(), for
     example, a 16K input buffer and a 64K output buffer, more than 95% of the
     inflate execution time is spent in this routine.

     Entry assumptions:

          state.mode === LEN
          strm.avail_in >= 6
          strm.avail_out >= 258
          start >= strm.avail_out
          state.bits < 8

     On return, state.mode is one of:

          LEN -- ran out of enough output space or enough available input
          TYPE -- reached end of block code, inflate() to interpret next block
          BAD -- error in block data

     Notes:

      - The maximum input bits used by a length/distance pair is 15 bits for the
        length code, 5 bits for the length extra, 15 bits for the distance code,
        and 13 bits for the distance extra.  This totals 48 bits, or six bytes.
        Therefore if strm.avail_in >= 6, then there is enough input to avoid
        checking for available input while decoding.

      - The maximum bytes that a single length/distance pair can output is 258
        bytes, which is the maximum length that can be coded.  inflate_fast()
        requires strm.avail_out >= 258 for each loop to avoid checking for
        output space.
   */
  var inffast = function inflate_fast(strm, start) {
    let _in;                    /* local strm.input */
    let last;                   /* have enough input while in < last */
    let _out;                   /* local strm.output */
    let beg;                    /* inflate()'s initial strm.output */
    let end;                    /* while out < end, enough space available */
  //#ifdef INFLATE_STRICT
    let dmax;                   /* maximum distance from zlib header */
  //#endif
    let wsize;                  /* window size or zero if not using window */
    let whave;                  /* valid bytes in the window */
    let wnext;                  /* window write index */
    // Use `s_window` instead `window`, avoid conflict with instrumentation tools
    let s_window;               /* allocated sliding window, if wsize != 0 */
    let hold;                   /* local strm.hold */
    let bits;                   /* local strm.bits */
    let lcode;                  /* local strm.lencode */
    let dcode;                  /* local strm.distcode */
    let lmask;                  /* mask for first level of length codes */
    let dmask;                  /* mask for first level of distance codes */
    let here;                   /* retrieved table entry */
    let op;                     /* code bits, operation, extra bits, or */
                                /*  window position, window bytes to copy */
    let len;                    /* match length, unused bytes */
    let dist;                   /* match distance */
    let from;                   /* where to copy match from */
    let from_source;


    let input, output; // JS specific, because we have no pointers

    /* copy state to local variables */
    const state = strm.state;
    //here = state.here;
    _in = strm.next_in;
    input = strm.input;
    last = _in + (strm.avail_in - 5);
    _out = strm.next_out;
    output = strm.output;
    beg = _out - (start - strm.avail_out);
    end = _out + (strm.avail_out - 257);
  //#ifdef INFLATE_STRICT
    dmax = state.dmax;
  //#endif
    wsize = state.wsize;
    whave = state.whave;
    wnext = state.wnext;
    s_window = state.window;
    hold = state.hold;
    bits = state.bits;
    lcode = state.lencode;
    dcode = state.distcode;
    lmask = (1 << state.lenbits) - 1;
    dmask = (1 << state.distbits) - 1;


    /* decode literals and length/distances until end-of-block or not enough
       input data or output space */

    top:
    do {
      if (bits < 15) {
        hold += input[_in++] << bits;
        bits += 8;
        hold += input[_in++] << bits;
        bits += 8;
      }

      here = lcode[hold & lmask];

      dolen:
      for (;;) { // Goto emulation
        op = here >>> 24/*here.bits*/;
        hold >>>= op;
        bits -= op;
        op = (here >>> 16) & 0xff/*here.op*/;
        if (op === 0) {                          /* literal */
          //Tracevv((stderr, here.val >= 0x20 && here.val < 0x7f ?
          //        "inflate:         literal '%c'\n" :
          //        "inflate:         literal 0x%02x\n", here.val));
          output[_out++] = here & 0xffff/*here.val*/;
        }
        else if (op & 16) {                     /* length base */
          len = here & 0xffff/*here.val*/;
          op &= 15;                           /* number of extra bits */
          if (op) {
            if (bits < op) {
              hold += input[_in++] << bits;
              bits += 8;
            }
            len += hold & ((1 << op) - 1);
            hold >>>= op;
            bits -= op;
          }
          //Tracevv((stderr, "inflate:         length %u\n", len));
          if (bits < 15) {
            hold += input[_in++] << bits;
            bits += 8;
            hold += input[_in++] << bits;
            bits += 8;
          }
          here = dcode[hold & dmask];

          dodist:
          for (;;) { // goto emulation
            op = here >>> 24/*here.bits*/;
            hold >>>= op;
            bits -= op;
            op = (here >>> 16) & 0xff/*here.op*/;

            if (op & 16) {                      /* distance base */
              dist = here & 0xffff/*here.val*/;
              op &= 15;                       /* number of extra bits */
              if (bits < op) {
                hold += input[_in++] << bits;
                bits += 8;
                if (bits < op) {
                  hold += input[_in++] << bits;
                  bits += 8;
                }
              }
              dist += hold & ((1 << op) - 1);
  //#ifdef INFLATE_STRICT
              if (dist > dmax) {
                strm.msg = 'invalid distance too far back';
                state.mode = BAD$1;
                break top;
              }
  //#endif
              hold >>>= op;
              bits -= op;
              //Tracevv((stderr, "inflate:         distance %u\n", dist));
              op = _out - beg;                /* max distance in output */
              if (dist > op) {                /* see if copy from window */
                op = dist - op;               /* distance back in window */
                if (op > whave) {
                  if (state.sane) {
                    strm.msg = 'invalid distance too far back';
                    state.mode = BAD$1;
                    break top;
                  }

  // (!) This block is disabled in zlib defaults,
  // don't enable it for binary compatibility
  //#ifdef INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR_ARRR
  //                if (len <= op - whave) {
  //                  do {
  //                    output[_out++] = 0;
  //                  } while (--len);
  //                  continue top;
  //                }
  //                len -= op - whave;
  //                do {
  //                  output[_out++] = 0;
  //                } while (--op > whave);
  //                if (op === 0) {
  //                  from = _out - dist;
  //                  do {
  //                    output[_out++] = output[from++];
  //                  } while (--len);
  //                  continue top;
  //                }
  //#endif
                }
                from = 0; // window index
                from_source = s_window;
                if (wnext === 0) {           /* very common case */
                  from += wsize - op;
                  if (op < len) {         /* some from window */
                    len -= op;
                    do {
                      output[_out++] = s_window[from++];
                    } while (--op);
                    from = _out - dist;  /* rest from output */
                    from_source = output;
                  }
                }
                else if (wnext < op) {      /* wrap around window */
                  from += wsize + wnext - op;
                  op -= wnext;
                  if (op < len) {         /* some from end of window */
                    len -= op;
                    do {
                      output[_out++] = s_window[from++];
                    } while (--op);
                    from = 0;
                    if (wnext < len) {  /* some from start of window */
                      op = wnext;
                      len -= op;
                      do {
                        output[_out++] = s_window[from++];
                      } while (--op);
                      from = _out - dist;      /* rest from output */
                      from_source = output;
                    }
                  }
                }
                else {                      /* contiguous in window */
                  from += wnext - op;
                  if (op < len) {         /* some from window */
                    len -= op;
                    do {
                      output[_out++] = s_window[from++];
                    } while (--op);
                    from = _out - dist;  /* rest from output */
                    from_source = output;
                  }
                }
                while (len > 2) {
                  output[_out++] = from_source[from++];
                  output[_out++] = from_source[from++];
                  output[_out++] = from_source[from++];
                  len -= 3;
                }
                if (len) {
                  output[_out++] = from_source[from++];
                  if (len > 1) {
                    output[_out++] = from_source[from++];
                  }
                }
              }
              else {
                from = _out - dist;          /* copy direct from output */
                do {                        /* minimum length is three */
                  output[_out++] = output[from++];
                  output[_out++] = output[from++];
                  output[_out++] = output[from++];
                  len -= 3;
                } while (len > 2);
                if (len) {
                  output[_out++] = output[from++];
                  if (len > 1) {
                    output[_out++] = output[from++];
                  }
                }
              }
            }
            else if ((op & 64) === 0) {          /* 2nd level distance code */
              here = dcode[(here & 0xffff)/*here.val*/ + (hold & ((1 << op) - 1))];
              continue dodist;
            }
            else {
              strm.msg = 'invalid distance code';
              state.mode = BAD$1;
              break top;
            }

            break; // need to emulate goto via "continue"
          }
        }
        else if ((op & 64) === 0) {              /* 2nd level length code */
          here = lcode[(here & 0xffff)/*here.val*/ + (hold & ((1 << op) - 1))];
          continue dolen;
        }
        else if (op & 32) {                     /* end-of-block */
          //Tracevv((stderr, "inflate:         end of block\n"));
          state.mode = TYPE$1;
          break top;
        }
        else {
          strm.msg = 'invalid literal/length code';
          state.mode = BAD$1;
          break top;
        }

        break; // need to emulate goto via "continue"
      }
    } while (_in < last && _out < end);

    /* return unused bytes (on entry, bits < 8, so in won't go too far back) */
    len = bits >> 3;
    _in -= len;
    bits -= len << 3;
    hold &= (1 << bits) - 1;

    /* update state and return */
    strm.next_in = _in;
    strm.next_out = _out;
    strm.avail_in = (_in < last ? 5 + (last - _in) : 5 - (_in - last));
    strm.avail_out = (_out < end ? 257 + (end - _out) : 257 - (_out - end));
    state.hold = hold;
    state.bits = bits;
    return;
  };

  // (C) 1995-2013 Jean-loup Gailly and Mark Adler
  // (C) 2014-2017 Vitaly Puzrin and Andrey Tupitsin
  //
  // This software is provided 'as-is', without any express or implied
  // warranty. In no event will the authors be held liable for any damages
  // arising from the use of this software.
  //
  // Permission is granted to anyone to use this software for any purpose,
  // including commercial applications, and to alter it and redistribute it
  // freely, subject to the following restrictions:
  //
  // 1. The origin of this software must not be misrepresented; you must not
  //   claim that you wrote the original software. If you use this software
  //   in a product, an acknowledgment in the product documentation would be
  //   appreciated but is not required.
  // 2. Altered source versions must be plainly marked as such, and must not be
  //   misrepresented as being the original software.
  // 3. This notice may not be removed or altered from any source distribution.

  const MAXBITS = 15;
  const ENOUGH_LENS$1 = 852;
  const ENOUGH_DISTS$1 = 592;
  //const ENOUGH = (ENOUGH_LENS+ENOUGH_DISTS);

  const CODES$1 = 0;
  const LENS$1 = 1;
  const DISTS$1 = 2;

  const lbase = new Uint16Array([ /* Length codes 257..285 base */
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0
  ]);

  const lext = new Uint8Array([ /* Length codes 257..285 extra */
    16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18,
    19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 16, 72, 78
  ]);

  const dbase = new Uint16Array([ /* Distance codes 0..29 base */
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577, 0, 0
  ]);

  const dext = new Uint8Array([ /* Distance codes 0..29 extra */
    16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22,
    23, 23, 24, 24, 25, 25, 26, 26, 27, 27,
    28, 28, 29, 29, 64, 64
  ]);

  const inflate_table = (type, lens, lens_index, codes, table, table_index, work, opts) =>
  {
    const bits = opts.bits;
        //here = opts.here; /* table entry for duplication */

    let len = 0;               /* a code's length in bits */
    let sym = 0;               /* index of code symbols */
    let min = 0, max = 0;          /* minimum and maximum code lengths */
    let root = 0;              /* number of index bits for root table */
    let curr = 0;              /* number of index bits for current table */
    let drop = 0;              /* code bits to drop for sub-table */
    let left = 0;                   /* number of prefix codes available */
    let used = 0;              /* code entries in table used */
    let huff = 0;              /* Huffman code */
    let incr;              /* for incrementing code, index */
    let fill;              /* index for replicating entries */
    let low;               /* low bits for current root entry */
    let mask;              /* mask for low root bits */
    let next;             /* next available space in table */
    let base = null;     /* base value table to use */
  //  let shoextra;    /* extra bits table to use */
    let match;                  /* use base and extra for symbol >= match */
    const count = new Uint16Array(MAXBITS + 1); //[MAXBITS+1];    /* number of codes of each length */
    const offs = new Uint16Array(MAXBITS + 1); //[MAXBITS+1];     /* offsets in table for each length */
    let extra = null;

    let here_bits, here_op, here_val;

    /*
     Process a set of code lengths to create a canonical Huffman code.  The
     code lengths are lens[0..codes-1].  Each length corresponds to the
     symbols 0..codes-1.  The Huffman code is generated by first sorting the
     symbols by length from short to long, and retaining the symbol order
     for codes with equal lengths.  Then the code starts with all zero bits
     for the first code of the shortest length, and the codes are integer
     increments for the same length, and zeros are appended as the length
     increases.  For the deflate format, these bits are stored backwards
     from their more natural integer increment ordering, and so when the
     decoding tables are built in the large loop below, the integer codes
     are incremented backwards.

     This routine assumes, but does not check, that all of the entries in
     lens[] are in the range 0..MAXBITS.  The caller must assure this.
     1..MAXBITS is interpreted as that code length.  zero means that that
     symbol does not occur in this code.

     The codes are sorted by computing a count of codes for each length,
     creating from that a table of starting indices for each length in the
     sorted table, and then entering the symbols in order in the sorted
     table.  The sorted table is work[], with that space being provided by
     the caller.

     The length counts are used for other purposes as well, i.e. finding
     the minimum and maximum length codes, determining if there are any
     codes at all, checking for a valid set of lengths, and looking ahead
     at length counts to determine sub-table sizes when building the
     decoding tables.
     */

    /* accumulate lengths for codes (assumes lens[] all in 0..MAXBITS) */
    for (len = 0; len <= MAXBITS; len++) {
      count[len] = 0;
    }
    for (sym = 0; sym < codes; sym++) {
      count[lens[lens_index + sym]]++;
    }

    /* bound code lengths, force root to be within code lengths */
    root = bits;
    for (max = MAXBITS; max >= 1; max--) {
      if (count[max] !== 0) { break; }
    }
    if (root > max) {
      root = max;
    }
    if (max === 0) {                     /* no symbols to code at all */
      //table.op[opts.table_index] = 64;  //here.op = (var char)64;    /* invalid code marker */
      //table.bits[opts.table_index] = 1;   //here.bits = (var char)1;
      //table.val[opts.table_index++] = 0;   //here.val = (var short)0;
      table[table_index++] = (1 << 24) | (64 << 16) | 0;


      //table.op[opts.table_index] = 64;
      //table.bits[opts.table_index] = 1;
      //table.val[opts.table_index++] = 0;
      table[table_index++] = (1 << 24) | (64 << 16) | 0;

      opts.bits = 1;
      return 0;     /* no symbols, but wait for decoding to report error */
    }
    for (min = 1; min < max; min++) {
      if (count[min] !== 0) { break; }
    }
    if (root < min) {
      root = min;
    }

    /* check for an over-subscribed or incomplete set of lengths */
    left = 1;
    for (len = 1; len <= MAXBITS; len++) {
      left <<= 1;
      left -= count[len];
      if (left < 0) {
        return -1;
      }        /* over-subscribed */
    }
    if (left > 0 && (type === CODES$1 || max !== 1)) {
      return -1;                      /* incomplete set */
    }

    /* generate offsets into symbol table for each length for sorting */
    offs[1] = 0;
    for (len = 1; len < MAXBITS; len++) {
      offs[len + 1] = offs[len] + count[len];
    }

    /* sort symbols by length, by symbol order within each length */
    for (sym = 0; sym < codes; sym++) {
      if (lens[lens_index + sym] !== 0) {
        work[offs[lens[lens_index + sym]]++] = sym;
      }
    }

    /*
     Create and fill in decoding tables.  In this loop, the table being
     filled is at next and has curr index bits.  The code being used is huff
     with length len.  That code is converted to an index by dropping drop
     bits off of the bottom.  For codes where len is less than drop + curr,
     those top drop + curr - len bits are incremented through all values to
     fill the table with replicated entries.

     root is the number of index bits for the root table.  When len exceeds
     root, sub-tables are created pointed to by the root entry with an index
     of the low root bits of huff.  This is saved in low to check for when a
     new sub-table should be started.  drop is zero when the root table is
     being filled, and drop is root when sub-tables are being filled.

     When a new sub-table is needed, it is necessary to look ahead in the
     code lengths to determine what size sub-table is needed.  The length
     counts are used for this, and so count[] is decremented as codes are
     entered in the tables.

     used keeps track of how many table entries have been allocated from the
     provided *table space.  It is checked for LENS and DIST tables against
     the constants ENOUGH_LENS and ENOUGH_DISTS to guard against changes in
     the initial root table size constants.  See the comments in inftrees.h
     for more information.

     sym increments through all symbols, and the loop terminates when
     all codes of length max, i.e. all codes, have been processed.  This
     routine permits incomplete codes, so another loop after this one fills
     in the rest of the decoding tables with invalid code markers.
     */

    /* set up for code type */
    // poor man optimization - use if-else instead of switch,
    // to avoid deopts in old v8
    if (type === CODES$1) {
      base = extra = work;    /* dummy value--not used */
      match = 20;

    } else if (type === LENS$1) {
      base = lbase;
      extra = lext;
      match = 257;

    } else {                    /* DISTS */
      base = dbase;
      extra = dext;
      match = 0;
    }

    /* initialize opts for loop */
    huff = 0;                   /* starting code */
    sym = 0;                    /* starting code symbol */
    len = min;                  /* starting code length */
    next = table_index;              /* current table to fill in */
    curr = root;                /* current table index bits */
    drop = 0;                   /* current bits to drop from code for index */
    low = -1;                   /* trigger new sub-table when len > root */
    used = 1 << root;          /* use root table entries */
    mask = used - 1;            /* mask for comparing low */

    /* check available table space */
    if ((type === LENS$1 && used > ENOUGH_LENS$1) ||
      (type === DISTS$1 && used > ENOUGH_DISTS$1)) {
      return 1;
    }

    /* process all codes and make table entries */
    for (;;) {
      /* create table entry */
      here_bits = len - drop;
      if (work[sym] + 1 < match) {
        here_op = 0;
        here_val = work[sym];
      }
      else if (work[sym] >= match) {
        here_op = extra[work[sym] - match];
        here_val = base[work[sym] - match];
      }
      else {
        here_op = 32 + 64;         /* end of block */
        here_val = 0;
      }

      /* replicate for those indices with low len bits equal to huff */
      incr = 1 << (len - drop);
      fill = 1 << curr;
      min = fill;                 /* save offset to next table */
      do {
        fill -= incr;
        table[next + (huff >> drop) + fill] = (here_bits << 24) | (here_op << 16) | here_val |0;
      } while (fill !== 0);

      /* backwards increment the len-bit code huff */
      incr = 1 << (len - 1);
      while (huff & incr) {
        incr >>= 1;
      }
      if (incr !== 0) {
        huff &= incr - 1;
        huff += incr;
      } else {
        huff = 0;
      }

      /* go to next symbol, update count, len */
      sym++;
      if (--count[len] === 0) {
        if (len === max) { break; }
        len = lens[lens_index + work[sym]];
      }

      /* create new sub-table if needed */
      if (len > root && (huff & mask) !== low) {
        /* if first time, transition to sub-tables */
        if (drop === 0) {
          drop = root;
        }

        /* increment past last table */
        next += min;            /* here min is 1 << curr */

        /* determine length of next table */
        curr = len - drop;
        left = 1 << curr;
        while (curr + drop < max) {
          left -= count[curr + drop];
          if (left <= 0) { break; }
          curr++;
          left <<= 1;
        }

        /* check for enough space */
        used += 1 << curr;
        if ((type === LENS$1 && used > ENOUGH_LENS$1) ||
          (type === DISTS$1 && used > ENOUGH_DISTS$1)) {
          return 1;
        }

        /* point entry in root table to sub-table */
        low = huff & mask;
        /*table.op[low] = curr;
        table.bits[low] = root;
        table.val[low] = next - opts.table_index;*/
        table[low] = (root << 24) | (curr << 16) | (next - table_index) |0;
      }
    }

    /* fill in remaining table entry if code is incomplete (guaranteed to have
     at most one remaining entry, since if the code is incomplete, the
     maximum code length that was allowed to get this far is one bit) */
    if (huff !== 0) {
      //table.op[next + huff] = 64;            /* invalid code marker */
      //table.bits[next + huff] = len - drop;
      //table.val[next + huff] = 0;
      table[next + huff] = ((len - drop) << 24) | (64 << 16) |0;
    }

    /* set return parameters */
    //opts.table_index += used;
    opts.bits = root;
    return 0;
  };


  var inftrees = inflate_table;

  // (C) 1995-2013 Jean-loup Gailly and Mark Adler
  // (C) 2014-2017 Vitaly Puzrin and Andrey Tupitsin
  //
  // This software is provided 'as-is', without any express or implied
  // warranty. In no event will the authors be held liable for any damages
  // arising from the use of this software.
  //
  // Permission is granted to anyone to use this software for any purpose,
  // including commercial applications, and to alter it and redistribute it
  // freely, subject to the following restrictions:
  //
  // 1. The origin of this software must not be misrepresented; you must not
  //   claim that you wrote the original software. If you use this software
  //   in a product, an acknowledgment in the product documentation would be
  //   appreciated but is not required.
  // 2. Altered source versions must be plainly marked as such, and must not be
  //   misrepresented as being the original software.
  // 3. This notice may not be removed or altered from any source distribution.

  var constants$1 = {

    /* Allowed flush values; see deflate() and inflate() below for details */
    Z_NO_FLUSH:         0,
    Z_PARTIAL_FLUSH:    1,
    Z_SYNC_FLUSH:       2,
    Z_FULL_FLUSH:       3,
    Z_FINISH:           4,
    Z_BLOCK:            5,
    Z_TREES:            6,

    /* Return codes for the compression/decompression functions. Negative values
    * are errors, positive values are used for special but normal events.
    */
    Z_OK:               0,
    Z_STREAM_END:       1,
    Z_NEED_DICT:        2,
    Z_ERRNO:           -1,
    Z_STREAM_ERROR:    -2,
    Z_DATA_ERROR:      -3,
    Z_MEM_ERROR:       -4,
    Z_BUF_ERROR:       -5,
    //Z_VERSION_ERROR: -6,

    /* compression levels */
    Z_NO_COMPRESSION:         0,
    Z_BEST_SPEED:             1,
    Z_BEST_COMPRESSION:       9,
    Z_DEFAULT_COMPRESSION:   -1,


    Z_FILTERED:               1,
    Z_HUFFMAN_ONLY:           2,
    Z_RLE:                    3,
    Z_FIXED:                  4,
    Z_DEFAULT_STRATEGY:       0,

    /* Possible values of the data_type field (though see inflate()) */
    Z_BINARY:                 0,
    Z_TEXT:                   1,
    //Z_ASCII:                1, // = Z_TEXT (deprecated)
    Z_UNKNOWN:                2,

    /* The deflate compression method */
    Z_DEFLATED:               8
    //Z_NULL:                 null // Use -1 or null inline, depending on var type
  };

  // (C) 1995-2013 Jean-loup Gailly and Mark Adler
  // (C) 2014-2017 Vitaly Puzrin and Andrey Tupitsin
  //
  // This software is provided 'as-is', without any express or implied
  // warranty. In no event will the authors be held liable for any damages
  // arising from the use of this software.
  //
  // Permission is granted to anyone to use this software for any purpose,
  // including commercial applications, and to alter it and redistribute it
  // freely, subject to the following restrictions:
  //
  // 1. The origin of this software must not be misrepresented; you must not
  //   claim that you wrote the original software. If you use this software
  //   in a product, an acknowledgment in the product documentation would be
  //   appreciated but is not required.
  // 2. Altered source versions must be plainly marked as such, and must not be
  //   misrepresented as being the original software.
  // 3. This notice may not be removed or altered from any source distribution.






  const CODES = 0;
  const LENS = 1;
  const DISTS = 2;

  /* Public constants ==========================================================*/
  /* ===========================================================================*/

  const {
    Z_FINISH: Z_FINISH$1, Z_BLOCK, Z_TREES,
    Z_OK: Z_OK$1, Z_STREAM_END: Z_STREAM_END$1, Z_NEED_DICT: Z_NEED_DICT$1, Z_STREAM_ERROR: Z_STREAM_ERROR$1, Z_DATA_ERROR: Z_DATA_ERROR$1, Z_MEM_ERROR: Z_MEM_ERROR$1, Z_BUF_ERROR,
    Z_DEFLATED
  } = constants$1;


  /* STATES ====================================================================*/
  /* ===========================================================================*/


  const    HEAD = 16180;       /* i: waiting for magic header */
  const    FLAGS = 16181;      /* i: waiting for method and flags (gzip) */
  const    TIME = 16182;       /* i: waiting for modification time (gzip) */
  const    OS = 16183;         /* i: waiting for extra flags and operating system (gzip) */
  const    EXLEN = 16184;      /* i: waiting for extra length (gzip) */
  const    EXTRA = 16185;      /* i: waiting for extra bytes (gzip) */
  const    NAME = 16186;       /* i: waiting for end of file name (gzip) */
  const    COMMENT = 16187;    /* i: waiting for end of comment (gzip) */
  const    HCRC = 16188;       /* i: waiting for header crc (gzip) */
  const    DICTID = 16189;    /* i: waiting for dictionary check value */
  const    DICT = 16190;      /* waiting for inflateSetDictionary() call */
  const        TYPE = 16191;      /* i: waiting for type bits, including last-flag bit */
  const        TYPEDO = 16192;    /* i: same, but skip check to exit inflate on new block */
  const        STORED = 16193;    /* i: waiting for stored size (length and complement) */
  const        COPY_ = 16194;     /* i/o: same as COPY below, but only first time in */
  const        COPY = 16195;      /* i/o: waiting for input or output to copy stored block */
  const        TABLE = 16196;     /* i: waiting for dynamic block table lengths */
  const        LENLENS = 16197;   /* i: waiting for code length code lengths */
  const        CODELENS = 16198;  /* i: waiting for length/lit and distance code lengths */
  const            LEN_ = 16199;      /* i: same as LEN below, but only first time in */
  const            LEN = 16200;       /* i: waiting for length/lit/eob code */
  const            LENEXT = 16201;    /* i: waiting for length extra bits */
  const            DIST = 16202;      /* i: waiting for distance code */
  const            DISTEXT = 16203;   /* i: waiting for distance extra bits */
  const            MATCH = 16204;     /* o: waiting for output space to copy string */
  const            LIT = 16205;       /* o: waiting for output space to write literal */
  const    CHECK = 16206;     /* i: waiting for 32-bit check value */
  const    LENGTH = 16207;    /* i: waiting for 32-bit length (gzip) */
  const    DONE = 16208;      /* finished check, done -- remain here until reset */
  const    BAD = 16209;       /* got a data error -- remain here until reset */
  const    MEM = 16210;       /* got an inflate() memory error -- remain here until reset */
  const    SYNC = 16211;      /* looking for synchronization bytes to restart inflate() */

  /* ===========================================================================*/



  const ENOUGH_LENS = 852;
  const ENOUGH_DISTS = 592;
  //const ENOUGH =  (ENOUGH_LENS+ENOUGH_DISTS);

  const MAX_WBITS = 15;
  /* 32K LZ77 window */
  const DEF_WBITS = MAX_WBITS;


  const zswap32 = (q) => {

    return  (((q >>> 24) & 0xff) +
            ((q >>> 8) & 0xff00) +
            ((q & 0xff00) << 8) +
            ((q & 0xff) << 24));
  };


  function InflateState() {
    this.strm = null;           /* pointer back to this zlib stream */
    this.mode = 0;              /* current inflate mode */
    this.last = false;          /* true if processing last block */
    this.wrap = 0;              /* bit 0 true for zlib, bit 1 true for gzip,
                                   bit 2 true to validate check value */
    this.havedict = false;      /* true if dictionary provided */
    this.flags = 0;             /* gzip header method and flags (0 if zlib), or
                                   -1 if raw or no header yet */
    this.dmax = 0;              /* zlib header max distance (INFLATE_STRICT) */
    this.check = 0;             /* protected copy of check value */
    this.total = 0;             /* protected copy of output count */
    // TODO: may be {}
    this.head = null;           /* where to save gzip header information */

    /* sliding window */
    this.wbits = 0;             /* log base 2 of requested window size */
    this.wsize = 0;             /* window size or zero if not using window */
    this.whave = 0;             /* valid bytes in the window */
    this.wnext = 0;             /* window write index */
    this.window = null;         /* allocated sliding window, if needed */

    /* bit accumulator */
    this.hold = 0;              /* input bit accumulator */
    this.bits = 0;              /* number of bits in "in" */

    /* for string and stored block copying */
    this.length = 0;            /* literal or length of data to copy */
    this.offset = 0;            /* distance back to copy string from */

    /* for table and code decoding */
    this.extra = 0;             /* extra bits needed */

    /* fixed and dynamic code tables */
    this.lencode = null;          /* starting table for length/literal codes */
    this.distcode = null;         /* starting table for distance codes */
    this.lenbits = 0;           /* index bits for lencode */
    this.distbits = 0;          /* index bits for distcode */

    /* dynamic table building */
    this.ncode = 0;             /* number of code length code lengths */
    this.nlen = 0;              /* number of length code lengths */
    this.ndist = 0;             /* number of distance code lengths */
    this.have = 0;              /* number of code lengths in lens[] */
    this.next = null;              /* next available space in codes[] */

    this.lens = new Uint16Array(320); /* temporary storage for code lengths */
    this.work = new Uint16Array(288); /* work area for code table building */

    /*
     because we don't have pointers in js, we use lencode and distcode directly
     as buffers so we don't need codes
    */
    //this.codes = new Int32Array(ENOUGH);       /* space for code tables */
    this.lendyn = null;              /* dynamic table for length/literal codes (JS specific) */
    this.distdyn = null;             /* dynamic table for distance codes (JS specific) */
    this.sane = 0;                   /* if false, allow invalid distance too far */
    this.back = 0;                   /* bits back of last unprocessed length/lit */
    this.was = 0;                    /* initial length of match */
  }


  const inflateStateCheck = (strm) => {

    if (!strm) {
      return 1;
    }
    const state = strm.state;
    if (!state || state.strm !== strm ||
      state.mode < HEAD || state.mode > SYNC) {
      return 1;
    }
    return 0;
  };


  const inflateResetKeep = (strm) => {

    if (inflateStateCheck(strm)) { return Z_STREAM_ERROR$1; }
    const state = strm.state;
    strm.total_in = strm.total_out = state.total = 0;
    strm.msg = ''; /*Z_NULL*/
    if (state.wrap) {       /* to support ill-conceived Java test suite */
      strm.adler = state.wrap & 1;
    }
    state.mode = HEAD;
    state.last = 0;
    state.havedict = 0;
    state.flags = -1;
    state.dmax = 32768;
    state.head = null/*Z_NULL*/;
    state.hold = 0;
    state.bits = 0;
    //state.lencode = state.distcode = state.next = state.codes;
    state.lencode = state.lendyn = new Int32Array(ENOUGH_LENS);
    state.distcode = state.distdyn = new Int32Array(ENOUGH_DISTS);

    state.sane = 1;
    state.back = -1;
    //Tracev((stderr, "inflate: reset\n"));
    return Z_OK$1;
  };


  const inflateReset = (strm) => {

    if (inflateStateCheck(strm)) { return Z_STREAM_ERROR$1; }
    const state = strm.state;
    state.wsize = 0;
    state.whave = 0;
    state.wnext = 0;
    return inflateResetKeep(strm);

  };


  const inflateReset2 = (strm, windowBits) => {
    let wrap;

    /* get the state */
    if (inflateStateCheck(strm)) { return Z_STREAM_ERROR$1; }
    const state = strm.state;

    /* extract wrap request from windowBits parameter */
    if (windowBits < 0) {
      wrap = 0;
      windowBits = -windowBits;
    }
    else {
      wrap = (windowBits >> 4) + 5;
      if (windowBits < 48) {
        windowBits &= 15;
      }
    }

    /* set number of window bits, free window if different */
    if (windowBits && (windowBits < 8 || windowBits > 15)) {
      return Z_STREAM_ERROR$1;
    }
    if (state.window !== null && state.wbits !== windowBits) {
      state.window = null;
    }

    /* update state and reset the rest of it */
    state.wrap = wrap;
    state.wbits = windowBits;
    return inflateReset(strm);
  };


  const inflateInit2 = (strm, windowBits) => {

    if (!strm) { return Z_STREAM_ERROR$1; }
    //strm.msg = Z_NULL;                 /* in case we return an error */

    const state = new InflateState();

    //if (state === Z_NULL) return Z_MEM_ERROR;
    //Tracev((stderr, "inflate: allocated\n"));
    strm.state = state;
    state.strm = strm;
    state.window = null/*Z_NULL*/;
    state.mode = HEAD;     /* to pass state test in inflateReset2() */
    const ret = inflateReset2(strm, windowBits);
    if (ret !== Z_OK$1) {
      strm.state = null/*Z_NULL*/;
    }
    return ret;
  };


  const inflateInit = (strm) => {

    return inflateInit2(strm, DEF_WBITS);
  };


  /*
   Return state with length and distance decoding tables and index sizes set to
   fixed code decoding.  Normally this returns fixed tables from inffixed.h.
   If BUILDFIXED is defined, then instead this routine builds the tables the
   first time it's called, and returns those tables the first time and
   thereafter.  This reduces the size of the code by about 2K bytes, in
   exchange for a little execution time.  However, BUILDFIXED should not be
   used for threaded applications, since the rewriting of the tables and virgin
   may not be thread-safe.
   */
  let virgin = true;

  let lenfix, distfix; // We have no pointers in JS, so keep tables separate


  const fixedtables = (state) => {

    /* build fixed huffman tables if first call (may not be thread safe) */
    if (virgin) {
      lenfix = new Int32Array(512);
      distfix = new Int32Array(32);

      /* literal/length table */
      let sym = 0;
      while (sym < 144) { state.lens[sym++] = 8; }
      while (sym < 256) { state.lens[sym++] = 9; }
      while (sym < 280) { state.lens[sym++] = 7; }
      while (sym < 288) { state.lens[sym++] = 8; }

      inftrees(LENS,  state.lens, 0, 288, lenfix,   0, state.work, { bits: 9 });

      /* distance table */
      sym = 0;
      while (sym < 32) { state.lens[sym++] = 5; }

      inftrees(DISTS, state.lens, 0, 32,   distfix, 0, state.work, { bits: 5 });

      /* do this just once */
      virgin = false;
    }

    state.lencode = lenfix;
    state.lenbits = 9;
    state.distcode = distfix;
    state.distbits = 5;
  };


  /*
   Update the window with the last wsize (normally 32K) bytes written before
   returning.  If window does not exist yet, create it.  This is only called
   when a window is already in use, or when output has been written during this
   inflate call, but the end of the deflate stream has not been reached yet.
   It is also called to create a window for dictionary data when a dictionary
   is loaded.

   Providing output buffers larger than 32K to inflate() should provide a speed
   advantage, since only the last 32K of output is copied to the sliding window
   upon return from inflate(), and since all distances after the first 32K of
   output will fall in the output data, making match copies simpler and faster.
   The advantage may be dependent on the size of the processor's data caches.
   */
  const updatewindow = (strm, src, end, copy) => {

    let dist;
    const state = strm.state;

    /* if it hasn't been done already, allocate space for the window */
    if (state.window === null) {
      state.wsize = 1 << state.wbits;
      state.wnext = 0;
      state.whave = 0;

      state.window = new Uint8Array(state.wsize);
    }

    /* copy state->wsize or less output bytes into the circular window */
    if (copy >= state.wsize) {
      state.window.set(src.subarray(end - state.wsize, end), 0);
      state.wnext = 0;
      state.whave = state.wsize;
    }
    else {
      dist = state.wsize - state.wnext;
      if (dist > copy) {
        dist = copy;
      }
      //zmemcpy(state->window + state->wnext, end - copy, dist);
      state.window.set(src.subarray(end - copy, end - copy + dist), state.wnext);
      copy -= dist;
      if (copy) {
        //zmemcpy(state->window, end - copy, copy);
        state.window.set(src.subarray(end - copy, end), 0);
        state.wnext = copy;
        state.whave = state.wsize;
      }
      else {
        state.wnext += dist;
        if (state.wnext === state.wsize) { state.wnext = 0; }
        if (state.whave < state.wsize) { state.whave += dist; }
      }
    }
    return 0;
  };


  const inflate$1 = (strm, flush) => {

    let state;
    let input, output;          // input/output buffers
    let next;                   /* next input INDEX */
    let put;                    /* next output INDEX */
    let have, left;             /* available input and output */
    let hold;                   /* bit buffer */
    let bits;                   /* bits in bit buffer */
    let _in, _out;              /* save starting available input and output */
    let copy;                   /* number of stored or match bytes to copy */
    let from;                   /* where to copy match bytes from */
    let from_source;
    let here = 0;               /* current decoding table entry */
    let here_bits, here_op, here_val; // paked "here" denormalized (JS specific)
    //let last;                   /* parent table entry */
    let last_bits, last_op, last_val; // paked "last" denormalized (JS specific)
    let len;                    /* length to copy for repeats, bits to drop */
    let ret;                    /* return code */
    const hbuf = new Uint8Array(4);    /* buffer for gzip header crc calculation */
    let opts;

    let n; // temporary variable for NEED_BITS

    const order = /* permutation of code lengths */
      new Uint8Array([ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 ]);


    if (inflateStateCheck(strm) || !strm.output ||
        (!strm.input && strm.avail_in !== 0)) {
      return Z_STREAM_ERROR$1;
    }

    state = strm.state;
    if (state.mode === TYPE) { state.mode = TYPEDO; }    /* skip check */


    //--- LOAD() ---
    put = strm.next_out;
    output = strm.output;
    left = strm.avail_out;
    next = strm.next_in;
    input = strm.input;
    have = strm.avail_in;
    hold = state.hold;
    bits = state.bits;
    //---

    _in = have;
    _out = left;
    ret = Z_OK$1;

    inf_leave: // goto emulation
    for (;;) {
      switch (state.mode) {
        case HEAD:
          if (state.wrap === 0) {
            state.mode = TYPEDO;
            break;
          }
          //=== NEEDBITS(16);
          while (bits < 16) {
            if (have === 0) { break inf_leave; }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          //===//
          if ((state.wrap & 2) && hold === 0x8b1f) {  /* gzip header */
            if (state.wbits === 0) {
              state.wbits = 15;
            }
            state.check = 0/*crc32(0L, Z_NULL, 0)*/;
            //=== CRC2(state.check, hold);
            hbuf[0] = hold & 0xff;
            hbuf[1] = (hold >>> 8) & 0xff;
            state.check = crc32_1(state.check, hbuf, 2, 0);
            //===//

            //=== INITBITS();
            hold = 0;
            bits = 0;
            //===//
            state.mode = FLAGS;
            break;
          }
          if (state.head) {
            state.head.done = false;
          }
          if (!(state.wrap & 1) ||   /* check if zlib header allowed */
            (((hold & 0xff)/*BITS(8)*/ << 8) + (hold >> 8)) % 31) {
            strm.msg = 'incorrect header check';
            state.mode = BAD;
            break;
          }
          if ((hold & 0x0f)/*BITS(4)*/ !== Z_DEFLATED) {
            strm.msg = 'unknown compression method';
            state.mode = BAD;
            break;
          }
          //--- DROPBITS(4) ---//
          hold >>>= 4;
          bits -= 4;
          //---//
          len = (hold & 0x0f)/*BITS(4)*/ + 8;
          if (state.wbits === 0) {
            state.wbits = len;
          }
          if (len > 15 || len > state.wbits) {
            strm.msg = 'invalid window size';
            state.mode = BAD;
            break;
          }

          // !!! pako patch. Force use `options.windowBits` if passed.
          // Required to always use max window size by default.
          state.dmax = 1 << state.wbits;
          //state.dmax = 1 << len;

          state.flags = 0;               /* indicate zlib header */
          //Tracev((stderr, "inflate:   zlib header ok\n"));
          strm.adler = state.check = 1/*adler32(0L, Z_NULL, 0)*/;
          state.mode = hold & 0x200 ? DICTID : TYPE;
          //=== INITBITS();
          hold = 0;
          bits = 0;
          //===//
          break;
        case FLAGS:
          //=== NEEDBITS(16); */
          while (bits < 16) {
            if (have === 0) { break inf_leave; }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          //===//
          state.flags = hold;
          if ((state.flags & 0xff) !== Z_DEFLATED) {
            strm.msg = 'unknown compression method';
            state.mode = BAD;
            break;
          }
          if (state.flags & 0xe000) {
            strm.msg = 'unknown header flags set';
            state.mode = BAD;
            break;
          }
          if (state.head) {
            state.head.text = ((hold >> 8) & 1);
          }
          if ((state.flags & 0x0200) && (state.wrap & 4)) {
            //=== CRC2(state.check, hold);
            hbuf[0] = hold & 0xff;
            hbuf[1] = (hold >>> 8) & 0xff;
            state.check = crc32_1(state.check, hbuf, 2, 0);
            //===//
          }
          //=== INITBITS();
          hold = 0;
          bits = 0;
          //===//
          state.mode = TIME;
          /* falls through */
        case TIME:
          //=== NEEDBITS(32); */
          while (bits < 32) {
            if (have === 0) { break inf_leave; }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          //===//
          if (state.head) {
            state.head.time = hold;
          }
          if ((state.flags & 0x0200) && (state.wrap & 4)) {
            //=== CRC4(state.check, hold)
            hbuf[0] = hold & 0xff;
            hbuf[1] = (hold >>> 8) & 0xff;
            hbuf[2] = (hold >>> 16) & 0xff;
            hbuf[3] = (hold >>> 24) & 0xff;
            state.check = crc32_1(state.check, hbuf, 4, 0);
            //===
          }
          //=== INITBITS();
          hold = 0;
          bits = 0;
          //===//
          state.mode = OS;
          /* falls through */
        case OS:
          //=== NEEDBITS(16); */
          while (bits < 16) {
            if (have === 0) { break inf_leave; }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          //===//
          if (state.head) {
            state.head.xflags = (hold & 0xff);
            state.head.os = (hold >> 8);
          }
          if ((state.flags & 0x0200) && (state.wrap & 4)) {
            //=== CRC2(state.check, hold);
            hbuf[0] = hold & 0xff;
            hbuf[1] = (hold >>> 8) & 0xff;
            state.check = crc32_1(state.check, hbuf, 2, 0);
            //===//
          }
          //=== INITBITS();
          hold = 0;
          bits = 0;
          //===//
          state.mode = EXLEN;
          /* falls through */
        case EXLEN:
          if (state.flags & 0x0400) {
            //=== NEEDBITS(16); */
            while (bits < 16) {
              if (have === 0) { break inf_leave; }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            //===//
            state.length = hold;
            if (state.head) {
              state.head.extra_len = hold;
            }
            if ((state.flags & 0x0200) && (state.wrap & 4)) {
              //=== CRC2(state.check, hold);
              hbuf[0] = hold & 0xff;
              hbuf[1] = (hold >>> 8) & 0xff;
              state.check = crc32_1(state.check, hbuf, 2, 0);
              //===//
            }
            //=== INITBITS();
            hold = 0;
            bits = 0;
            //===//
          }
          else if (state.head) {
            state.head.extra = null/*Z_NULL*/;
          }
          state.mode = EXTRA;
          /* falls through */
        case EXTRA:
          if (state.flags & 0x0400) {
            copy = state.length;
            if (copy > have) { copy = have; }
            if (copy) {
              if (state.head) {
                len = state.head.extra_len - state.length;
                if (!state.head.extra) {
                  // Use untyped array for more convenient processing later
                  state.head.extra = new Uint8Array(state.head.extra_len);
                }
                state.head.extra.set(
                  input.subarray(
                    next,
                    // extra field is limited to 65536 bytes
                    // - no need for additional size check
                    next + copy
                  ),
                  /*len + copy > state.head.extra_max - len ? state.head.extra_max : copy,*/
                  len
                );
                //zmemcpy(state.head.extra + len, next,
                //        len + copy > state.head.extra_max ?
                //        state.head.extra_max - len : copy);
              }
              if ((state.flags & 0x0200) && (state.wrap & 4)) {
                state.check = crc32_1(state.check, input, copy, next);
              }
              have -= copy;
              next += copy;
              state.length -= copy;
            }
            if (state.length) { break inf_leave; }
          }
          state.length = 0;
          state.mode = NAME;
          /* falls through */
        case NAME:
          if (state.flags & 0x0800) {
            if (have === 0) { break inf_leave; }
            copy = 0;
            do {
              // TODO: 2 or 1 bytes?
              len = input[next + copy++];
              /* use constant limit because in js we should not preallocate memory */
              if (state.head && len &&
                  (state.length < 65536 /*state.head.name_max*/)) {
                state.head.name += String.fromCharCode(len);
              }
            } while (len && copy < have);

            if ((state.flags & 0x0200) && (state.wrap & 4)) {
              state.check = crc32_1(state.check, input, copy, next);
            }
            have -= copy;
            next += copy;
            if (len) { break inf_leave; }
          }
          else if (state.head) {
            state.head.name = null;
          }
          state.length = 0;
          state.mode = COMMENT;
          /* falls through */
        case COMMENT:
          if (state.flags & 0x1000) {
            if (have === 0) { break inf_leave; }
            copy = 0;
            do {
              len = input[next + copy++];
              /* use constant limit because in js we should not preallocate memory */
              if (state.head && len &&
                  (state.length < 65536 /*state.head.comm_max*/)) {
                state.head.comment += String.fromCharCode(len);
              }
            } while (len && copy < have);
            if ((state.flags & 0x0200) && (state.wrap & 4)) {
              state.check = crc32_1(state.check, input, copy, next);
            }
            have -= copy;
            next += copy;
            if (len) { break inf_leave; }
          }
          else if (state.head) {
            state.head.comment = null;
          }
          state.mode = HCRC;
          /* falls through */
        case HCRC:
          if (state.flags & 0x0200) {
            //=== NEEDBITS(16); */
            while (bits < 16) {
              if (have === 0) { break inf_leave; }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            //===//
            if ((state.wrap & 4) && hold !== (state.check & 0xffff)) {
              strm.msg = 'header crc mismatch';
              state.mode = BAD;
              break;
            }
            //=== INITBITS();
            hold = 0;
            bits = 0;
            //===//
          }
          if (state.head) {
            state.head.hcrc = ((state.flags >> 9) & 1);
            state.head.done = true;
          }
          strm.adler = state.check = 0;
          state.mode = TYPE;
          break;
        case DICTID:
          //=== NEEDBITS(32); */
          while (bits < 32) {
            if (have === 0) { break inf_leave; }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          //===//
          strm.adler = state.check = zswap32(hold);
          //=== INITBITS();
          hold = 0;
          bits = 0;
          //===//
          state.mode = DICT;
          /* falls through */
        case DICT:
          if (state.havedict === 0) {
            //--- RESTORE() ---
            strm.next_out = put;
            strm.avail_out = left;
            strm.next_in = next;
            strm.avail_in = have;
            state.hold = hold;
            state.bits = bits;
            //---
            return Z_NEED_DICT$1;
          }
          strm.adler = state.check = 1/*adler32(0L, Z_NULL, 0)*/;
          state.mode = TYPE;
          /* falls through */
        case TYPE:
          if (flush === Z_BLOCK || flush === Z_TREES) { break inf_leave; }
          /* falls through */
        case TYPEDO:
          if (state.last) {
            //--- BYTEBITS() ---//
            hold >>>= bits & 7;
            bits -= bits & 7;
            //---//
            state.mode = CHECK;
            break;
          }
          //=== NEEDBITS(3); */
          while (bits < 3) {
            if (have === 0) { break inf_leave; }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          //===//
          state.last = (hold & 0x01)/*BITS(1)*/;
          //--- DROPBITS(1) ---//
          hold >>>= 1;
          bits -= 1;
          //---//

          switch ((hold & 0x03)/*BITS(2)*/) {
            case 0:                             /* stored block */
              //Tracev((stderr, "inflate:     stored block%s\n",
              //        state.last ? " (last)" : ""));
              state.mode = STORED;
              break;
            case 1:                             /* fixed block */
              fixedtables(state);
              //Tracev((stderr, "inflate:     fixed codes block%s\n",
              //        state.last ? " (last)" : ""));
              state.mode = LEN_;             /* decode codes */
              if (flush === Z_TREES) {
                //--- DROPBITS(2) ---//
                hold >>>= 2;
                bits -= 2;
                //---//
                break inf_leave;
              }
              break;
            case 2:                             /* dynamic block */
              //Tracev((stderr, "inflate:     dynamic codes block%s\n",
              //        state.last ? " (last)" : ""));
              state.mode = TABLE;
              break;
            case 3:
              strm.msg = 'invalid block type';
              state.mode = BAD;
          }
          //--- DROPBITS(2) ---//
          hold >>>= 2;
          bits -= 2;
          //---//
          break;
        case STORED:
          //--- BYTEBITS() ---// /* go to byte boundary */
          hold >>>= bits & 7;
          bits -= bits & 7;
          //---//
          //=== NEEDBITS(32); */
          while (bits < 32) {
            if (have === 0) { break inf_leave; }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          //===//
          if ((hold & 0xffff) !== ((hold >>> 16) ^ 0xffff)) {
            strm.msg = 'invalid stored block lengths';
            state.mode = BAD;
            break;
          }
          state.length = hold & 0xffff;
          //Tracev((stderr, "inflate:       stored length %u\n",
          //        state.length));
          //=== INITBITS();
          hold = 0;
          bits = 0;
          //===//
          state.mode = COPY_;
          if (flush === Z_TREES) { break inf_leave; }
          /* falls through */
        case COPY_:
          state.mode = COPY;
          /* falls through */
        case COPY:
          copy = state.length;
          if (copy) {
            if (copy > have) { copy = have; }
            if (copy > left) { copy = left; }
            if (copy === 0) { break inf_leave; }
            //--- zmemcpy(put, next, copy); ---
            output.set(input.subarray(next, next + copy), put);
            //---//
            have -= copy;
            next += copy;
            left -= copy;
            put += copy;
            state.length -= copy;
            break;
          }
          //Tracev((stderr, "inflate:       stored end\n"));
          state.mode = TYPE;
          break;
        case TABLE:
          //=== NEEDBITS(14); */
          while (bits < 14) {
            if (have === 0) { break inf_leave; }
            have--;
            hold += input[next++] << bits;
            bits += 8;
          }
          //===//
          state.nlen = (hold & 0x1f)/*BITS(5)*/ + 257;
          //--- DROPBITS(5) ---//
          hold >>>= 5;
          bits -= 5;
          //---//
          state.ndist = (hold & 0x1f)/*BITS(5)*/ + 1;
          //--- DROPBITS(5) ---//
          hold >>>= 5;
          bits -= 5;
          //---//
          state.ncode = (hold & 0x0f)/*BITS(4)*/ + 4;
          //--- DROPBITS(4) ---//
          hold >>>= 4;
          bits -= 4;
          //---//
  //#ifndef PKZIP_BUG_WORKAROUND
          if (state.nlen > 286 || state.ndist > 30) {
            strm.msg = 'too many length or distance symbols';
            state.mode = BAD;
            break;
          }
  //#endif
          //Tracev((stderr, "inflate:       table sizes ok\n"));
          state.have = 0;
          state.mode = LENLENS;
          /* falls through */
        case LENLENS:
          while (state.have < state.ncode) {
            //=== NEEDBITS(3);
            while (bits < 3) {
              if (have === 0) { break inf_leave; }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            //===//
            state.lens[order[state.have++]] = (hold & 0x07);//BITS(3);
            //--- DROPBITS(3) ---//
            hold >>>= 3;
            bits -= 3;
            //---//
          }
          while (state.have < 19) {
            state.lens[order[state.have++]] = 0;
          }
          // We have separate tables & no pointers. 2 commented lines below not needed.
          //state.next = state.codes;
          //state.lencode = state.next;
          // Switch to use dynamic table
          state.lencode = state.lendyn;
          state.lenbits = 7;

          opts = { bits: state.lenbits };
          ret = inftrees(CODES, state.lens, 0, 19, state.lencode, 0, state.work, opts);
          state.lenbits = opts.bits;

          if (ret) {
            strm.msg = 'invalid code lengths set';
            state.mode = BAD;
            break;
          }
          //Tracev((stderr, "inflate:       code lengths ok\n"));
          state.have = 0;
          state.mode = CODELENS;
          /* falls through */
        case CODELENS:
          while (state.have < state.nlen + state.ndist) {
            for (;;) {
              here = state.lencode[hold & ((1 << state.lenbits) - 1)];/*BITS(state.lenbits)*/
              here_bits = here >>> 24;
              here_op = (here >>> 16) & 0xff;
              here_val = here & 0xffff;

              if ((here_bits) <= bits) { break; }
              //--- PULLBYTE() ---//
              if (have === 0) { break inf_leave; }
              have--;
              hold += input[next++] << bits;
              bits += 8;
              //---//
            }
            if (here_val < 16) {
              //--- DROPBITS(here.bits) ---//
              hold >>>= here_bits;
              bits -= here_bits;
              //---//
              state.lens[state.have++] = here_val;
            }
            else {
              if (here_val === 16) {
                //=== NEEDBITS(here.bits + 2);
                n = here_bits + 2;
                while (bits < n) {
                  if (have === 0) { break inf_leave; }
                  have--;
                  hold += input[next++] << bits;
                  bits += 8;
                }
                //===//
                //--- DROPBITS(here.bits) ---//
                hold >>>= here_bits;
                bits -= here_bits;
                //---//
                if (state.have === 0) {
                  strm.msg = 'invalid bit length repeat';
                  state.mode = BAD;
                  break;
                }
                len = state.lens[state.have - 1];
                copy = 3 + (hold & 0x03);//BITS(2);
                //--- DROPBITS(2) ---//
                hold >>>= 2;
                bits -= 2;
                //---//
              }
              else if (here_val === 17) {
                //=== NEEDBITS(here.bits + 3);
                n = here_bits + 3;
                while (bits < n) {
                  if (have === 0) { break inf_leave; }
                  have--;
                  hold += input[next++] << bits;
                  bits += 8;
                }
                //===//
                //--- DROPBITS(here.bits) ---//
                hold >>>= here_bits;
                bits -= here_bits;
                //---//
                len = 0;
                copy = 3 + (hold & 0x07);//BITS(3);
                //--- DROPBITS(3) ---//
                hold >>>= 3;
                bits -= 3;
                //---//
              }
              else {
                //=== NEEDBITS(here.bits + 7);
                n = here_bits + 7;
                while (bits < n) {
                  if (have === 0) { break inf_leave; }
                  have--;
                  hold += input[next++] << bits;
                  bits += 8;
                }
                //===//
                //--- DROPBITS(here.bits) ---//
                hold >>>= here_bits;
                bits -= here_bits;
                //---//
                len = 0;
                copy = 11 + (hold & 0x7f);//BITS(7);
                //--- DROPBITS(7) ---//
                hold >>>= 7;
                bits -= 7;
                //---//
              }
              if (state.have + copy > state.nlen + state.ndist) {
                strm.msg = 'invalid bit length repeat';
                state.mode = BAD;
                break;
              }
              while (copy--) {
                state.lens[state.have++] = len;
              }
            }
          }

          /* handle error breaks in while */
          if (state.mode === BAD) { break; }

          /* check for end-of-block code (better have one) */
          if (state.lens[256] === 0) {
            strm.msg = 'invalid code -- missing end-of-block';
            state.mode = BAD;
            break;
          }

          /* build code tables -- note: do not change the lenbits or distbits
             values here (9 and 6) without reading the comments in inftrees.h
             concerning the ENOUGH constants, which depend on those values */
          state.lenbits = 9;

          opts = { bits: state.lenbits };
          ret = inftrees(LENS, state.lens, 0, state.nlen, state.lencode, 0, state.work, opts);
          // We have separate tables & no pointers. 2 commented lines below not needed.
          // state.next_index = opts.table_index;
          state.lenbits = opts.bits;
          // state.lencode = state.next;

          if (ret) {
            strm.msg = 'invalid literal/lengths set';
            state.mode = BAD;
            break;
          }

          state.distbits = 6;
          //state.distcode.copy(state.codes);
          // Switch to use dynamic table
          state.distcode = state.distdyn;
          opts = { bits: state.distbits };
          ret = inftrees(DISTS, state.lens, state.nlen, state.ndist, state.distcode, 0, state.work, opts);
          // We have separate tables & no pointers. 2 commented lines below not needed.
          // state.next_index = opts.table_index;
          state.distbits = opts.bits;
          // state.distcode = state.next;

          if (ret) {
            strm.msg = 'invalid distances set';
            state.mode = BAD;
            break;
          }
          //Tracev((stderr, 'inflate:       codes ok\n'));
          state.mode = LEN_;
          if (flush === Z_TREES) { break inf_leave; }
          /* falls through */
        case LEN_:
          state.mode = LEN;
          /* falls through */
        case LEN:
          if (have >= 6 && left >= 258) {
            //--- RESTORE() ---
            strm.next_out = put;
            strm.avail_out = left;
            strm.next_in = next;
            strm.avail_in = have;
            state.hold = hold;
            state.bits = bits;
            //---
            inffast(strm, _out);
            //--- LOAD() ---
            put = strm.next_out;
            output = strm.output;
            left = strm.avail_out;
            next = strm.next_in;
            input = strm.input;
            have = strm.avail_in;
            hold = state.hold;
            bits = state.bits;
            //---

            if (state.mode === TYPE) {
              state.back = -1;
            }
            break;
          }
          state.back = 0;
          for (;;) {
            here = state.lencode[hold & ((1 << state.lenbits) - 1)];  /*BITS(state.lenbits)*/
            here_bits = here >>> 24;
            here_op = (here >>> 16) & 0xff;
            here_val = here & 0xffff;

            if (here_bits <= bits) { break; }
            //--- PULLBYTE() ---//
            if (have === 0) { break inf_leave; }
            have--;
            hold += input[next++] << bits;
            bits += 8;
            //---//
          }
          if (here_op && (here_op & 0xf0) === 0) {
            last_bits = here_bits;
            last_op = here_op;
            last_val = here_val;
            for (;;) {
              here = state.lencode[last_val +
                      ((hold & ((1 << (last_bits + last_op)) - 1))/*BITS(last.bits + last.op)*/ >> last_bits)];
              here_bits = here >>> 24;
              here_op = (here >>> 16) & 0xff;
              here_val = here & 0xffff;

              if ((last_bits + here_bits) <= bits) { break; }
              //--- PULLBYTE() ---//
              if (have === 0) { break inf_leave; }
              have--;
              hold += input[next++] << bits;
              bits += 8;
              //---//
            }
            //--- DROPBITS(last.bits) ---//
            hold >>>= last_bits;
            bits -= last_bits;
            //---//
            state.back += last_bits;
          }
          //--- DROPBITS(here.bits) ---//
          hold >>>= here_bits;
          bits -= here_bits;
          //---//
          state.back += here_bits;
          state.length = here_val;
          if (here_op === 0) {
            //Tracevv((stderr, here.val >= 0x20 && here.val < 0x7f ?
            //        "inflate:         literal '%c'\n" :
            //        "inflate:         literal 0x%02x\n", here.val));
            state.mode = LIT;
            break;
          }
          if (here_op & 32) {
            //Tracevv((stderr, "inflate:         end of block\n"));
            state.back = -1;
            state.mode = TYPE;
            break;
          }
          if (here_op & 64) {
            strm.msg = 'invalid literal/length code';
            state.mode = BAD;
            break;
          }
          state.extra = here_op & 15;
          state.mode = LENEXT;
          /* falls through */
        case LENEXT:
          if (state.extra) {
            //=== NEEDBITS(state.extra);
            n = state.extra;
            while (bits < n) {
              if (have === 0) { break inf_leave; }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            //===//
            state.length += hold & ((1 << state.extra) - 1)/*BITS(state.extra)*/;
            //--- DROPBITS(state.extra) ---//
            hold >>>= state.extra;
            bits -= state.extra;
            //---//
            state.back += state.extra;
          }
          //Tracevv((stderr, "inflate:         length %u\n", state.length));
          state.was = state.length;
          state.mode = DIST;
          /* falls through */
        case DIST:
          for (;;) {
            here = state.distcode[hold & ((1 << state.distbits) - 1)];/*BITS(state.distbits)*/
            here_bits = here >>> 24;
            here_op = (here >>> 16) & 0xff;
            here_val = here & 0xffff;

            if ((here_bits) <= bits) { break; }
            //--- PULLBYTE() ---//
            if (have === 0) { break inf_leave; }
            have--;
            hold += input[next++] << bits;
            bits += 8;
            //---//
          }
          if ((here_op & 0xf0) === 0) {
            last_bits = here_bits;
            last_op = here_op;
            last_val = here_val;
            for (;;) {
              here = state.distcode[last_val +
                      ((hold & ((1 << (last_bits + last_op)) - 1))/*BITS(last.bits + last.op)*/ >> last_bits)];
              here_bits = here >>> 24;
              here_op = (here >>> 16) & 0xff;
              here_val = here & 0xffff;

              if ((last_bits + here_bits) <= bits) { break; }
              //--- PULLBYTE() ---//
              if (have === 0) { break inf_leave; }
              have--;
              hold += input[next++] << bits;
              bits += 8;
              //---//
            }
            //--- DROPBITS(last.bits) ---//
            hold >>>= last_bits;
            bits -= last_bits;
            //---//
            state.back += last_bits;
          }
          //--- DROPBITS(here.bits) ---//
          hold >>>= here_bits;
          bits -= here_bits;
          //---//
          state.back += here_bits;
          if (here_op & 64) {
            strm.msg = 'invalid distance code';
            state.mode = BAD;
            break;
          }
          state.offset = here_val;
          state.extra = (here_op) & 15;
          state.mode = DISTEXT;
          /* falls through */
        case DISTEXT:
          if (state.extra) {
            //=== NEEDBITS(state.extra);
            n = state.extra;
            while (bits < n) {
              if (have === 0) { break inf_leave; }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            //===//
            state.offset += hold & ((1 << state.extra) - 1)/*BITS(state.extra)*/;
            //--- DROPBITS(state.extra) ---//
            hold >>>= state.extra;
            bits -= state.extra;
            //---//
            state.back += state.extra;
          }
  //#ifdef INFLATE_STRICT
          if (state.offset > state.dmax) {
            strm.msg = 'invalid distance too far back';
            state.mode = BAD;
            break;
          }
  //#endif
          //Tracevv((stderr, "inflate:         distance %u\n", state.offset));
          state.mode = MATCH;
          /* falls through */
        case MATCH:
          if (left === 0) { break inf_leave; }
          copy = _out - left;
          if (state.offset > copy) {         /* copy from window */
            copy = state.offset - copy;
            if (copy > state.whave) {
              if (state.sane) {
                strm.msg = 'invalid distance too far back';
                state.mode = BAD;
                break;
              }
  // (!) This block is disabled in zlib defaults,
  // don't enable it for binary compatibility
  //#ifdef INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR_ARRR
  //          Trace((stderr, "inflate.c too far\n"));
  //          copy -= state.whave;
  //          if (copy > state.length) { copy = state.length; }
  //          if (copy > left) { copy = left; }
  //          left -= copy;
  //          state.length -= copy;
  //          do {
  //            output[put++] = 0;
  //          } while (--copy);
  //          if (state.length === 0) { state.mode = LEN; }
  //          break;
  //#endif
            }
            if (copy > state.wnext) {
              copy -= state.wnext;
              from = state.wsize - copy;
            }
            else {
              from = state.wnext - copy;
            }
            if (copy > state.length) { copy = state.length; }
            from_source = state.window;
          }
          else {                              /* copy from output */
            from_source = output;
            from = put - state.offset;
            copy = state.length;
          }
          if (copy > left) { copy = left; }
          left -= copy;
          state.length -= copy;
          do {
            output[put++] = from_source[from++];
          } while (--copy);
          if (state.length === 0) { state.mode = LEN; }
          break;
        case LIT:
          if (left === 0) { break inf_leave; }
          output[put++] = state.length;
          left--;
          state.mode = LEN;
          break;
        case CHECK:
          if (state.wrap) {
            //=== NEEDBITS(32);
            while (bits < 32) {
              if (have === 0) { break inf_leave; }
              have--;
              // Use '|' instead of '+' to make sure that result is signed
              hold |= input[next++] << bits;
              bits += 8;
            }
            //===//
            _out -= left;
            strm.total_out += _out;
            state.total += _out;
            if ((state.wrap & 4) && _out) {
              strm.adler = state.check =
                  /*UPDATE_CHECK(state.check, put - _out, _out);*/
                  (state.flags ? crc32_1(state.check, output, _out, put - _out) : adler32_1(state.check, output, _out, put - _out));

            }
            _out = left;
            // NB: crc32 stored as signed 32-bit int, zswap32 returns signed too
            if ((state.wrap & 4) && (state.flags ? hold : zswap32(hold)) !== state.check) {
              strm.msg = 'incorrect data check';
              state.mode = BAD;
              break;
            }
            //=== INITBITS();
            hold = 0;
            bits = 0;
            //===//
            //Tracev((stderr, "inflate:   check matches trailer\n"));
          }
          state.mode = LENGTH;
          /* falls through */
        case LENGTH:
          if (state.wrap && state.flags) {
            //=== NEEDBITS(32);
            while (bits < 32) {
              if (have === 0) { break inf_leave; }
              have--;
              hold += input[next++] << bits;
              bits += 8;
            }
            //===//
            if ((state.wrap & 4) && hold !== (state.total & 0xffffffff)) {
              strm.msg = 'incorrect length check';
              state.mode = BAD;
              break;
            }
            //=== INITBITS();
            hold = 0;
            bits = 0;
            //===//
            //Tracev((stderr, "inflate:   length matches trailer\n"));
          }
          state.mode = DONE;
          /* falls through */
        case DONE:
          ret = Z_STREAM_END$1;
          break inf_leave;
        case BAD:
          ret = Z_DATA_ERROR$1;
          break inf_leave;
        case MEM:
          return Z_MEM_ERROR$1;
        case SYNC:
          /* falls through */
        default:
          return Z_STREAM_ERROR$1;
      }
    }

    // inf_leave <- here is real place for "goto inf_leave", emulated via "break inf_leave"

    /*
       Return from inflate(), updating the total counts and the check value.
       If there was no progress during the inflate() call, return a buffer
       error.  Call updatewindow() to create and/or update the window state.
       Note: a memory error from inflate() is non-recoverable.
     */

    //--- RESTORE() ---
    strm.next_out = put;
    strm.avail_out = left;
    strm.next_in = next;
    strm.avail_in = have;
    state.hold = hold;
    state.bits = bits;
    //---

    if (state.wsize || (_out !== strm.avail_out && state.mode < BAD &&
                        (state.mode < CHECK || flush !== Z_FINISH$1))) {
      if (updatewindow(strm, strm.output, strm.next_out, _out - strm.avail_out)) ;
    }
    _in -= strm.avail_in;
    _out -= strm.avail_out;
    strm.total_in += _in;
    strm.total_out += _out;
    state.total += _out;
    if ((state.wrap & 4) && _out) {
      strm.adler = state.check = /*UPDATE_CHECK(state.check, strm.next_out - _out, _out);*/
        (state.flags ? crc32_1(state.check, output, _out, strm.next_out - _out) : adler32_1(state.check, output, _out, strm.next_out - _out));
    }
    strm.data_type = state.bits + (state.last ? 64 : 0) +
                      (state.mode === TYPE ? 128 : 0) +
                      (state.mode === LEN_ || state.mode === COPY_ ? 256 : 0);
    if (((_in === 0 && _out === 0) || flush === Z_FINISH$1) && ret === Z_OK$1) {
      ret = Z_BUF_ERROR;
    }
    return ret;
  };


  const inflateEnd = (strm) => {

    if (inflateStateCheck(strm)) {
      return Z_STREAM_ERROR$1;
    }

    let state = strm.state;
    if (state.window) {
      state.window = null;
    }
    strm.state = null;
    return Z_OK$1;
  };


  const inflateGetHeader = (strm, head) => {

    /* check state */
    if (inflateStateCheck(strm)) { return Z_STREAM_ERROR$1; }
    const state = strm.state;
    if ((state.wrap & 2) === 0) { return Z_STREAM_ERROR$1; }

    /* save header structure */
    state.head = head;
    head.done = false;
    return Z_OK$1;
  };


  const inflateSetDictionary = (strm, dictionary) => {
    const dictLength = dictionary.length;

    let state;
    let dictid;
    let ret;

    /* check state */
    if (inflateStateCheck(strm)) { return Z_STREAM_ERROR$1; }
    state = strm.state;

    if (state.wrap !== 0 && state.mode !== DICT) {
      return Z_STREAM_ERROR$1;
    }

    /* check for correct dictionary identifier */
    if (state.mode === DICT) {
      dictid = 1; /* adler32(0, null, 0)*/
      /* dictid = adler32(dictid, dictionary, dictLength); */
      dictid = adler32_1(dictid, dictionary, dictLength, 0);
      if (dictid !== state.check) {
        return Z_DATA_ERROR$1;
      }
    }
    /* copy dictionary to window using updatewindow(), which will amend the
     existing dictionary if appropriate */
    ret = updatewindow(strm, dictionary, dictLength, dictLength);
    if (ret) {
      state.mode = MEM;
      return Z_MEM_ERROR$1;
    }
    state.havedict = 1;
    // Tracev((stderr, "inflate:   dictionary set\n"));
    return Z_OK$1;
  };


  var inflateReset_1 = inflateReset;
  var inflateReset2_1 = inflateReset2;
  var inflateResetKeep_1 = inflateResetKeep;
  var inflateInit_1 = inflateInit;
  var inflateInit2_1 = inflateInit2;
  var inflate_2$1 = inflate$1;
  var inflateEnd_1 = inflateEnd;
  var inflateGetHeader_1 = inflateGetHeader;
  var inflateSetDictionary_1 = inflateSetDictionary;
  var inflateInfo = 'pako inflate (from Nodeca project)';

  /* Not implemented
  module.exports.inflateCodesUsed = inflateCodesUsed;
  module.exports.inflateCopy = inflateCopy;
  module.exports.inflateGetDictionary = inflateGetDictionary;
  module.exports.inflateMark = inflateMark;
  module.exports.inflatePrime = inflatePrime;
  module.exports.inflateSync = inflateSync;
  module.exports.inflateSyncPoint = inflateSyncPoint;
  module.exports.inflateUndermine = inflateUndermine;
  module.exports.inflateValidate = inflateValidate;
  */

  var inflate_1$1 = {
  	inflateReset: inflateReset_1,
  	inflateReset2: inflateReset2_1,
  	inflateResetKeep: inflateResetKeep_1,
  	inflateInit: inflateInit_1,
  	inflateInit2: inflateInit2_1,
  	inflate: inflate_2$1,
  	inflateEnd: inflateEnd_1,
  	inflateGetHeader: inflateGetHeader_1,
  	inflateSetDictionary: inflateSetDictionary_1,
  	inflateInfo: inflateInfo
  };

  const _has = (obj, key) => {
    return Object.prototype.hasOwnProperty.call(obj, key);
  };

  var assign = function (obj /*from1, from2, from3, ...*/) {
    const sources = Array.prototype.slice.call(arguments, 1);
    while (sources.length) {
      const source = sources.shift();
      if (!source) { continue; }

      if (typeof source !== 'object') {
        throw new TypeError(source + 'must be non-object');
      }

      for (const p in source) {
        if (_has(source, p)) {
          obj[p] = source[p];
        }
      }
    }

    return obj;
  };


  // Join array of chunks to single array.
  var flattenChunks = (chunks) => {
    // calculate data length
    let len = 0;

    for (let i = 0, l = chunks.length; i < l; i++) {
      len += chunks[i].length;
    }

    // join chunks
    const result = new Uint8Array(len);

    for (let i = 0, pos = 0, l = chunks.length; i < l; i++) {
      let chunk = chunks[i];
      result.set(chunk, pos);
      pos += chunk.length;
    }

    return result;
  };

  var common = {
  	assign: assign,
  	flattenChunks: flattenChunks
  };

  // String encode/decode helpers


  // Quick check if we can use fast array to bin string conversion
  //
  // - apply(Array) can fail on Android 2.2
  // - apply(Uint8Array) can fail on iOS 5.1 Safari
  //
  let STR_APPLY_UIA_OK = true;

  try { String.fromCharCode.apply(null, new Uint8Array(1)); } catch (__) { STR_APPLY_UIA_OK = false; }


  // Table with utf8 lengths (calculated by first byte of sequence)
  // Note, that 5 & 6-byte values and some 4-byte values can not be represented in JS,
  // because max possible codepoint is 0x10ffff
  const _utf8len = new Uint8Array(256);
  for (let q = 0; q < 256; q++) {
    _utf8len[q] = (q >= 252 ? 6 : q >= 248 ? 5 : q >= 240 ? 4 : q >= 224 ? 3 : q >= 192 ? 2 : 1);
  }
  _utf8len[254] = _utf8len[254] = 1; // Invalid sequence start


  // convert string to array (typed, when possible)
  var string2buf = (str) => {
    if (typeof TextEncoder === 'function' && TextEncoder.prototype.encode) {
      return new TextEncoder().encode(str);
    }

    let buf, c, c2, m_pos, i, str_len = str.length, buf_len = 0;

    // count binary size
    for (m_pos = 0; m_pos < str_len; m_pos++) {
      c = str.charCodeAt(m_pos);
      if ((c & 0xfc00) === 0xd800 && (m_pos + 1 < str_len)) {
        c2 = str.charCodeAt(m_pos + 1);
        if ((c2 & 0xfc00) === 0xdc00) {
          c = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
          m_pos++;
        }
      }
      buf_len += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
    }

    // allocate buffer
    buf = new Uint8Array(buf_len);

    // convert
    for (i = 0, m_pos = 0; i < buf_len; m_pos++) {
      c = str.charCodeAt(m_pos);
      if ((c & 0xfc00) === 0xd800 && (m_pos + 1 < str_len)) {
        c2 = str.charCodeAt(m_pos + 1);
        if ((c2 & 0xfc00) === 0xdc00) {
          c = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
          m_pos++;
        }
      }
      if (c < 0x80) {
        /* one byte */
        buf[i++] = c;
      } else if (c < 0x800) {
        /* two bytes */
        buf[i++] = 0xC0 | (c >>> 6);
        buf[i++] = 0x80 | (c & 0x3f);
      } else if (c < 0x10000) {
        /* three bytes */
        buf[i++] = 0xE0 | (c >>> 12);
        buf[i++] = 0x80 | (c >>> 6 & 0x3f);
        buf[i++] = 0x80 | (c & 0x3f);
      } else {
        /* four bytes */
        buf[i++] = 0xf0 | (c >>> 18);
        buf[i++] = 0x80 | (c >>> 12 & 0x3f);
        buf[i++] = 0x80 | (c >>> 6 & 0x3f);
        buf[i++] = 0x80 | (c & 0x3f);
      }
    }

    return buf;
  };

  // Helper
  const buf2binstring = (buf, len) => {
    // On Chrome, the arguments in a function call that are allowed is `65534`.
    // If the length of the buffer is smaller than that, we can use this optimization,
    // otherwise we will take a slower path.
    if (len < 65534) {
      if (buf.subarray && STR_APPLY_UIA_OK) {
        return String.fromCharCode.apply(null, buf.length === len ? buf : buf.subarray(0, len));
      }
    }

    let result = '';
    for (let i = 0; i < len; i++) {
      result += String.fromCharCode(buf[i]);
    }
    return result;
  };


  // convert array to string
  var buf2string = (buf, max) => {
    const len = max || buf.length;

    if (typeof TextDecoder === 'function' && TextDecoder.prototype.decode) {
      return new TextDecoder().decode(buf.subarray(0, max));
    }

    let i, out;

    // Reserve max possible length (2 words per char)
    // NB: by unknown reasons, Array is significantly faster for
    //     String.fromCharCode.apply than Uint16Array.
    const utf16buf = new Array(len * 2);

    for (out = 0, i = 0; i < len;) {
      let c = buf[i++];
      // quick process ascii
      if (c < 0x80) { utf16buf[out++] = c; continue; }

      let c_len = _utf8len[c];
      // skip 5 & 6 byte codes
      if (c_len > 4) { utf16buf[out++] = 0xfffd; i += c_len - 1; continue; }

      // apply mask on first byte
      c &= c_len === 2 ? 0x1f : c_len === 3 ? 0x0f : 0x07;
      // join the rest
      while (c_len > 1 && i < len) {
        c = (c << 6) | (buf[i++] & 0x3f);
        c_len--;
      }

      // terminated by end of string?
      if (c_len > 1) { utf16buf[out++] = 0xfffd; continue; }

      if (c < 0x10000) {
        utf16buf[out++] = c;
      } else {
        c -= 0x10000;
        utf16buf[out++] = 0xd800 | ((c >> 10) & 0x3ff);
        utf16buf[out++] = 0xdc00 | (c & 0x3ff);
      }
    }

    return buf2binstring(utf16buf, out);
  };


  // Calculate max possible position in utf8 buffer,
  // that will not break sequence. If that's not possible
  // - (very small limits) return max size as is.
  //
  // buf[] - utf8 bytes array
  // max   - length limit (mandatory);
  var utf8border = (buf, max) => {

    max = max || buf.length;
    if (max > buf.length) { max = buf.length; }

    // go back from last position, until start of sequence found
    let pos = max - 1;
    while (pos >= 0 && (buf[pos] & 0xC0) === 0x80) { pos--; }

    // Very small and broken sequence,
    // return max, because we should return something anyway.
    if (pos < 0) { return max; }

    // If we came to start of buffer - that means buffer is too small,
    // return max too.
    if (pos === 0) { return max; }

    return (pos + _utf8len[buf[pos]] > max) ? pos : max;
  };

  var strings = {
  	string2buf: string2buf,
  	buf2string: buf2string,
  	utf8border: utf8border
  };

  // (C) 1995-2013 Jean-loup Gailly and Mark Adler
  // (C) 2014-2017 Vitaly Puzrin and Andrey Tupitsin
  //
  // This software is provided 'as-is', without any express or implied
  // warranty. In no event will the authors be held liable for any damages
  // arising from the use of this software.
  //
  // Permission is granted to anyone to use this software for any purpose,
  // including commercial applications, and to alter it and redistribute it
  // freely, subject to the following restrictions:
  //
  // 1. The origin of this software must not be misrepresented; you must not
  //   claim that you wrote the original software. If you use this software
  //   in a product, an acknowledgment in the product documentation would be
  //   appreciated but is not required.
  // 2. Altered source versions must be plainly marked as such, and must not be
  //   misrepresented as being the original software.
  // 3. This notice may not be removed or altered from any source distribution.

  var messages = {
    2:      'need dictionary',     /* Z_NEED_DICT       2  */
    1:      'stream end',          /* Z_STREAM_END      1  */
    0:      '',                    /* Z_OK              0  */
    '-1':   'file error',          /* Z_ERRNO         (-1) */
    '-2':   'stream error',        /* Z_STREAM_ERROR  (-2) */
    '-3':   'data error',          /* Z_DATA_ERROR    (-3) */
    '-4':   'insufficient memory', /* Z_MEM_ERROR     (-4) */
    '-5':   'buffer error',        /* Z_BUF_ERROR     (-5) */
    '-6':   'incompatible version' /* Z_VERSION_ERROR (-6) */
  };

  // (C) 1995-2013 Jean-loup Gailly and Mark Adler
  // (C) 2014-2017 Vitaly Puzrin and Andrey Tupitsin
  //
  // This software is provided 'as-is', without any express or implied
  // warranty. In no event will the authors be held liable for any damages
  // arising from the use of this software.
  //
  // Permission is granted to anyone to use this software for any purpose,
  // including commercial applications, and to alter it and redistribute it
  // freely, subject to the following restrictions:
  //
  // 1. The origin of this software must not be misrepresented; you must not
  //   claim that you wrote the original software. If you use this software
  //   in a product, an acknowledgment in the product documentation would be
  //   appreciated but is not required.
  // 2. Altered source versions must be plainly marked as such, and must not be
  //   misrepresented as being the original software.
  // 3. This notice may not be removed or altered from any source distribution.

  function ZStream() {
    /* next input byte */
    this.input = null; // JS specific, because we have no pointers
    this.next_in = 0;
    /* number of bytes available at input */
    this.avail_in = 0;
    /* total number of input bytes read so far */
    this.total_in = 0;
    /* next output byte should be put there */
    this.output = null; // JS specific, because we have no pointers
    this.next_out = 0;
    /* remaining free space at output */
    this.avail_out = 0;
    /* total number of bytes output so far */
    this.total_out = 0;
    /* last error message, NULL if no error */
    this.msg = ''/*Z_NULL*/;
    /* not visible by applications */
    this.state = null;
    /* best guess about the data type: binary or text */
    this.data_type = 2/*Z_UNKNOWN*/;
    /* adler32 value of the uncompressed data */
    this.adler = 0;
  }

  var zstream = ZStream;

  // (C) 1995-2013 Jean-loup Gailly and Mark Adler
  // (C) 2014-2017 Vitaly Puzrin and Andrey Tupitsin
  //
  // This software is provided 'as-is', without any express or implied
  // warranty. In no event will the authors be held liable for any damages
  // arising from the use of this software.
  //
  // Permission is granted to anyone to use this software for any purpose,
  // including commercial applications, and to alter it and redistribute it
  // freely, subject to the following restrictions:
  //
  // 1. The origin of this software must not be misrepresented; you must not
  //   claim that you wrote the original software. If you use this software
  //   in a product, an acknowledgment in the product documentation would be
  //   appreciated but is not required.
  // 2. Altered source versions must be plainly marked as such, and must not be
  //   misrepresented as being the original software.
  // 3. This notice may not be removed or altered from any source distribution.

  function GZheader() {
    /* true if compressed data believed to be text */
    this.text       = 0;
    /* modification time */
    this.time       = 0;
    /* extra flags (not used when writing a gzip file) */
    this.xflags     = 0;
    /* operating system */
    this.os         = 0;
    /* pointer to extra field or Z_NULL if none */
    this.extra      = null;
    /* extra field length (valid if extra != Z_NULL) */
    this.extra_len  = 0; // Actually, we don't need it in JS,
                         // but leave for few code modifications

    //
    // Setup limits is not necessary because in js we should not preallocate memory
    // for inflate use constant limit in 65536 bytes
    //

    /* space at extra (only when reading header) */
    // this.extra_max  = 0;
    /* pointer to zero-terminated file name or Z_NULL */
    this.name       = '';
    /* space at name (only when reading header) */
    // this.name_max   = 0;
    /* pointer to zero-terminated comment or Z_NULL */
    this.comment    = '';
    /* space at comment (only when reading header) */
    // this.comm_max   = 0;
    /* true if there was or will be a header crc */
    this.hcrc       = 0;
    /* true when done reading gzip header (not used when writing a gzip file) */
    this.done       = false;
  }

  var gzheader = GZheader;

  const toString = Object.prototype.toString;

  /* Public constants ==========================================================*/
  /* ===========================================================================*/

  const {
    Z_NO_FLUSH, Z_FINISH,
    Z_OK, Z_STREAM_END, Z_NEED_DICT, Z_STREAM_ERROR, Z_DATA_ERROR, Z_MEM_ERROR
  } = constants$1;

  /* ===========================================================================*/


  /**
   * class Inflate
   *
   * Generic JS-style wrapper for zlib calls. If you don't need
   * streaming behaviour - use more simple functions: [[inflate]]
   * and [[inflateRaw]].
   **/

  /* internal
   * inflate.chunks -> Array
   *
   * Chunks of output data, if [[Inflate#onData]] not overridden.
   **/

  /**
   * Inflate.result -> Uint8Array|String
   *
   * Uncompressed result, generated by default [[Inflate#onData]]
   * and [[Inflate#onEnd]] handlers. Filled after you push last chunk
   * (call [[Inflate#push]] with `Z_FINISH` / `true` param).
   **/

  /**
   * Inflate.err -> Number
   *
   * Error code after inflate finished. 0 (Z_OK) on success.
   * Should be checked if broken data possible.
   **/

  /**
   * Inflate.msg -> String
   *
   * Error message, if [[Inflate.err]] != 0
   **/


  /**
   * new Inflate(options)
   * - options (Object): zlib inflate options.
   *
   * Creates new inflator instance with specified params. Throws exception
   * on bad params. Supported options:
   *
   * - `windowBits`
   * - `dictionary`
   *
   * [http://zlib.net/manual.html#Advanced](http://zlib.net/manual.html#Advanced)
   * for more information on these.
   *
   * Additional options, for internal needs:
   *
   * - `chunkSize` - size of generated data chunks (16K by default)
   * - `raw` (Boolean) - do raw inflate
   * - `to` (String) - if equal to 'string', then result will be converted
   *   from utf8 to utf16 (javascript) string. When string output requested,
   *   chunk length can differ from `chunkSize`, depending on content.
   *
   * By default, when no options set, autodetect deflate/gzip data format via
   * wrapper header.
   *
   * ##### Example:
   *
   * ```javascript
   * const pako = require('pako')
   * const chunk1 = new Uint8Array([1,2,3,4,5,6,7,8,9])
   * const chunk2 = new Uint8Array([10,11,12,13,14,15,16,17,18,19]);
   *
   * const inflate = new pako.Inflate({ level: 3});
   *
   * inflate.push(chunk1, false);
   * inflate.push(chunk2, true);  // true -> last chunk
   *
   * if (inflate.err) { throw new Error(inflate.err); }
   *
   * console.log(inflate.result);
   * ```
   **/
  function Inflate(options) {
    this.options = common.assign({
      chunkSize: 1024 * 64,
      windowBits: 15,
      to: ''
    }, options || {});

    const opt = this.options;

    // Force window size for `raw` data, if not set directly,
    // because we have no header for autodetect.
    if (opt.raw && (opt.windowBits >= 0) && (opt.windowBits < 16)) {
      opt.windowBits = -opt.windowBits;
      if (opt.windowBits === 0) { opt.windowBits = -15; }
    }

    // If `windowBits` not defined (and mode not raw) - set autodetect flag for gzip/deflate
    if ((opt.windowBits >= 0) && (opt.windowBits < 16) &&
        !(options && options.windowBits)) {
      opt.windowBits += 32;
    }

    // Gzip header has no info about windows size, we can do autodetect only
    // for deflate. So, if window size not set, force it to max when gzip possible
    if ((opt.windowBits > 15) && (opt.windowBits < 48)) {
      // bit 3 (16) -> gzipped data
      // bit 4 (32) -> autodetect gzip/deflate
      if ((opt.windowBits & 15) === 0) {
        opt.windowBits |= 15;
      }
    }

    this.err    = 0;      // error code, if happens (0 = Z_OK)
    this.msg    = '';     // error message
    this.ended  = false;  // used to avoid multiple onEnd() calls
    this.chunks = [];     // chunks of compressed data

    this.strm   = new zstream();
    this.strm.avail_out = 0;

    let status  = inflate_1$1.inflateInit2(
      this.strm,
      opt.windowBits
    );

    if (status !== Z_OK) {
      throw new Error(messages[status]);
    }

    this.header = new gzheader();

    inflate_1$1.inflateGetHeader(this.strm, this.header);

    // Setup dictionary
    if (opt.dictionary) {
      // Convert data if needed
      if (typeof opt.dictionary === 'string') {
        opt.dictionary = strings.string2buf(opt.dictionary);
      } else if (toString.call(opt.dictionary) === '[object ArrayBuffer]') {
        opt.dictionary = new Uint8Array(opt.dictionary);
      }
      if (opt.raw) { //In raw mode we need to set the dictionary early
        status = inflate_1$1.inflateSetDictionary(this.strm, opt.dictionary);
        if (status !== Z_OK) {
          throw new Error(messages[status]);
        }
      }
    }
  }

  /**
   * Inflate#push(data[, flush_mode]) -> Boolean
   * - data (Uint8Array|ArrayBuffer): input data
   * - flush_mode (Number|Boolean): 0..6 for corresponding Z_NO_FLUSH..Z_TREE
   *   flush modes. See constants. Skipped or `false` means Z_NO_FLUSH,
   *   `true` means Z_FINISH.
   *
   * Sends input data to inflate pipe, generating [[Inflate#onData]] calls with
   * new output chunks. Returns `true` on success. If end of stream detected,
   * [[Inflate#onEnd]] will be called.
   *
   * `flush_mode` is not needed for normal operation, because end of stream
   * detected automatically. You may try to use it for advanced things, but
   * this functionality was not tested.
   *
   * On fail call [[Inflate#onEnd]] with error code and return false.
   *
   * ##### Example
   *
   * ```javascript
   * push(chunk, false); // push one of data chunks
   * ...
   * push(chunk, true);  // push last chunk
   * ```
   **/
  Inflate.prototype.push = function (data, flush_mode) {
    const strm = this.strm;
    const chunkSize = this.options.chunkSize;
    const dictionary = this.options.dictionary;
    let status, _flush_mode, last_avail_out;

    if (this.ended) return false;

    if (flush_mode === ~~flush_mode) _flush_mode = flush_mode;
    else _flush_mode = flush_mode === true ? Z_FINISH : Z_NO_FLUSH;

    // Convert data if needed
    if (toString.call(data) === '[object ArrayBuffer]') {
      strm.input = new Uint8Array(data);
    } else {
      strm.input = data;
    }

    strm.next_in = 0;
    strm.avail_in = strm.input.length;

    for (;;) {
      if (strm.avail_out === 0) {
        strm.output = new Uint8Array(chunkSize);
        strm.next_out = 0;
        strm.avail_out = chunkSize;
      }

      status = inflate_1$1.inflate(strm, _flush_mode);

      if (status === Z_NEED_DICT && dictionary) {
        status = inflate_1$1.inflateSetDictionary(strm, dictionary);

        if (status === Z_OK) {
          status = inflate_1$1.inflate(strm, _flush_mode);
        } else if (status === Z_DATA_ERROR) {
          // Replace code with more verbose
          status = Z_NEED_DICT;
        }
      }

      // Skip snyc markers if more data follows and not raw mode
      while (strm.avail_in > 0 &&
             status === Z_STREAM_END &&
             strm.state.wrap > 0 &&
             data[strm.next_in] !== 0)
      {
        inflate_1$1.inflateReset(strm);
        status = inflate_1$1.inflate(strm, _flush_mode);
      }

      switch (status) {
        case Z_STREAM_ERROR:
        case Z_DATA_ERROR:
        case Z_NEED_DICT:
        case Z_MEM_ERROR:
          this.onEnd(status);
          this.ended = true;
          return false;
      }

      // Remember real `avail_out` value, because we may patch out buffer content
      // to align utf8 strings boundaries.
      last_avail_out = strm.avail_out;

      if (strm.next_out) {
        if (strm.avail_out === 0 || status === Z_STREAM_END) {

          if (this.options.to === 'string') {

            let next_out_utf8 = strings.utf8border(strm.output, strm.next_out);

            let tail = strm.next_out - next_out_utf8;
            let utf8str = strings.buf2string(strm.output, next_out_utf8);

            // move tail & realign counters
            strm.next_out = tail;
            strm.avail_out = chunkSize - tail;
            if (tail) strm.output.set(strm.output.subarray(next_out_utf8, next_out_utf8 + tail), 0);

            this.onData(utf8str);

          } else {
            this.onData(strm.output.length === strm.next_out ? strm.output : strm.output.subarray(0, strm.next_out));
          }
        }
      }

      // Must repeat iteration if out buffer is full
      if (status === Z_OK && last_avail_out === 0) continue;

      // Finalize if end of stream reached.
      if (status === Z_STREAM_END) {
        status = inflate_1$1.inflateEnd(this.strm);
        this.onEnd(status);
        this.ended = true;
        return true;
      }

      if (strm.avail_in === 0) break;
    }

    return true;
  };


  /**
   * Inflate#onData(chunk) -> Void
   * - chunk (Uint8Array|String): output data. When string output requested,
   *   each chunk will be string.
   *
   * By default, stores data blocks in `chunks[]` property and glue
   * those in `onEnd`. Override this handler, if you need another behaviour.
   **/
  Inflate.prototype.onData = function (chunk) {
    this.chunks.push(chunk);
  };


  /**
   * Inflate#onEnd(status) -> Void
   * - status (Number): inflate status. 0 (Z_OK) on success,
   *   other if not.
   *
   * Called either after you tell inflate that the input stream is
   * complete (Z_FINISH). By default - join collected chunks,
   * free memory and fill `results` / `err` properties.
   **/
  Inflate.prototype.onEnd = function (status) {
    // On success - join
    if (status === Z_OK) {
      if (this.options.to === 'string') {
        this.result = this.chunks.join('');
      } else {
        this.result = common.flattenChunks(this.chunks);
      }
    }
    this.chunks = [];
    this.err = status;
    this.msg = this.strm.msg;
  };


  /**
   * inflate(data[, options]) -> Uint8Array|String
   * - data (Uint8Array|ArrayBuffer): input data to decompress.
   * - options (Object): zlib inflate options.
   *
   * Decompress `data` with inflate/ungzip and `options`. Autodetect
   * format via wrapper header by default. That's why we don't provide
   * separate `ungzip` method.
   *
   * Supported options are:
   *
   * - windowBits
   *
   * [http://zlib.net/manual.html#Advanced](http://zlib.net/manual.html#Advanced)
   * for more information.
   *
   * Sugar (options):
   *
   * - `raw` (Boolean) - say that we work with raw stream, if you don't wish to specify
   *   negative windowBits implicitly.
   * - `to` (String) - if equal to 'string', then result will be converted
   *   from utf8 to utf16 (javascript) string. When string output requested,
   *   chunk length can differ from `chunkSize`, depending on content.
   *
   *
   * ##### Example:
   *
   * ```javascript
   * const pako = require('pako');
   * const input = pako.deflate(new Uint8Array([1,2,3,4,5,6,7,8,9]));
   * let output;
   *
   * try {
   *   output = pako.inflate(input);
   * } catch (err) {
   *   console.log(err);
   * }
   * ```
   **/
  function inflate(input, options) {
    const inflator = new Inflate(options);

    inflator.push(input);

    // That will never happens, if you don't cheat with options :)
    if (inflator.err) throw inflator.msg || messages[inflator.err];

    return inflator.result;
  }


  /**
   * inflateRaw(data[, options]) -> Uint8Array|String
   * - data (Uint8Array|ArrayBuffer): input data to decompress.
   * - options (Object): zlib inflate options.
   *
   * The same as [[inflate]], but creates raw data, without wrapper
   * (header and adler32 crc).
   **/
  function inflateRaw(input, options) {
    options = options || {};
    options.raw = true;
    return inflate(input, options);
  }


  /**
   * ungzip(data[, options]) -> Uint8Array|String
   * - data (Uint8Array|ArrayBuffer): input data to decompress.
   * - options (Object): zlib inflate options.
   *
   * Just shortcut to [[inflate]], because it autodetects format
   * by header.content. Done for convenience.
   **/


  var Inflate_1 = Inflate;
  var inflate_2 = inflate;
  var inflateRaw_1 = inflateRaw;
  var ungzip = inflate;
  var constants = constants$1;

  var inflate_1 = {
  	Inflate: Inflate_1,
  	inflate: inflate_2,
  	inflateRaw: inflateRaw_1,
  	ungzip: ungzip,
  	constants: constants
  };

  exports.Inflate = Inflate_1;
  exports.constants = constants;
  exports["default"] = inflate_1;
  exports.inflate = inflate_2;
  exports.inflateRaw = inflateRaw_1;
  exports.ungzip = ungzip;

  Object.defineProperty(exports, '__esModule', { value: true });

}));


/***/ }),

/***/ "./src/api/gramjs/apiBuilders/helpers.ts":
/*!***********************************************!*\
  !*** ./src/api/gramjs/apiBuilders/helpers.ts ***!
  \***********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   bytesToDataUri: () => (/* binding */ bytesToDataUri),
/* harmony export */   omitVirtualClassFields: () => (/* binding */ omitVirtualClassFields)
/* harmony export */ });
function bytesToDataUri(bytes, shouldOmitPrefix = false, mimeType = 'image/jpeg') {
  const prefix = shouldOmitPrefix ? '' : `data:${mimeType};base64,`;
  return `${prefix}${btoa(String.fromCharCode(...bytes))}`;
}
function omitVirtualClassFields(instance) {
  const {
    flags,
    CONSTRUCTOR_ID,
    SUBCLASS_OF_ID,
    className,
    classType,
    getBytes,
    ...rest
  } = instance;
  return rest;
}

/***/ }),

/***/ "./src/api/gramjs/apiBuilders/peers.ts":
/*!*********************************************!*\
  !*** ./src/api/gramjs/apiBuilders/peers.ts ***!
  \*********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   buildApiEmojiStatus: () => (/* binding */ buildApiEmojiStatus),
/* harmony export */   buildApiPeerColor: () => (/* binding */ buildApiPeerColor),
/* harmony export */   buildApiPeerId: () => (/* binding */ buildApiPeerId),
/* harmony export */   getApiChatIdFromMtpPeer: () => (/* binding */ getApiChatIdFromMtpPeer),
/* harmony export */   isMtpPeerChannel: () => (/* binding */ isMtpPeerChannel),
/* harmony export */   isMtpPeerChat: () => (/* binding */ isMtpPeerChat),
/* harmony export */   isMtpPeerUser: () => (/* binding */ isMtpPeerUser)
/* harmony export */ });
/* harmony import */ var _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../lib/gramjs */ "./src/lib/gramjs/index.ts");
/* harmony import */ var _config__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../config */ "./src/config.ts");
/* harmony import */ var _util_colors__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../util/colors */ "./src/util/colors.ts");



function isMtpPeerUser(peer) {
  return peer.hasOwnProperty('userId');
}
function isMtpPeerChat(peer) {
  return peer.hasOwnProperty('chatId');
}
function isMtpPeerChannel(peer) {
  return peer.hasOwnProperty('channelId');
}
function buildApiPeerId(id, type) {
  if (type === 'user') {
    return id.toString();
  }
  if (type === 'channel') {
    return id.add(_config__WEBPACK_IMPORTED_MODULE_1__.CHANNEL_ID_BASE).negate().toString();
  }
  return id.negate().toString();
}
function getApiChatIdFromMtpPeer(peer) {
  if (isMtpPeerUser(peer)) {
    return buildApiPeerId(peer.userId, 'user');
  } else if (isMtpPeerChat(peer)) {
    return buildApiPeerId(peer.chatId, 'chat');
  } else {
    return buildApiPeerId(peer.channelId, 'channel');
  }
}
function buildApiPeerColor(peerColor) {
  const {
    color,
    backgroundEmojiId
  } = peerColor;
  return {
    color,
    backgroundEmojiId: backgroundEmojiId?.toString()
  };
}
function buildApiEmojiStatus(mtpEmojiStatus) {
  if (mtpEmojiStatus instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.Api.EmojiStatus) {
    return {
      type: 'regular',
      documentId: mtpEmojiStatus.documentId.toString(),
      until: mtpEmojiStatus.until
    };
  }
  if (mtpEmojiStatus instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.Api.EmojiStatusCollectible) {
    return {
      type: 'collectible',
      collectibleId: mtpEmojiStatus.collectibleId.toString(),
      documentId: mtpEmojiStatus.documentId.toString(),
      title: mtpEmojiStatus.title,
      slug: mtpEmojiStatus.slug,
      patternDocumentId: mtpEmojiStatus.patternDocumentId.toString(),
      centerColor: (0,_util_colors__WEBPACK_IMPORTED_MODULE_2__.numberToHexColor)(mtpEmojiStatus.centerColor),
      edgeColor: (0,_util_colors__WEBPACK_IMPORTED_MODULE_2__.numberToHexColor)(mtpEmojiStatus.edgeColor),
      patternColor: (0,_util_colors__WEBPACK_IMPORTED_MODULE_2__.numberToHexColor)(mtpEmojiStatus.patternColor),
      textColor: (0,_util_colors__WEBPACK_IMPORTED_MODULE_2__.numberToHexColor)(mtpEmojiStatus.textColor),
      until: mtpEmojiStatus.until
    };
  }
  return undefined;
}

/***/ }),

/***/ "./src/api/gramjs/gramjsBuilders/index.ts":
/*!************************************************!*\
  !*** ./src/api/gramjs/gramjsBuilders/index.ts ***!
  \************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   DEFAULT_PRIMITIVES: () => (/* binding */ DEFAULT_PRIMITIVES),
/* harmony export */   buildChatAdminRights: () => (/* binding */ buildChatAdminRights),
/* harmony export */   buildChatBannedRights: () => (/* binding */ buildChatBannedRights),
/* harmony export */   buildChatPhotoForLocalDb: () => (/* binding */ buildChatPhotoForLocalDb),
/* harmony export */   buildDisallowedGiftsSettings: () => (/* binding */ buildDisallowedGiftsSettings),
/* harmony export */   buildFilterFromApiFolder: () => (/* binding */ buildFilterFromApiFolder),
/* harmony export */   buildInputBotApp: () => (/* binding */ buildInputBotApp),
/* harmony export */   buildInputChannel: () => (/* binding */ buildInputChannel),
/* harmony export */   buildInputChannelFromLocalDb: () => (/* binding */ buildInputChannelFromLocalDb),
/* harmony export */   buildInputChat: () => (/* binding */ buildInputChat),
/* harmony export */   buildInputChatReactions: () => (/* binding */ buildInputChatReactions),
/* harmony export */   buildInputContact: () => (/* binding */ buildInputContact),
/* harmony export */   buildInputDocument: () => (/* binding */ buildInputDocument),
/* harmony export */   buildInputEmojiStatus: () => (/* binding */ buildInputEmojiStatus),
/* harmony export */   buildInputGroupCall: () => (/* binding */ buildInputGroupCall),
/* harmony export */   buildInputInvoice: () => (/* binding */ buildInputInvoice),
/* harmony export */   buildInputMediaDocument: () => (/* binding */ buildInputMediaDocument),
/* harmony export */   buildInputPaidReactionPrivacy: () => (/* binding */ buildInputPaidReactionPrivacy),
/* harmony export */   buildInputPeer: () => (/* binding */ buildInputPeer),
/* harmony export */   buildInputPeerFromLocalDb: () => (/* binding */ buildInputPeerFromLocalDb),
/* harmony export */   buildInputPhoneCall: () => (/* binding */ buildInputPhoneCall),
/* harmony export */   buildInputPhoto: () => (/* binding */ buildInputPhoto),
/* harmony export */   buildInputPoll: () => (/* binding */ buildInputPoll),
/* harmony export */   buildInputPollFromExisting: () => (/* binding */ buildInputPollFromExisting),
/* harmony export */   buildInputPrivacyKey: () => (/* binding */ buildInputPrivacyKey),
/* harmony export */   buildInputPrivacyRules: () => (/* binding */ buildInputPrivacyRules),
/* harmony export */   buildInputReaction: () => (/* binding */ buildInputReaction),
/* harmony export */   buildInputReplyTo: () => (/* binding */ buildInputReplyTo),
/* harmony export */   buildInputReportReason: () => (/* binding */ buildInputReportReason),
/* harmony export */   buildInputSavedStarGift: () => (/* binding */ buildInputSavedStarGift),
/* harmony export */   buildInputStarsAmount: () => (/* binding */ buildInputStarsAmount),
/* harmony export */   buildInputStickerSet: () => (/* binding */ buildInputStickerSet),
/* harmony export */   buildInputStickerSetShortName: () => (/* binding */ buildInputStickerSetShortName),
/* harmony export */   buildInputStorePaymentPurpose: () => (/* binding */ buildInputStorePaymentPurpose),
/* harmony export */   buildInputStory: () => (/* binding */ buildInputStory),
/* harmony export */   buildInputSuggestedPost: () => (/* binding */ buildInputSuggestedPost),
/* harmony export */   buildInputTextWithEntities: () => (/* binding */ buildInputTextWithEntities),
/* harmony export */   buildInputThemeParams: () => (/* binding */ buildInputThemeParams),
/* harmony export */   buildInputTodo: () => (/* binding */ buildInputTodo),
/* harmony export */   buildInputUser: () => (/* binding */ buildInputUser),
/* harmony export */   buildMessageFromUpdate: () => (/* binding */ buildMessageFromUpdate),
/* harmony export */   buildMtpMessageEntity: () => (/* binding */ buildMtpMessageEntity),
/* harmony export */   buildMtpPeerId: () => (/* binding */ buildMtpPeerId),
/* harmony export */   buildPeer: () => (/* binding */ buildPeer),
/* harmony export */   buildSendMessageAction: () => (/* binding */ buildSendMessageAction),
/* harmony export */   buildShippingInfo: () => (/* binding */ buildShippingInfo),
/* harmony export */   generateRandomBigInt: () => (/* binding */ generateRandomBigInt),
/* harmony export */   generateRandomInt: () => (/* binding */ generateRandomInt),
/* harmony export */   generateRandomTimestampedBigInt: () => (/* binding */ generateRandomTimestampedBigInt),
/* harmony export */   getEntityTypeById: () => (/* binding */ getEntityTypeById)
/* harmony export */ });
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! big-integer */ "./node_modules/big-integer/BigInteger.js");
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(big_integer__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../lib/gramjs */ "./src/lib/gramjs/index.ts");
/* harmony import */ var _lib_gramjs_Helpers__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../lib/gramjs/Helpers */ "./src/lib/gramjs/Helpers.ts");
/* harmony import */ var _types__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../types */ "./src/api/types/index.ts");
/* harmony import */ var _config__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../../../config */ "./src/config.ts");
/* harmony import */ var _util_iteratees__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../util/iteratees */ "./src/util/iteratees.ts");
/* harmony import */ var _helpers_misc__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../helpers/misc */ "./src/api/gramjs/helpers/misc.ts");
/* harmony import */ var _localDb__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../localDb */ "./src/api/gramjs/localDb.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];








const DEFAULT_PRIMITIVES = {
  INT: 0,
  BIGINT: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(0),
  STRING: ''
};
function getEntityTypeById(peerId) {
  const n = Number(peerId);
  if (n > 0) {
    return 'user';
  }
  if (n < -_config__WEBPACK_IMPORTED_MODULE_4__.CHANNEL_ID_BASE) {
    return 'channel';
  }
  return 'chat';
}
function buildPeer(chatOrUserId) {
  const type = getEntityTypeById(chatOrUserId);
  if (type === 'user') {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.PeerUser({
      userId: buildMtpPeerId(chatOrUserId, 'user')
    });
  } else if (type === 'channel') {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.PeerChannel({
      channelId: buildMtpPeerId(chatOrUserId, 'channel')
    });
  } else {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.PeerChat({
      chatId: buildMtpPeerId(chatOrUserId, 'chat')
    });
  }
}
function buildInputPeer(chatOrUserId, accessHash) {
  const type = getEntityTypeById(chatOrUserId);
  if (type === 'user') {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPeerUser({
      userId: buildMtpPeerId(chatOrUserId, 'user'),
      accessHash: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(accessHash)
    });
  } else if (type === 'channel') {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPeerChannel({
      channelId: buildMtpPeerId(chatOrUserId, 'channel'),
      accessHash: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(accessHash)
    });
  } else {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPeerChat({
      chatId: buildMtpPeerId(chatOrUserId, 'chat')
    });
  }
}
function buildInputUser(userId, accessHash) {
  if (!accessHash) {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputUserEmpty();
  }
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputUser({
    userId: buildMtpPeerId(userId, 'user'),
    accessHash: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(accessHash)
  });
}
function buildInputChannel(channelId, accessHash) {
  if (!accessHash) {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputChannelEmpty();
  }
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputChannel({
    channelId: buildMtpPeerId(channelId, 'channel'),
    accessHash: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(accessHash)
  });
}
function buildInputChat(chatId) {
  return big_integer__WEBPACK_IMPORTED_MODULE_0___default()(chatId.slice(1));
}
function buildInputPaidReactionPrivacy(isPrivate, peerId) {
  if (isPrivate) return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.PaidReactionPrivacyAnonymous();
  if (peerId) {
    const peer = buildInputPeerFromLocalDb(peerId);
    if (peer) {
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.PaidReactionPrivacyPeer({
        peer
      });
    }
  }
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.PaidReactionPrivacyDefault();
}
function buildInputPeerFromLocalDb(chatOrUserId) {
  const type = getEntityTypeById(chatOrUserId);
  let accessHash;
  if (type === 'user') {
    accessHash = _localDb__WEBPACK_IMPORTED_MODULE_7__["default"].users[chatOrUserId]?.accessHash;
    if (!accessHash) {
      return undefined;
    }
  } else if (type === 'channel') {
    accessHash = _localDb__WEBPACK_IMPORTED_MODULE_7__["default"].chats[chatOrUserId]?.accessHash;
    if (!accessHash) {
      return undefined;
    }
  }
  return buildInputPeer(chatOrUserId, String(accessHash));
}
function buildInputChannelFromLocalDb(channelId) {
  const channel = _localDb__WEBPACK_IMPORTED_MODULE_7__["default"].chats[channelId];
  if (!channel || !(channel instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.Channel)) {
    return undefined;
  }
  return buildInputChannel(channelId, String(channel.accessHash));
}
function buildInputStickerSet(id, accessHash) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputStickerSetID({
    id: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(id),
    accessHash: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(accessHash)
  });
}
function buildInputStickerSetShortName(shortName) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputStickerSetShortName({
    shortName
  });
}
function buildInputDocument(media) {
  const document = _localDb__WEBPACK_IMPORTED_MODULE_7__["default"].documents[media.id];
  if (!document) {
    return undefined;
  }
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputDocument((0,_util_iteratees__WEBPACK_IMPORTED_MODULE_5__.pick)(document, ['id', 'accessHash', 'fileReference']));
}
function buildInputMediaDocument(media) {
  const inputDocument = buildInputDocument(media);
  if (!inputDocument) {
    return undefined;
  }
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputMediaDocument({
    id: inputDocument
  });
}
function buildInputPoll(pollParams, randomId) {
  const {
    summary,
    quiz
  } = pollParams;
  const poll = new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.Poll({
    id: randomId,
    publicVoters: summary.isPublic,
    question: buildInputTextWithEntities(summary.question),
    answers: summary.answers.map(({
      text,
      option
    }) => {
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.PollAnswer({
        text: buildInputTextWithEntities(text),
        option: (0,_helpers_misc__WEBPACK_IMPORTED_MODULE_6__.deserializeBytes)(option)
      });
    }),
    quiz: summary.quiz,
    multipleChoice: summary.multipleChoice
  });
  if (!quiz) {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputMediaPoll({
      poll
    });
  }
  const correctAnswers = quiz.correctAnswers.map(_helpers_misc__WEBPACK_IMPORTED_MODULE_6__.deserializeBytes);
  const {
    solution
  } = quiz;
  const solutionEntities = quiz.solutionEntities ? quiz.solutionEntities.map(buildMtpMessageEntity) : [];
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputMediaPoll({
    poll,
    correctAnswers,
    ...(solution && {
      solution,
      solutionEntities
    })
  });
}
function buildInputPollFromExisting(poll, shouldClose = false) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputMediaPoll({
    poll: new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.Poll({
      id: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(poll.id),
      publicVoters: poll.summary.isPublic,
      question: buildInputTextWithEntities(poll.summary.question),
      answers: poll.summary.answers.map(({
        text,
        option
      }) => {
        return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.PollAnswer({
          text: buildInputTextWithEntities(text),
          option: (0,_helpers_misc__WEBPACK_IMPORTED_MODULE_6__.deserializeBytes)(option)
        });
      }),
      quiz: poll.summary.quiz,
      multipleChoice: poll.summary.multipleChoice,
      closeDate: poll.summary.closeDate,
      closePeriod: poll.summary.closePeriod,
      closed: shouldClose ? true : poll.summary.closed
    }),
    correctAnswers: poll.results.results?.filter(o => o.isCorrect).map(o => (0,_helpers_misc__WEBPACK_IMPORTED_MODULE_6__.deserializeBytes)(o.option)),
    solution: poll.results.solution,
    solutionEntities: poll.results.solutionEntities?.map(buildMtpMessageEntity)
  });
}
function buildInputTodo(todo) {
  const {
    title,
    items
  } = todo.todo;
  const todoItems = items.map(item => {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.TodoItem({
      id: item.id,
      title: buildInputTextWithEntities(item.title)
    });
  });
  const todoList = new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.TodoList({
    title: buildInputTextWithEntities(title),
    list: todoItems,
    othersCanAppend: todo.todo.othersCanAppend || undefined,
    othersCanComplete: todo.todo.othersCanComplete || undefined
  });
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputMediaTodo({
    todo: todoList
  });
}
function buildFilterFromApiFolder(folder) {
  const {
    emoticon,
    contacts,
    nonContacts,
    groups,
    channels,
    bots,
    color,
    excludeArchived,
    excludeMuted,
    excludeRead,
    pinnedChatIds,
    includedChatIds,
    excludedChatIds,
    noTitleAnimations
  } = folder;
  const pinnedPeers = pinnedChatIds ? pinnedChatIds.map(buildInputPeerFromLocalDb).filter(Boolean) : [];
  const includePeers = includedChatIds ? includedChatIds.map(buildInputPeerFromLocalDb).filter(Boolean) : [];
  const excludePeers = excludedChatIds ? excludedChatIds.map(buildInputPeerFromLocalDb).filter(Boolean) : [];
  if (folder.isChatList) {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.DialogFilterChatlist({
      id: folder.id,
      title: buildInputTextWithEntities(folder.title),
      color,
      emoticon: emoticon || undefined,
      pinnedPeers,
      includePeers,
      hasMyInvites: folder.hasMyInvites,
      titleNoanimate: noTitleAnimations
    });
  }
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.DialogFilter({
    id: folder.id,
    title: buildInputTextWithEntities(folder.title),
    emoticon: emoticon || undefined,
    contacts: contacts || undefined,
    nonContacts: nonContacts || undefined,
    groups: groups || undefined,
    bots: bots || undefined,
    color,
    excludeArchived: excludeArchived || undefined,
    excludeMuted: excludeMuted || undefined,
    excludeRead: excludeRead || undefined,
    broadcasts: channels || undefined,
    pinnedPeers,
    includePeers,
    excludePeers,
    titleNoanimate: noTitleAnimations
  });
}
function buildInputStory(story) {
  const peer = buildInputPeerFromLocalDb(story.peerId);
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputMediaStory({
    peer,
    id: story.id
  });
}
function generateRandomBigInt() {
  return (0,_lib_gramjs_Helpers__WEBPACK_IMPORTED_MODULE_2__.readBigIntFromBuffer)((0,_lib_gramjs_Helpers__WEBPACK_IMPORTED_MODULE_2__.generateRandomBytes)(8), true, true);
}
function generateRandomTimestampedBigInt() {
  // 32 bits for timestamp, 32 bits are random
  const buffer = (0,_lib_gramjs_Helpers__WEBPACK_IMPORTED_MODULE_2__.generateRandomBytes)(8);
  const timestampBuffer = Buffer.alloc(4);
  timestampBuffer.writeUInt32LE(Math.floor(Date.now() / 1000), 0);
  buffer.set(timestampBuffer, 4);
  return (0,_lib_gramjs_Helpers__WEBPACK_IMPORTED_MODULE_2__.readBigIntFromBuffer)(buffer, true, true);
}
function generateRandomInt() {
  return (0,_lib_gramjs_Helpers__WEBPACK_IMPORTED_MODULE_2__.readBigIntFromBuffer)((0,_lib_gramjs_Helpers__WEBPACK_IMPORTED_MODULE_2__.generateRandomBytes)(4), true, true).toJSNumber();
}
function buildMessageFromUpdate(id, chatId, update) {
  // This is not a proper message, but we only need these fields for downloading media through `localDb`.
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.Message({
    id,
    peerId: buildPeer(chatId),
    fromId: buildPeer(chatId),
    media: update.media
  });
}
function buildMtpMessageEntity(entity) {
  const {
    type,
    offset,
    length
  } = entity;
  const user = 'userId' in entity ? _localDb__WEBPACK_IMPORTED_MODULE_7__["default"].users[entity.userId] : undefined;
  switch (type) {
    case _types__WEBPACK_IMPORTED_MODULE_3__.ApiMessageEntityTypes.Bold:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.MessageEntityBold({
        offset,
        length
      });
    case _types__WEBPACK_IMPORTED_MODULE_3__.ApiMessageEntityTypes.Italic:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.MessageEntityItalic({
        offset,
        length
      });
    case _types__WEBPACK_IMPORTED_MODULE_3__.ApiMessageEntityTypes.Underline:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.MessageEntityUnderline({
        offset,
        length
      });
    case _types__WEBPACK_IMPORTED_MODULE_3__.ApiMessageEntityTypes.Strike:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.MessageEntityStrike({
        offset,
        length
      });
    case _types__WEBPACK_IMPORTED_MODULE_3__.ApiMessageEntityTypes.Code:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.MessageEntityCode({
        offset,
        length
      });
    case _types__WEBPACK_IMPORTED_MODULE_3__.ApiMessageEntityTypes.Pre:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.MessageEntityPre({
        offset,
        length,
        language: entity.language || ''
      });
    case _types__WEBPACK_IMPORTED_MODULE_3__.ApiMessageEntityTypes.Blockquote:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.MessageEntityBlockquote({
        offset,
        length
      });
    case _types__WEBPACK_IMPORTED_MODULE_3__.ApiMessageEntityTypes.TextUrl:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.MessageEntityTextUrl({
        offset,
        length,
        url: entity.url
      });
    case _types__WEBPACK_IMPORTED_MODULE_3__.ApiMessageEntityTypes.Url:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.MessageEntityUrl({
        offset,
        length
      });
    case _types__WEBPACK_IMPORTED_MODULE_3__.ApiMessageEntityTypes.Hashtag:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.MessageEntityHashtag({
        offset,
        length
      });
    case _types__WEBPACK_IMPORTED_MODULE_3__.ApiMessageEntityTypes.MentionName:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputMessageEntityMentionName({
        offset,
        length,
        userId: new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputUser({
          userId: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(user.id),
          accessHash: user.accessHash
        })
      });
    case _types__WEBPACK_IMPORTED_MODULE_3__.ApiMessageEntityTypes.Spoiler:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.MessageEntitySpoiler({
        offset,
        length
      });
    case _types__WEBPACK_IMPORTED_MODULE_3__.ApiMessageEntityTypes.CustomEmoji:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.MessageEntityCustomEmoji({
        offset,
        length,
        documentId: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(entity.documentId)
      });
    default:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.MessageEntityUnknown({
        offset,
        length
      });
  }
}
function buildChatPhotoForLocalDb(photo) {
  if (photo instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.PhotoEmpty) {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.ChatPhotoEmpty();
  }
  const {
    dcId,
    id: photoId
  } = photo;
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.ChatPhoto({
    dcId,
    photoId
  });
}
function buildInputPhoto(photo) {
  const localPhoto = _localDb__WEBPACK_IMPORTED_MODULE_7__["default"].photos[photo?.id];
  if (!localPhoto) {
    return undefined;
  }
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPhoto((0,_util_iteratees__WEBPACK_IMPORTED_MODULE_5__.pick)(localPhoto, ['id', 'accessHash', 'fileReference']));
}
function buildInputContact({
  phone,
  firstName,
  lastName
}) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPhoneContact({
    clientId: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(1),
    phone,
    firstName,
    lastName
  });
}
function buildChatBannedRights(bannedRights, untilDate = 0) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.ChatBannedRights({
    ...bannedRights,
    untilDate
  });
}
function buildChatAdminRights(adminRights) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.ChatAdminRights(adminRights);
}
function buildShippingInfo(info) {
  const {
    shippingAddress
  } = info;
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.PaymentRequestedInfo({
    ...info,
    shippingAddress: shippingAddress ? new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.PostAddress(shippingAddress) : undefined
  });
}
function buildInputPrivacyKey(privacyKey) {
  switch (privacyKey) {
    case 'phoneNumber':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyKeyPhoneNumber();
    case 'addByPhone':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyKeyAddedByPhone();
    case 'lastSeen':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyKeyStatusTimestamp();
    case 'profilePhoto':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyKeyProfilePhoto();
    case 'forwards':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyKeyForwards();
    case 'chatInvite':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyKeyChatInvite();
    case 'phoneCall':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyKeyPhoneCall();
    case 'phoneP2P':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyKeyPhoneP2P();
    case 'voiceMessages':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyKeyVoiceMessages();
    case 'bio':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyKeyAbout();
    case 'birthday':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyKeyBirthday();
    case 'gifts':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyKeyStarGiftsAutoSave();
    case 'noPaidMessages':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyKeyNoPaidMessages();
  }
  return undefined;
}
function buildInputReportReason(reason) {
  switch (reason) {
    case 'spam':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputReportReasonSpam();
    case 'violence':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputReportReasonViolence();
    case 'childAbuse':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputReportReasonChildAbuse();
    case 'pornography':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputReportReasonPornography();
    case 'copyright':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputReportReasonCopyright();
    case 'fake':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputReportReasonFake();
    case 'geoIrrelevant':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputReportReasonGeoIrrelevant();
    case 'illegalDrugs':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputReportReasonIllegalDrugs();
    case 'personalDetails':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputReportReasonPersonalDetails();
    case 'other':
    default:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputReportReasonOther();
  }
}
function buildSendMessageAction(action) {
  switch (action.type) {
    case 'cancel':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.SendMessageCancelAction();
    case 'typing':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.SendMessageTypingAction();
    case 'recordAudio':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.SendMessageRecordAudioAction();
    case 'chooseSticker':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.SendMessageChooseStickerAction();
    case 'playingGame':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.SendMessageGamePlayAction();
  }
  return undefined;
}
function buildInputThemeParams(params) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.DataJSON({
    data: JSON.stringify(params)
  });
}
function buildMtpPeerId(id, type) {
  if (type === 'user') {
    return big_integer__WEBPACK_IMPORTED_MODULE_0___default()(id);
  }
  const n = Number(id);
  if (type === 'channel') {
    return big_integer__WEBPACK_IMPORTED_MODULE_0___default()(-n - _config__WEBPACK_IMPORTED_MODULE_4__.CHANNEL_ID_BASE);
  }
  return big_integer__WEBPACK_IMPORTED_MODULE_0___default()(n * -1);
}
function buildInputGroupCall(groupCall) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputGroupCall({
    id: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(groupCall.id),
    accessHash: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(groupCall.accessHash)
  });
}
function buildInputPhoneCall({
  id,
  accessHash
}) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPhoneCall({
    id: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(id),
    accessHash: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(accessHash)
  });
}
function buildInputStorePaymentPurpose(purpose) {
  if (purpose.type === 'stars') {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputStorePaymentStarsTopup({
      stars: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(purpose.stars),
      currency: purpose.currency,
      amount: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(purpose.amount)
    });
  }
  if (purpose.type === 'starsgift') {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputStorePaymentStarsGift({
      userId: buildInputUser(purpose.user.id, purpose.user.accessHash),
      stars: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(purpose.stars),
      currency: purpose.currency,
      amount: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(purpose.amount)
    });
  }
  if (purpose.type === 'giftcode') {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputStorePaymentPremiumGiftCode({
      users: purpose.users.map(user => buildInputUser(user.id, user.accessHash)),
      boostPeer: purpose.boostChannel ? buildInputPeer(purpose.boostChannel.id, purpose.boostChannel.accessHash) : undefined,
      currency: purpose.currency,
      amount: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(purpose.amount),
      message: purpose.message && buildInputTextWithEntities(purpose.message)
    });
  }
  const randomId = generateRandomBigInt();
  if (purpose.type === 'starsgiveaway') {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputStorePaymentStarsGiveaway({
      boostPeer: buildInputPeer(purpose.chat.id, purpose.chat.accessHash),
      additionalPeers: purpose.additionalChannels?.map(chat => buildInputPeer(chat.id, chat.accessHash)),
      stars: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(purpose.stars),
      countriesIso2: purpose.countries,
      prizeDescription: purpose.prizeDescription,
      onlyNewSubscribers: purpose.isOnlyForNewSubscribers || undefined,
      winnersAreVisible: purpose.areWinnersVisible || undefined,
      untilDate: purpose.untilDate,
      currency: purpose.currency,
      amount: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(purpose.amount),
      users: purpose.users,
      randomId
    });
  }
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputStorePaymentPremiumGiveaway({
    boostPeer: buildInputPeer(purpose.chat.id, purpose.chat.accessHash),
    additionalPeers: purpose.additionalChannels?.map(chat => buildInputPeer(chat.id, chat.accessHash)),
    countriesIso2: purpose.countries,
    prizeDescription: purpose.prizeDescription,
    onlyNewSubscribers: purpose.isOnlyForNewSubscribers || undefined,
    winnersAreVisible: purpose.areWinnersVisible || undefined,
    untilDate: purpose.untilDate,
    currency: purpose.currency,
    amount: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(purpose.amount),
    randomId
  });
}
function buildPremiumGiftCodeOption(optionData) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.PremiumGiftCodeOption({
    users: optionData.users,
    months: optionData.months,
    currency: optionData.currency,
    amount: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(optionData.amount)
  });
}
function buildDisallowedGiftsSettings(disallowedGifts) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.DisallowedGiftsSettings({
    disallowUnlimitedStargifts: disallowedGifts.shouldDisallowLimitedStarGifts,
    disallowLimitedStargifts: disallowedGifts.shouldDisallowUnlimitedStarGifts,
    disallowUniqueStargifts: disallowedGifts.shouldDisallowUniqueStarGifts,
    disallowPremiumGifts: disallowedGifts.shouldDisallowPremiumGifts
  });
}
function buildInputInvoice(invoice) {
  switch (invoice.type) {
    case 'message':
      {
        return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputInvoiceMessage({
          peer: buildInputPeer(invoice.chat.id, invoice.chat.accessHash),
          msgId: invoice.messageId
        });
      }
    case 'slug':
      {
        return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputInvoiceSlug({
          slug: invoice.slug
        });
      }
    case 'stargiftResale':
      {
        const {
          peer,
          slug
        } = invoice;
        return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputInvoiceStarGiftResale({
          toId: buildInputPeer(peer.id, peer.accessHash),
          slug,
          ton: invoice.currency === 'TON' || undefined
        });
      }
    case 'stargift':
      {
        const {
          peer,
          shouldHideName,
          giftId,
          message,
          shouldUpgrade
        } = invoice;
        return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputInvoiceStarGift({
          peer: buildInputPeer(peer.id, peer.accessHash),
          hideName: shouldHideName || undefined,
          giftId: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(giftId),
          message: message && buildInputTextWithEntities(message),
          includeUpgrade: shouldUpgrade
        });
      }
    case 'stars':
      {
        const purpose = buildInputStorePaymentPurpose(invoice.purpose);
        return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputInvoiceStars({
          purpose
        });
      }
    case 'premiumGiftStars':
      {
        const {
          user,
          message,
          months
        } = invoice;
        return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputInvoicePremiumGiftStars({
          months,
          userId: buildInputUser(user.id, user.accessHash),
          message: message && buildInputTextWithEntities(message)
        });
      }
    case 'starsgiveaway':
      {
        const purpose = buildInputStorePaymentPurpose(invoice.purpose);
        return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputInvoiceStars({
          purpose
        });
      }
    case 'chatInviteSubscription':
      {
        return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputInvoiceChatInviteSubscription({
          hash: invoice.hash
        });
      }
    case 'stargiftUpgrade':
      {
        return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputInvoiceStarGiftUpgrade({
          stargift: buildInputSavedStarGift(invoice.inputSavedGift),
          keepOriginalDetails: invoice.shouldKeepOriginalDetails
        });
      }
    case 'stargiftTransfer':
      {
        return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputInvoiceStarGiftTransfer({
          stargift: buildInputSavedStarGift(invoice.inputSavedGift),
          toId: buildInputPeer(invoice.recipient.id, invoice.recipient.accessHash)
        });
      }
    case 'giveaway':
    default:
      {
        const purpose = buildInputStorePaymentPurpose(invoice.purpose);
        const option = buildPremiumGiftCodeOption(invoice.option);
        return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputInvoicePremiumGiftCode({
          purpose,
          option
        });
      }
  }
}
function buildInputReaction(reaction) {
  switch (reaction?.type) {
    case 'emoji':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.ReactionEmoji({
        emoticon: reaction.emoticon
      });
    case 'custom':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.ReactionCustomEmoji({
        documentId: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(reaction.documentId)
      });
    case 'paid':
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.ReactionPaid();
    default:
      return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.ReactionEmpty();
  }
}
function buildInputChatReactions(chatReactions) {
  if (chatReactions?.type === 'all') {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.ChatReactionsAll({
      allowCustom: chatReactions.areCustomAllowed
    });
  }
  if (chatReactions?.type === 'some') {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.ChatReactionsSome({
      reactions: chatReactions.allowed.map(buildInputReaction)
    });
  }
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.ChatReactionsNone();
}
function buildInputEmojiStatus(emojiStatus) {
  if (emojiStatus.type === 'collectible') {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputEmojiStatusCollectible({
      collectibleId: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(emojiStatus.collectibleId),
      until: emojiStatus.until
    });
  }
  if (emojiStatus.documentId === _config__WEBPACK_IMPORTED_MODULE_4__.DEFAULT_STATUS_ICON_ID) {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.EmojiStatusEmpty();
  }
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.EmojiStatus({
    documentId: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(emojiStatus.documentId),
    until: emojiStatus.until
  });
}
function buildInputTextWithEntities(formatted) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.TextWithEntities({
    text: formatted.text,
    entities: formatted.entities?.map(buildMtpMessageEntity) || []
  });
}
function buildInputBotApp(app) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputBotAppID({
    id: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(app.id),
    accessHash: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(app.accessHash)
  });
}
function buildInputReplyTo(replyInfo) {
  if (replyInfo.type === 'story') {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputReplyToStory({
      peer: buildInputPeerFromLocalDb(replyInfo.peerId),
      storyId: replyInfo.storyId
    });
  }
  if (replyInfo.type === 'message') {
    const {
      replyToMsgId,
      replyToTopId,
      replyToPeerId,
      quoteText,
      quoteOffset,
      monoforumPeerId
    } = replyInfo;
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputReplyToMessage({
      replyToMsgId,
      topMsgId: replyToTopId,
      replyToPeerId: replyToPeerId ? buildInputPeerFromLocalDb(replyToPeerId) : undefined,
      monoforumPeerId: monoforumPeerId ? buildInputPeerFromLocalDb(monoforumPeerId) : undefined,
      quoteText: quoteText?.text,
      quoteEntities: quoteText?.entities?.map(buildMtpMessageEntity),
      quoteOffset
    });
  }
  return undefined;
}
function buildInputStarsAmount(amount) {
  if (amount.currency === _config__WEBPACK_IMPORTED_MODULE_4__.STARS_CURRENCY_CODE) {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.StarsAmount({
      amount: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(amount.amount),
      nanos: amount.nanos
    });
  }
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.StarsTonAmount({
    amount: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(amount.amount)
  });
}
function buildInputSuggestedPost(suggestedPostInfo) {
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.SuggestedPost({
    price: suggestedPostInfo.price && buildInputStarsAmount(suggestedPostInfo.price),
    scheduleDate: suggestedPostInfo.scheduleDate
  });
}
function buildInputPrivacyRules(rules) {
  const privacyRules = [];
  if (rules.allowedUsers?.length) {
    privacyRules.push(new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyValueAllowUsers({
      users: rules.allowedUsers.map(({
        id,
        accessHash
      }) => buildInputUser(id, accessHash))
    }));
  }
  if (rules.allowedChats?.length) {
    privacyRules.push(new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyValueAllowChatParticipants({
      chats: rules.allowedChats.map(({
        id,
        type
      }) => buildMtpPeerId(id, type === 'chatTypeBasicGroup' ? 'chat' : 'channel'))
    }));
  }
  if (rules.blockedUsers?.length) {
    privacyRules.push(new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyValueDisallowUsers({
      users: rules.blockedUsers.map(({
        id,
        accessHash
      }) => buildInputUser(id, accessHash))
    }));
  }
  if (rules.blockedChats?.length) {
    privacyRules.push(new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyValueDisallowChatParticipants({
      chats: rules.blockedChats.map(({
        id,
        type
      }) => buildMtpPeerId(id, type === 'chatTypeBasicGroup' ? 'chat' : 'channel'))
    }));
  }
  if (rules.shouldAllowPremium) {
    privacyRules.push(new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyValueAllowPremium());
  }
  if (rules.botsPrivacy === 'allow') {
    privacyRules.push(new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyValueAllowBots());
  }
  if (rules.botsPrivacy === 'disallow') {
    privacyRules.push(new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyValueDisallowBots());
  }
  if (!rules.isUnspecified) {
    switch (rules.visibility) {
      case 'everybody':
        privacyRules.push(new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyValueAllowAll());
        break;
      case 'contacts':
        privacyRules.push(new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyValueAllowContacts());
        break;
      case 'nonContacts':
        privacyRules.push(new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyValueDisallowContacts());
        break;
      case 'nobody':
        privacyRules.push(new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputPrivacyValueDisallowAll());
        break;
    }
  }
  return privacyRules;
}
function buildInputSavedStarGift(inputGift) {
  if (inputGift.type === 'user') {
    return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputSavedStarGiftUser({
      msgId: inputGift.messageId
    });
  }
  return new _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api.InputSavedStarGiftChat({
    peer: buildInputPeer(inputGift.chat.id, inputGift.chat.accessHash),
    savedId: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(inputGift.savedId)
  });
}

/***/ }),

/***/ "./src/api/gramjs/helpers/misc.ts":
/*!****************************************!*\
  !*** ./src/api/gramjs/helpers/misc.ts ***!
  \****************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   checkErrorType: () => (/* binding */ checkErrorType),
/* harmony export */   deserializeBytes: () => (/* binding */ deserializeBytes),
/* harmony export */   isChatFolder: () => (/* binding */ isChatFolder),
/* harmony export */   isResponseUpdate: () => (/* binding */ isResponseUpdate),
/* harmony export */   log: () => (/* binding */ log),
/* harmony export */   resolveMessageApiChatId: () => (/* binding */ resolveMessageApiChatId),
/* harmony export */   serializeBytes: () => (/* binding */ serializeBytes),
/* harmony export */   wrapError: () => (/* binding */ wrapError)
/* harmony export */ });
/* harmony import */ var _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../lib/gramjs */ "./src/lib/gramjs/index.ts");
/* harmony import */ var _config__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../config */ "./src/config.ts");
/* harmony import */ var _util_dates_units__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../util/dates/units */ "./src/util/dates/units.ts");
/* harmony import */ var _apiBuilders_peers__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../apiBuilders/peers */ "./src/api/gramjs/apiBuilders/peers.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];




const LOG_BACKGROUND = '#111111DD';
const LOG_PREFIX_COLOR = '#E4D00A';
const LOG_SUFFIX = {
  INVOKE: '#49DBF5',
  BEACON: '#F549DB',
  RESPONSE: '#6887F7',
  CONNECTING: '#E4D00A',
  CONNECTED: '#26D907',
  'CONNECTING ERROR': '#D1191C',
  'INVOKE ERROR': '#D1191C',
  UPDATE: '#0DD151',
  'UNEXPECTED UPDATE': '#9C9C9C',
  'UNEXPECTED RESPONSE': '#D1191C'
};
const ERROR_KEYS = {
  PHONE_NUMBER_INVALID: 'ErrorPhoneNumberInvalid',
  PHONE_CODE_INVALID: 'ErrorCodeInvalid',
  PASSWORD_HASH_INVALID: 'ErrorIncorrectPassword',
  PHONE_PASSWORD_FLOOD: 'ErrorPasswordFlood',
  PHONE_NUMBER_BANNED: 'ErrorPhoneBanned',
  EMAIL_UNCONFIRMED: 'ErrorEmailUnconfirmed',
  EMAIL_HASH_EXPIRED: 'ErrorEmailHashExpired',
  NEW_SALT_INVALID: 'ErrorNewSaltInvalid',
  SRP_PASSWORD_CHANGED: 'ErrorPasswordChanged',
  CODE_INVALID: 'ErrorEmailCodeInvalid',
  PASSWORD_MISSING: 'ErrorPasswordMissing'
};
function resolveMessageApiChatId(mtpMessage) {
  if (!(mtpMessage instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.Api.Message || mtpMessage instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.Api.MessageService)) {
    return undefined;
  }
  return (0,_apiBuilders_peers__WEBPACK_IMPORTED_MODULE_3__.getApiChatIdFromMtpPeer)(mtpMessage.peerId);
}
function isChatFolder(filter) {
  return filter instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.Api.DialogFilter || filter instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.Api.DialogFilterChatlist;
}
function serializeBytes(value) {
  return String.fromCharCode(...value);
}
function deserializeBytes(value) {
  return Buffer.from(value, 'binary');
}
function log(suffix, ...data) {
  /* eslint-disable @stylistic/max-len */
  /* eslint-disable no-console */
  const func = suffix === 'UNEXPECTED RESPONSE' ? console.error : suffix === 'INVOKE ERROR' || suffix === 'UNEXPECTED UPDATE' ? console.warn : console.log;
  /* eslint-enable no-console */
  func(`%cGramJS%c${suffix}`, `color: ${LOG_PREFIX_COLOR}; background: ${LOG_BACKGROUND}; padding: 0.25rem; border-radius: 0.25rem;`, `color: ${LOG_SUFFIX[suffix]}; background: ${LOG_BACKGROUND}; padding: 0.25rem; border-radius: 0.25rem; margin-left: 0.25rem;`, ...data);
  /* eslint-enable @stylistic/max-len */
}
function isResponseUpdate(result) {
  return result instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.Api.UpdatesTooLong || result instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.Api.UpdateShortMessage || result instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.Api.UpdateShortChatMessage || result instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.Api.UpdateShort || result instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.Api.UpdatesCombined || result instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.Api.Updates || result instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.Api.UpdateShortSentMessage;
}
function checkErrorType(error) {
  if (!(error instanceof Error)) {
    // eslint-disable-next-line no-console
    if (_config__WEBPACK_IMPORTED_MODULE_1__.DEBUG) console.warn('Unexpected error type', error);
    return false;
  }
  return true;
}
function wrapError(error) {
  let messageKey;
  const errorMessage = error instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.errors.RPCError ? error.errorMessage : undefined;
  if (error instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.errors.FloodWaitError) {
    messageKey = {
      key: 'ErrorFloodTime',
      variables: {
        time: formatWait(error.seconds)
      }
    };
  } else if (error instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.errors.PasswordFreshError) {
    messageKey = {
      key: 'ErrorPasswordFresh',
      variables: {
        time: formatWait(error.seconds)
      }
    };
  } else if (error instanceof _lib_gramjs__WEBPACK_IMPORTED_MODULE_0__.errors.RPCError) {
    messageKey = {
      key: ERROR_KEYS[error.errorMessage]
    };
  }
  if (!messageKey) {
    if (error.message) {
      messageKey = {
        key: 'ErrorUnexpectedMessage',
        variables: {
          error: error.message
        }
      };
    } else {
      messageKey = {
        key: 'ErrorUnexpected'
      };
    }
  }
  return {
    messageKey,
    errorMessage,
    error
  };
}
function formatWait(seconds) {
  if (seconds < _util_dates_units__WEBPACK_IMPORTED_MODULE_2__.MINUTE) {
    return {
      key: 'Seconds',
      variables: {
        count: seconds
      },
      options: {
        pluralValue: seconds
      }
    };
  }
  if (seconds < _util_dates_units__WEBPACK_IMPORTED_MODULE_2__.HOUR) {
    const minutes = (0,_util_dates_units__WEBPACK_IMPORTED_MODULE_2__.getMinutes)(seconds);
    return {
      key: 'Minutes',
      variables: {
        count: minutes
      },
      options: {
        pluralValue: minutes
      }
    };
  }
  if (seconds < _util_dates_units__WEBPACK_IMPORTED_MODULE_2__.DAY) {
    const hours = (0,_util_dates_units__WEBPACK_IMPORTED_MODULE_2__.getHours)(seconds);
    return {
      key: 'Hours',
      variables: {
        count: hours
      },
      options: {
        pluralValue: hours
      }
    };
  }
  const days = (0,_util_dates_units__WEBPACK_IMPORTED_MODULE_2__.getDays)(seconds);
  return {
    key: 'Days',
    variables: {
      count: days
    },
    options: {
      pluralValue: days
    }
  };
}

/***/ }),

/***/ "./src/api/gramjs/localDb.ts":
/*!***********************************!*\
  !*** ./src/api/gramjs/localDb.ts ***!
  \***********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   broadcastLocalDbUpdateFull: () => (/* binding */ broadcastLocalDbUpdateFull),
/* harmony export */   clearLocalDb: () => (/* binding */ clearLocalDb),
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__),
/* harmony export */   updateFullLocalDb: () => (/* binding */ updateFullLocalDb)
/* harmony export */ });
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! big-integer */ "./node_modules/big-integer/BigInteger.js");
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(big_integer__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../lib/gramjs */ "./src/lib/gramjs/index.ts");
/* harmony import */ var _config__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../config */ "./src/config.ts");
/* harmony import */ var _util_multiaccount__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../util/multiaccount */ "./src/util/multiaccount.ts");
/* harmony import */ var _util_schedulers__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../../util/schedulers */ "./src/util/schedulers.ts");
/* harmony import */ var _apiBuilders_helpers__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./apiBuilders/helpers */ "./src/api/gramjs/apiBuilders/helpers.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];






const channel = new BroadcastChannel(_util_multiaccount__WEBPACK_IMPORTED_MODULE_3__.DATA_BROADCAST_CHANNEL_NAME);
let batchedUpdates = [];
const throttledLocalDbUpdate = (0,_util_schedulers__WEBPACK_IMPORTED_MODULE_4__.throttle)(() => {
  channel.postMessage({
    type: 'localDbUpdate',
    batchedUpdates
  });
  batchedUpdates = [];
}, 100);
function createProxy(name, object) {
  return new Proxy(object, {
    get(target, prop, value) {
      return Reflect.get(target, prop, value);
    },
    set(target, prop, value) {
      batchedUpdates.push({
        name,
        prop,
        value
      });
      throttledLocalDbUpdate();
      return Reflect.set(target, prop, value);
    }
  });
}
function convertToVirtualClass(value) {
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'object' && Object.keys(value).length === 1 && Object.keys(value)[0] === 'value') {
    return big_integer__WEBPACK_IMPORTED_MODULE_0___default()(value.value);
  }
  if (Array.isArray(value)) {
    return value.map(convertToVirtualClass);
  }
  if (typeof value !== 'object' || !('CONSTRUCTOR_ID' in value)) {
    return value;
  }
  const path = value.className.split('.');
  const VirtualClass = path.reduce((acc, field) => {
    return acc[field];
  }, _lib_gramjs__WEBPACK_IMPORTED_MODULE_1__.Api);
  const valueOmited = (0,_apiBuilders_helpers__WEBPACK_IMPORTED_MODULE_5__.omitVirtualClassFields)(value);
  const valueConverted = Object.keys(valueOmited).reduce((acc, key) => {
    acc[key] = convertToVirtualClass(valueOmited[key]);
    return acc;
  }, {});
  return new VirtualClass(valueConverted);
}
function createLocalDbInitial(initial) {
  return ['localMessages', 'chats', 'users', 'messages', 'documents', 'stickerSets', 'photos', 'webDocuments', 'stories', 'commonBoxState', 'channelPtsById'].reduce((acc, key) => {
    const value = initial?.[key] ?? {};
    const convertedValue = Object.keys(value).reduce((acc2, key2) => {
      if (key === 'commonBoxState' || key === 'channelPtsById') {
        const typedValue = value;
        acc2[key2] = typedValue[key2];
        return acc2;
      }
      acc2[key2] = convertToVirtualClass(value[key2]);
      return acc2;
    }, {});
    acc[key] = createProxy(key, convertedValue);
    return acc;
  }, {});
}
const localDb = createLocalDbInitial();
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (localDb);
function broadcastLocalDbUpdateFull() {
  if (!channel) return;
  channel.postMessage({
    type: 'localDbUpdateFull',
    localDb: Object.keys(localDb).reduce((acc, key) => {
      acc[key] = {
        ...localDb[key]
      };
      return acc;
    }, {})
  });
}
function updateFullLocalDb(initial) {
  Object.assign(localDb, createLocalDbInitial(initial));
}
function clearLocalDb() {
  Object.assign(localDb, createLocalDbInitial());
}
if (_config__WEBPACK_IMPORTED_MODULE_2__.DEBUG) {
  globalThis.getLocalDb = () => localDb;
}

/***/ }),

/***/ "./src/api/gramjs/updates/UpdatePremiumFloodWait.ts":
/*!**********************************************************!*\
  !*** ./src/api/gramjs/updates/UpdatePremiumFloodWait.ts ***!
  \**********************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ LocalUpdatePremiumFloodWait)
/* harmony export */ });
class LocalUpdatePremiumFloodWait {
  constructor(isUpload) {
    this.isUpload = isUpload;
  }
}

/***/ }),

/***/ "./src/api/types/bots.ts":
/*!*******************************!*\
  !*** ./src/api/types/bots.ts ***!
  \*******************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);


/***/ }),

/***/ "./src/api/types/business.ts":
/*!***********************************!*\
  !*** ./src/api/types/business.ts ***!
  \***********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);


/***/ }),

/***/ "./src/api/types/calls.ts":
/*!********************************!*\
  !*** ./src/api/types/calls.ts ***!
  \********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);


/***/ }),

/***/ "./src/api/types/chats.ts":
/*!********************************!*\
  !*** ./src/api/types/chats.ts ***!
  \********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);


/***/ }),

/***/ "./src/api/types/index.ts":
/*!********************************!*\
  !*** ./src/api/types/index.ts ***!
  \********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ApiMediaFormat: () => (/* reexport safe */ _media__WEBPACK_IMPORTED_MODULE_4__.ApiMediaFormat),
/* harmony export */   ApiMessageEntityTypes: () => (/* reexport safe */ _messages__WEBPACK_IMPORTED_MODULE_2__.ApiMessageEntityTypes),
/* harmony export */   MAIN_THREAD_ID: () => (/* reexport safe */ _messages__WEBPACK_IMPORTED_MODULE_2__.MAIN_THREAD_ID),
/* harmony export */   MESSAGE_DELETED: () => (/* reexport safe */ _messages__WEBPACK_IMPORTED_MODULE_2__.MESSAGE_DELETED)
/* harmony export */ });
/* harmony import */ var _users__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./users */ "./src/api/types/users.ts");
/* harmony import */ var _chats__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./chats */ "./src/api/types/chats.ts");
/* harmony import */ var _messages__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./messages */ "./src/api/types/messages.ts");
/* harmony import */ var _updates__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./updates */ "./src/api/types/updates.ts");
/* harmony import */ var _media__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./media */ "./src/api/types/media.ts");
/* harmony import */ var _payments__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./payments */ "./src/api/types/payments.ts");
/* harmony import */ var _settings__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./settings */ "./src/api/types/settings.ts");
/* harmony import */ var _bots__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./bots */ "./src/api/types/bots.ts");
/* harmony import */ var _misc__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./misc */ "./src/api/types/misc.ts");
/* harmony import */ var _calls__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./calls */ "./src/api/types/calls.ts");
/* harmony import */ var _statistics__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ./statistics */ "./src/api/types/statistics.ts");
/* harmony import */ var _stories__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ./stories */ "./src/api/types/stories.ts");
/* harmony import */ var _business__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! ./business */ "./src/api/types/business.ts");
/* harmony import */ var _stars__WEBPACK_IMPORTED_MODULE_13__ = __webpack_require__(/*! ./stars */ "./src/api/types/stars.ts");















/***/ }),

/***/ "./src/api/types/media.ts":
/*!********************************!*\
  !*** ./src/api/types/media.ts ***!
  \********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ApiMediaFormat: () => (/* binding */ ApiMediaFormat)
/* harmony export */ });
// We cache avatars as Data URI for faster initial load
// and messages media as Blob for smaller size.

let ApiMediaFormat = /*#__PURE__*/function (ApiMediaFormat) {
  ApiMediaFormat[ApiMediaFormat["BlobUrl"] = 0] = "BlobUrl";
  ApiMediaFormat[ApiMediaFormat["Progressive"] = 1] = "Progressive";
  ApiMediaFormat[ApiMediaFormat["DownloadUrl"] = 2] = "DownloadUrl";
  ApiMediaFormat[ApiMediaFormat["Text"] = 3] = "Text";
  return ApiMediaFormat;
}({});

/***/ }),

/***/ "./src/api/types/messages.ts":
/*!***********************************!*\
  !*** ./src/api/types/messages.ts ***!
  \***********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ApiMessageEntityTypes: () => (/* binding */ ApiMessageEntityTypes),
/* harmony export */   MAIN_THREAD_ID: () => (/* binding */ MAIN_THREAD_ID),
/* harmony export */   MESSAGE_DELETED: () => (/* binding */ MESSAGE_DELETED)
/* harmony export */ });
/**
 * Wrapper with message-specific fields
 */

// Local entities

let ApiMessageEntityTypes = /*#__PURE__*/function (ApiMessageEntityTypes) {
  ApiMessageEntityTypes["Bold"] = "MessageEntityBold";
  ApiMessageEntityTypes["Blockquote"] = "MessageEntityBlockquote";
  ApiMessageEntityTypes["BotCommand"] = "MessageEntityBotCommand";
  ApiMessageEntityTypes["Cashtag"] = "MessageEntityCashtag";
  ApiMessageEntityTypes["Code"] = "MessageEntityCode";
  ApiMessageEntityTypes["Email"] = "MessageEntityEmail";
  ApiMessageEntityTypes["Hashtag"] = "MessageEntityHashtag";
  ApiMessageEntityTypes["Italic"] = "MessageEntityItalic";
  ApiMessageEntityTypes["MentionName"] = "MessageEntityMentionName";
  ApiMessageEntityTypes["Mention"] = "MessageEntityMention";
  ApiMessageEntityTypes["Phone"] = "MessageEntityPhone";
  ApiMessageEntityTypes["Pre"] = "MessageEntityPre";
  ApiMessageEntityTypes["Strike"] = "MessageEntityStrike";
  ApiMessageEntityTypes["TextUrl"] = "MessageEntityTextUrl";
  ApiMessageEntityTypes["Url"] = "MessageEntityUrl";
  ApiMessageEntityTypes["Underline"] = "MessageEntityUnderline";
  ApiMessageEntityTypes["Spoiler"] = "MessageEntitySpoiler";
  ApiMessageEntityTypes["CustomEmoji"] = "MessageEntityCustomEmoji";
  ApiMessageEntityTypes["Timestamp"] = "MessageEntityTimestamp";
  ApiMessageEntityTypes["QuoteFocus"] = "MessageEntityQuoteFocus";
  ApiMessageEntityTypes["Unknown"] = "MessageEntityUnknown";
  return ApiMessageEntityTypes;
}({});

// KeyboardButtons

const MAIN_THREAD_ID = -1;

// `Symbol` can not be transferred from worker
const MESSAGE_DELETED = 'MESSAGE_DELETED';

/***/ }),

/***/ "./src/api/types/misc.ts":
/*!*******************************!*\
  !*** ./src/api/types/misc.ts ***!
  \*******************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);


/***/ }),

/***/ "./src/api/types/payments.ts":
/*!***********************************!*\
  !*** ./src/api/types/payments.ts ***!
  \***********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);


/***/ }),

/***/ "./src/api/types/settings.ts":
/*!***********************************!*\
  !*** ./src/api/types/settings.ts ***!
  \***********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);


/***/ }),

/***/ "./src/api/types/stars.ts":
/*!********************************!*\
  !*** ./src/api/types/stars.ts ***!
  \********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);


/***/ }),

/***/ "./src/api/types/statistics.ts":
/*!*************************************!*\
  !*** ./src/api/types/statistics.ts ***!
  \*************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);


/***/ }),

/***/ "./src/api/types/stories.ts":
/*!**********************************!*\
  !*** ./src/api/types/stories.ts ***!
  \**********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);


/***/ }),

/***/ "./src/api/types/updates.ts":
/*!**********************************!*\
  !*** ./src/api/types/updates.ts ***!
  \**********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);


/***/ }),

/***/ "./src/api/types/users.ts":
/*!********************************!*\
  !*** ./src/api/types/users.ts ***!
  \********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);


/***/ }),

/***/ "./src/config.ts":
/*!***********************!*\
  !*** ./src/config.ts ***!
  \***********************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ACCEPTABLE_USERNAME_ERRORS: () => (/* binding */ ACCEPTABLE_USERNAME_ERRORS),
/* harmony export */   ACCOUNT_QUERY: () => (/* binding */ ACCOUNT_QUERY),
/* harmony export */   ACCOUNT_TTL_OPTIONS: () => (/* binding */ ACCOUNT_TTL_OPTIONS),
/* harmony export */   ALL_FOLDER_ID: () => (/* binding */ ALL_FOLDER_ID),
/* harmony export */   ANIMATION_END_DELAY: () => (/* binding */ ANIMATION_END_DELAY),
/* harmony export */   ANIMATION_LEVEL_CUSTOM: () => (/* binding */ ANIMATION_LEVEL_CUSTOM),
/* harmony export */   ANIMATION_LEVEL_DEFAULT: () => (/* binding */ ANIMATION_LEVEL_DEFAULT),
/* harmony export */   ANIMATION_LEVEL_MAX: () => (/* binding */ ANIMATION_LEVEL_MAX),
/* harmony export */   ANIMATION_LEVEL_MED: () => (/* binding */ ANIMATION_LEVEL_MED),
/* harmony export */   ANIMATION_LEVEL_MIN: () => (/* binding */ ANIMATION_LEVEL_MIN),
/* harmony export */   ANIMATION_WAVE_MIN_INTERVAL: () => (/* binding */ ANIMATION_WAVE_MIN_INTERVAL),
/* harmony export */   ANONYMOUS_USER_ID: () => (/* binding */ ANONYMOUS_USER_ID),
/* harmony export */   API_CHAT_TYPES: () => (/* binding */ API_CHAT_TYPES),
/* harmony export */   API_THROTTLE_RESET_UPDATES: () => (/* binding */ API_THROTTLE_RESET_UPDATES),
/* harmony export */   API_UPDATE_THROTTLE: () => (/* binding */ API_UPDATE_THROTTLE),
/* harmony export */   APP_CODE_NAME: () => (/* binding */ APP_CODE_NAME),
/* harmony export */   APP_CONFIG_REFETCH_INTERVAL: () => (/* binding */ APP_CONFIG_REFETCH_INTERVAL),
/* harmony export */   APP_NAME: () => (/* binding */ APP_NAME),
/* harmony export */   ARCHIVED_FOLDER_ID: () => (/* binding */ ARCHIVED_FOLDER_ID),
/* harmony export */   ARCHIVE_MINIMIZED_HEIGHT: () => (/* binding */ ARCHIVE_MINIMIZED_HEIGHT),
/* harmony export */   ASSET_CACHE_NAME: () => (/* binding */ ASSET_CACHE_NAME),
/* harmony export */   AUTODOWNLOAD_FILESIZE_MB_LIMITS: () => (/* binding */ AUTODOWNLOAD_FILESIZE_MB_LIMITS),
/* harmony export */   BASE_EMOJI_KEYWORD_LANG: () => (/* binding */ BASE_EMOJI_KEYWORD_LANG),
/* harmony export */   BASE_URL: () => (/* binding */ BASE_URL),
/* harmony export */   BETA_CHANGELOG_URL: () => (/* binding */ BETA_CHANGELOG_URL),
/* harmony export */   BIRTHDAY_NUMBERS_SET: () => (/* binding */ BIRTHDAY_NUMBERS_SET),
/* harmony export */   BOOST_PER_SENT_GIFT: () => (/* binding */ BOOST_PER_SENT_GIFT),
/* harmony export */   BOT_FATHER_USERNAME: () => (/* binding */ BOT_FATHER_USERNAME),
/* harmony export */   BOT_VERIFICATION_PEERS_LIMIT: () => (/* binding */ BOT_VERIFICATION_PEERS_LIMIT),
/* harmony export */   CHANNEL_ID_BASE: () => (/* binding */ CHANNEL_ID_BASE),
/* harmony export */   CHAT_HEIGHT_PX: () => (/* binding */ CHAT_HEIGHT_PX),
/* harmony export */   CHAT_LIST_LOAD_SLICE: () => (/* binding */ CHAT_LIST_LOAD_SLICE),
/* harmony export */   CHAT_LIST_SLICE: () => (/* binding */ CHAT_LIST_SLICE),
/* harmony export */   CHAT_MEDIA_SLICE: () => (/* binding */ CHAT_MEDIA_SLICE),
/* harmony export */   CHAT_STICKER_SET_ID: () => (/* binding */ CHAT_STICKER_SET_ID),
/* harmony export */   COLLECTIBLE_STATUS_SET_ID: () => (/* binding */ COLLECTIBLE_STATUS_SET_ID),
/* harmony export */   COMPOSER_EMOJI_SIZE_PICKER: () => (/* binding */ COMPOSER_EMOJI_SIZE_PICKER),
/* harmony export */   CONTENT_TYPES_WITH_PREVIEW: () => (/* binding */ CONTENT_TYPES_WITH_PREVIEW),
/* harmony export */   COUNTRIES_WITH_12H_TIME_FORMAT: () => (/* binding */ COUNTRIES_WITH_12H_TIME_FORMAT),
/* harmony export */   CUSTOM_APPENDIX_ATTRIBUTE: () => (/* binding */ CUSTOM_APPENDIX_ATTRIBUTE),
/* harmony export */   CUSTOM_BG_CACHE_NAME: () => (/* binding */ CUSTOM_BG_CACHE_NAME),
/* harmony export */   DARK_THEME_BG_COLOR: () => (/* binding */ DARK_THEME_BG_COLOR),
/* harmony export */   DARK_THEME_PATTERN_COLOR: () => (/* binding */ DARK_THEME_PATTERN_COLOR),
/* harmony export */   DATA_BROADCAST_CHANNEL_PREFIX: () => (/* binding */ DATA_BROADCAST_CHANNEL_PREFIX),
/* harmony export */   DC_IDS: () => (/* binding */ DC_IDS),
/* harmony export */   DEBUG: () => (/* binding */ DEBUG),
/* harmony export */   DEBUG_ALERT_MSG: () => (/* binding */ DEBUG_ALERT_MSG),
/* harmony export */   DEBUG_GRAMJS: () => (/* binding */ DEBUG_GRAMJS),
/* harmony export */   DEBUG_LOG_FILENAME: () => (/* binding */ DEBUG_LOG_FILENAME),
/* harmony export */   DEBUG_MORE: () => (/* binding */ DEBUG_MORE),
/* harmony export */   DEBUG_PAYMENT_SMART_GLOCAL: () => (/* binding */ DEBUG_PAYMENT_SMART_GLOCAL),
/* harmony export */   DEFAULT_CHARGE_FOR_MESSAGES: () => (/* binding */ DEFAULT_CHARGE_FOR_MESSAGES),
/* harmony export */   DEFAULT_GIFT_PROFILE_FILTER_OPTIONS: () => (/* binding */ DEFAULT_GIFT_PROFILE_FILTER_OPTIONS),
/* harmony export */   DEFAULT_GIF_SEARCH_BOT_USERNAME: () => (/* binding */ DEFAULT_GIF_SEARCH_BOT_USERNAME),
/* harmony export */   DEFAULT_MAXIMUM_CHARGE_FOR_MESSAGES: () => (/* binding */ DEFAULT_MAXIMUM_CHARGE_FOR_MESSAGES),
/* harmony export */   DEFAULT_MESSAGE_TEXT_SIZE_PX: () => (/* binding */ DEFAULT_MESSAGE_TEXT_SIZE_PX),
/* harmony export */   DEFAULT_PATTERN_COLOR: () => (/* binding */ DEFAULT_PATTERN_COLOR),
/* harmony export */   DEFAULT_PLAYBACK_RATE: () => (/* binding */ DEFAULT_PLAYBACK_RATE),
/* harmony export */   DEFAULT_RESALE_GIFTS_FILTER_OPTIONS: () => (/* binding */ DEFAULT_RESALE_GIFTS_FILTER_OPTIONS),
/* harmony export */   DEFAULT_STATUS_ICON_ID: () => (/* binding */ DEFAULT_STATUS_ICON_ID),
/* harmony export */   DEFAULT_TOPIC_ICON_STICKER_ID: () => (/* binding */ DEFAULT_TOPIC_ICON_STICKER_ID),
/* harmony export */   DEFAULT_VOLUME: () => (/* binding */ DEFAULT_VOLUME),
/* harmony export */   DELETED_COMMENTS_CHANNEL_ID: () => (/* binding */ DELETED_COMMENTS_CHANNEL_ID),
/* harmony export */   DOWNLOAD_WORKERS: () => (/* binding */ DOWNLOAD_WORKERS),
/* harmony export */   DRAFT_DEBOUNCE: () => (/* binding */ DRAFT_DEBOUNCE),
/* harmony export */   EDITABLE_INPUT_CSS_SELECTOR: () => (/* binding */ EDITABLE_INPUT_CSS_SELECTOR),
/* harmony export */   EDITABLE_INPUT_ID: () => (/* binding */ EDITABLE_INPUT_ID),
/* harmony export */   EDITABLE_INPUT_MODAL_CSS_SELECTOR: () => (/* binding */ EDITABLE_INPUT_MODAL_CSS_SELECTOR),
/* harmony export */   EDITABLE_INPUT_MODAL_ID: () => (/* binding */ EDITABLE_INPUT_MODAL_ID),
/* harmony export */   EDITABLE_STORY_INPUT_CSS_SELECTOR: () => (/* binding */ EDITABLE_STORY_INPUT_CSS_SELECTOR),
/* harmony export */   EDITABLE_STORY_INPUT_ID: () => (/* binding */ EDITABLE_STORY_INPUT_ID),
/* harmony export */   EFFECT_EMOJIS_SET_ID: () => (/* binding */ EFFECT_EMOJIS_SET_ID),
/* harmony export */   EFFECT_STICKERS_SET_ID: () => (/* binding */ EFFECT_STICKERS_SET_ID),
/* harmony export */   ELECTRON_HOST_URL: () => (/* binding */ ELECTRON_HOST_URL),
/* harmony export */   ELECTRON_WINDOW_DRAG_EVENT_END: () => (/* binding */ ELECTRON_WINDOW_DRAG_EVENT_END),
/* harmony export */   ELECTRON_WINDOW_DRAG_EVENT_START: () => (/* binding */ ELECTRON_WINDOW_DRAG_EVENT_START),
/* harmony export */   EMOJI_IMG_REGEX: () => (/* binding */ EMOJI_IMG_REGEX),
/* harmony export */   EMOJI_SIZES: () => (/* binding */ EMOJI_SIZES),
/* harmony export */   EMOJI_SIZE_MODAL: () => (/* binding */ EMOJI_SIZE_MODAL),
/* harmony export */   EMOJI_SIZE_PICKER: () => (/* binding */ EMOJI_SIZE_PICKER),
/* harmony export */   EMOJI_STATUS_LOOP_LIMIT: () => (/* binding */ EMOJI_STATUS_LOOP_LIMIT),
/* harmony export */   ESTABLISH_BROADCAST_CHANNEL_PREFIX: () => (/* binding */ ESTABLISH_BROADCAST_CHANNEL_PREFIX),
/* harmony export */   FAQ_URL: () => (/* binding */ FAQ_URL),
/* harmony export */   FAVORITE_SYMBOL_SET_ID: () => (/* binding */ FAVORITE_SYMBOL_SET_ID),
/* harmony export */   FEEDBACK_URL: () => (/* binding */ FEEDBACK_URL),
/* harmony export */   FRAGMENT_ADS_URL: () => (/* binding */ FRAGMENT_ADS_URL),
/* harmony export */   FRAGMENT_PHONE_CODE: () => (/* binding */ FRAGMENT_PHONE_CODE),
/* harmony export */   FRAGMENT_PHONE_LENGTH: () => (/* binding */ FRAGMENT_PHONE_LENGTH),
/* harmony export */   FRESH_AUTH_PERIOD: () => (/* binding */ FRESH_AUTH_PERIOD),
/* harmony export */   GENERAL_REFETCH_INTERVAL: () => (/* binding */ GENERAL_REFETCH_INTERVAL),
/* harmony export */   GENERAL_TOPIC_ID: () => (/* binding */ GENERAL_TOPIC_ID),
/* harmony export */   GIF_MIME_TYPE: () => (/* binding */ GIF_MIME_TYPE),
/* harmony export */   GIVEAWAY_BOOST_PER_PREMIUM: () => (/* binding */ GIVEAWAY_BOOST_PER_PREMIUM),
/* harmony export */   GIVEAWAY_MAX_ADDITIONAL_CHANNELS: () => (/* binding */ GIVEAWAY_MAX_ADDITIONAL_CHANNELS),
/* harmony export */   GIVEAWAY_MAX_ADDITIONAL_COUNTRIES: () => (/* binding */ GIVEAWAY_MAX_ADDITIONAL_COUNTRIES),
/* harmony export */   GIVEAWAY_MAX_ADDITIONAL_USERS: () => (/* binding */ GIVEAWAY_MAX_ADDITIONAL_USERS),
/* harmony export */   GLOBAL_SEARCH_SLICE: () => (/* binding */ GLOBAL_SEARCH_SLICE),
/* harmony export */   GLOBAL_STATE_CACHE_ARCHIVED_CHAT_LIST_LIMIT: () => (/* binding */ GLOBAL_STATE_CACHE_ARCHIVED_CHAT_LIST_LIMIT),
/* harmony export */   GLOBAL_STATE_CACHE_CHAT_LIST_LIMIT: () => (/* binding */ GLOBAL_STATE_CACHE_CHAT_LIST_LIMIT),
/* harmony export */   GLOBAL_STATE_CACHE_CUSTOM_EMOJI_LIMIT: () => (/* binding */ GLOBAL_STATE_CACHE_CUSTOM_EMOJI_LIMIT),
/* harmony export */   GLOBAL_STATE_CACHE_DISABLED: () => (/* binding */ GLOBAL_STATE_CACHE_DISABLED),
/* harmony export */   GLOBAL_STATE_CACHE_PREFIX: () => (/* binding */ GLOBAL_STATE_CACHE_PREFIX),
/* harmony export */   GLOBAL_STATE_CACHE_USER_LIST_LIMIT: () => (/* binding */ GLOBAL_STATE_CACHE_USER_LIST_LIMIT),
/* harmony export */   GLOBAL_SUGGESTED_CHANNELS_ID: () => (/* binding */ GLOBAL_SUGGESTED_CHANNELS_ID),
/* harmony export */   GLOBAL_TOPIC_SEARCH_SLICE: () => (/* binding */ GLOBAL_TOPIC_SEARCH_SLICE),
/* harmony export */   GROUP_CALL_DEFAULT_VOLUME: () => (/* binding */ GROUP_CALL_DEFAULT_VOLUME),
/* harmony export */   GROUP_CALL_VOLUME_MULTIPLIER: () => (/* binding */ GROUP_CALL_VOLUME_MULTIPLIER),
/* harmony export */   HEART_REACTION: () => (/* binding */ HEART_REACTION),
/* harmony export */   IGNORE_UNHANDLED_ERRORS: () => (/* binding */ IGNORE_UNHANDLED_ERRORS),
/* harmony export */   INACTIVE_MARKER: () => (/* binding */ INACTIVE_MARKER),
/* harmony export */   IOS_DEFAULT_MESSAGE_TEXT_SIZE_PX: () => (/* binding */ IOS_DEFAULT_MESSAGE_TEXT_SIZE_PX),
/* harmony export */   IS_BETA: () => (/* binding */ IS_BETA),
/* harmony export */   IS_MOCKED_CLIENT: () => (/* binding */ IS_MOCKED_CLIENT),
/* harmony export */   IS_PACKAGED_ELECTRON: () => (/* binding */ IS_PACKAGED_ELECTRON),
/* harmony export */   IS_PERF: () => (/* binding */ IS_PERF),
/* harmony export */   IS_SCREEN_LOCKED_CACHE_KEY: () => (/* binding */ IS_SCREEN_LOCKED_CACHE_KEY),
/* harmony export */   IS_TEST: () => (/* binding */ IS_TEST),
/* harmony export */   LANG_CACHE_NAME: () => (/* binding */ LANG_CACHE_NAME),
/* harmony export */   LANG_PACK: () => (/* binding */ LANG_PACK),
/* harmony export */   LANG_PACKS: () => (/* binding */ LANG_PACKS),
/* harmony export */   LEGACY_PASSCODE_CACHE_NAME: () => (/* binding */ LEGACY_PASSCODE_CACHE_NAME),
/* harmony export */   LIGHT_THEME_BG_COLOR: () => (/* binding */ LIGHT_THEME_BG_COLOR),
/* harmony export */   LOCK_SCREEN_ANIMATION_DURATION_MS: () => (/* binding */ LOCK_SCREEN_ANIMATION_DURATION_MS),
/* harmony export */   LOTTIE_STICKER_MIME_TYPE: () => (/* binding */ LOTTIE_STICKER_MIME_TYPE),
/* harmony export */   MACOS_DEFAULT_MESSAGE_TEXT_SIZE_PX: () => (/* binding */ MACOS_DEFAULT_MESSAGE_TEXT_SIZE_PX),
/* harmony export */   MAX_ACTIVE_PINNED_CHATS: () => (/* binding */ MAX_ACTIVE_PINNED_CHATS),
/* harmony export */   MAX_INT_32: () => (/* binding */ MAX_INT_32),
/* harmony export */   MAX_MEDIA_FILES_FOR_ALBUM: () => (/* binding */ MAX_MEDIA_FILES_FOR_ALBUM),
/* harmony export */   MAX_UPLOAD_FILEPART_SIZE: () => (/* binding */ MAX_UPLOAD_FILEPART_SIZE),
/* harmony export */   MEDIA_CACHE_DISABLED: () => (/* binding */ MEDIA_CACHE_DISABLED),
/* harmony export */   MEDIA_CACHE_MAX_BYTES: () => (/* binding */ MEDIA_CACHE_MAX_BYTES),
/* harmony export */   MEDIA_CACHE_NAME: () => (/* binding */ MEDIA_CACHE_NAME),
/* harmony export */   MEDIA_CACHE_NAME_AVATARS: () => (/* binding */ MEDIA_CACHE_NAME_AVATARS),
/* harmony export */   MEDIA_PROGRESSIVE_CACHE_DISABLED: () => (/* binding */ MEDIA_PROGRESSIVE_CACHE_DISABLED),
/* harmony export */   MEDIA_PROGRESSIVE_CACHE_NAME: () => (/* binding */ MEDIA_PROGRESSIVE_CACHE_NAME),
/* harmony export */   MEDIA_TIMESTAMP_SAVE_MINIMUM_DURATION: () => (/* binding */ MEDIA_TIMESTAMP_SAVE_MINIMUM_DURATION),
/* harmony export */   MEMBERS_LOAD_SLICE: () => (/* binding */ MEMBERS_LOAD_SLICE),
/* harmony export */   MEMBERS_SLICE: () => (/* binding */ MEMBERS_SLICE),
/* harmony export */   MENTION_UNREAD_SLICE: () => (/* binding */ MENTION_UNREAD_SLICE),
/* harmony export */   MENU_TRANSITION_DURATION: () => (/* binding */ MENU_TRANSITION_DURATION),
/* harmony export */   MESSAGE_APPEARANCE_DELAY: () => (/* binding */ MESSAGE_APPEARANCE_DELAY),
/* harmony export */   MESSAGE_CONTENT_CLASS_NAME: () => (/* binding */ MESSAGE_CONTENT_CLASS_NAME),
/* harmony export */   MESSAGE_CONTENT_SELECTOR: () => (/* binding */ MESSAGE_CONTENT_SELECTOR),
/* harmony export */   MESSAGE_ID_REQUIRED_ERROR: () => (/* binding */ MESSAGE_ID_REQUIRED_ERROR),
/* harmony export */   MESSAGE_LIST_SLICE: () => (/* binding */ MESSAGE_LIST_SLICE),
/* harmony export */   MESSAGE_LIST_VIEWPORT_LIMIT: () => (/* binding */ MESSAGE_LIST_VIEWPORT_LIMIT),
/* harmony export */   MESSAGE_SEARCH_SLICE: () => (/* binding */ MESSAGE_SEARCH_SLICE),
/* harmony export */   MINIMUM_CHARGE_FOR_MESSAGES: () => (/* binding */ MINIMUM_CHARGE_FOR_MESSAGES),
/* harmony export */   MINI_APP_TOS_URL: () => (/* binding */ MINI_APP_TOS_URL),
/* harmony export */   MIN_PASSWORD_LENGTH: () => (/* binding */ MIN_PASSWORD_LENGTH),
/* harmony export */   MIN_SCREEN_WIDTH_FOR_STATIC_LEFT_COLUMN: () => (/* binding */ MIN_SCREEN_WIDTH_FOR_STATIC_LEFT_COLUMN),
/* harmony export */   MIN_SCREEN_WIDTH_FOR_STATIC_RIGHT_COLUMN: () => (/* binding */ MIN_SCREEN_WIDTH_FOR_STATIC_RIGHT_COLUMN),
/* harmony export */   MOBILE_SCREEN_LANDSCAPE_MAX_HEIGHT: () => (/* binding */ MOBILE_SCREEN_LANDSCAPE_MAX_HEIGHT),
/* harmony export */   MOBILE_SCREEN_LANDSCAPE_MAX_WIDTH: () => (/* binding */ MOBILE_SCREEN_LANDSCAPE_MAX_WIDTH),
/* harmony export */   MOBILE_SCREEN_MAX_WIDTH: () => (/* binding */ MOBILE_SCREEN_MAX_WIDTH),
/* harmony export */   MULTIACCOUNT_MAX_SLOTS: () => (/* binding */ MULTIACCOUNT_MAX_SLOTS),
/* harmony export */   MULTITAB_LOCALSTORAGE_KEY_PREFIX: () => (/* binding */ MULTITAB_LOCALSTORAGE_KEY_PREFIX),
/* harmony export */   NSFW_RESTRICTION_REASON: () => (/* binding */ NSFW_RESTRICTION_REASON),
/* harmony export */   ONE_TIME_MEDIA_TTL_SECONDS: () => (/* binding */ ONE_TIME_MEDIA_TTL_SECONDS),
/* harmony export */   PAGE_TITLE: () => (/* binding */ PAGE_TITLE),
/* harmony export */   PAID_MESSAGES_PURPOSE: () => (/* binding */ PAID_MESSAGES_PURPOSE),
/* harmony export */   PAID_SEND_DELAY: () => (/* binding */ PAID_SEND_DELAY),
/* harmony export */   PEER_COLOR_BG_ACTIVE_OPACITY: () => (/* binding */ PEER_COLOR_BG_ACTIVE_OPACITY),
/* harmony export */   PEER_COLOR_BG_OPACITY: () => (/* binding */ PEER_COLOR_BG_OPACITY),
/* harmony export */   PEER_COLOR_GRADIENT_STEP: () => (/* binding */ PEER_COLOR_GRADIENT_STEP),
/* harmony export */   PEER_PICKER_ITEM_HEIGHT_PX: () => (/* binding */ PEER_PICKER_ITEM_HEIGHT_PX),
/* harmony export */   PLAYBACK_RATE_FOR_AUDIO_MIN_DURATION: () => (/* binding */ PLAYBACK_RATE_FOR_AUDIO_MIN_DURATION),
/* harmony export */   POPULAR_SYMBOL_SET_ID: () => (/* binding */ POPULAR_SYMBOL_SET_ID),
/* harmony export */   PREMIUM_BOTTOM_VIDEOS: () => (/* binding */ PREMIUM_BOTTOM_VIDEOS),
/* harmony export */   PREMIUM_FEATURE_SECTIONS: () => (/* binding */ PREMIUM_FEATURE_SECTIONS),
/* harmony export */   PREMIUM_LIMITS_ORDER: () => (/* binding */ PREMIUM_LIMITS_ORDER),
/* harmony export */   PREVIEW_AVATAR_COUNT: () => (/* binding */ PREVIEW_AVATAR_COUNT),
/* harmony export */   PRIVACY_URL: () => (/* binding */ PRIVACY_URL),
/* harmony export */   PRODUCTION_HOSTNAME: () => (/* binding */ PRODUCTION_HOSTNAME),
/* harmony export */   PRODUCTION_URL: () => (/* binding */ PRODUCTION_URL),
/* harmony export */   PROFILE_SENSITIVE_AREA: () => (/* binding */ PROFILE_SENSITIVE_AREA),
/* harmony export */   PUBLIC_POSTS_SEARCH_DEFAULT_STARS_AMOUNT: () => (/* binding */ PUBLIC_POSTS_SEARCH_DEFAULT_STARS_AMOUNT),
/* harmony export */   PUBLIC_POSTS_SEARCH_DEFAULT_TOTAL_DAILY: () => (/* binding */ PUBLIC_POSTS_SEARCH_DEFAULT_TOTAL_DAILY),
/* harmony export */   PURCHASE_USERNAME: () => (/* binding */ PURCHASE_USERNAME),
/* harmony export */   REACTION_UNREAD_SLICE: () => (/* binding */ REACTION_UNREAD_SLICE),
/* harmony export */   RECENT_STATUS_LIMIT: () => (/* binding */ RECENT_STATUS_LIMIT),
/* harmony export */   RECENT_STICKERS_LIMIT: () => (/* binding */ RECENT_STICKERS_LIMIT),
/* harmony export */   RECENT_SYMBOL_SET_ID: () => (/* binding */ RECENT_SYMBOL_SET_ID),
/* harmony export */   RELEASE_DATETIME: () => (/* binding */ RELEASE_DATETIME),
/* harmony export */   REPLIES_USER_ID: () => (/* binding */ REPLIES_USER_ID),
/* harmony export */   RESIZE_HANDLE_CLASS_NAME: () => (/* binding */ RESIZE_HANDLE_CLASS_NAME),
/* harmony export */   RESIZE_HANDLE_SELECTOR: () => (/* binding */ RESIZE_HANDLE_SELECTOR),
/* harmony export */   RESTRICTED_EMOJI_SET: () => (/* binding */ RESTRICTED_EMOJI_SET),
/* harmony export */   RESTRICTED_EMOJI_SET_ID: () => (/* binding */ RESTRICTED_EMOJI_SET_ID),
/* harmony export */   RE_LINK_TEMPLATE: () => (/* binding */ RE_LINK_TEMPLATE),
/* harmony export */   RE_MENTION_TEMPLATE: () => (/* binding */ RE_MENTION_TEMPLATE),
/* harmony export */   RE_TELEGRAM_LINK: () => (/* binding */ RE_TELEGRAM_LINK),
/* harmony export */   RE_TG_LINK: () => (/* binding */ RE_TG_LINK),
/* harmony export */   RE_TME_LINK: () => (/* binding */ RE_TME_LINK),
/* harmony export */   SAVED_FOLDER_ID: () => (/* binding */ SAVED_FOLDER_ID),
/* harmony export */   SCHEDULED_WHEN_ONLINE: () => (/* binding */ SCHEDULED_WHEN_ONLINE),
/* harmony export */   SCROLL_MAX_DISTANCE: () => (/* binding */ SCROLL_MAX_DISTANCE),
/* harmony export */   SCROLL_MAX_DURATION: () => (/* binding */ SCROLL_MAX_DURATION),
/* harmony export */   SCROLL_MIN_DURATION: () => (/* binding */ SCROLL_MIN_DURATION),
/* harmony export */   SCROLL_SHORT_TRANSITION_MAX_DISTANCE: () => (/* binding */ SCROLL_SHORT_TRANSITION_MAX_DISTANCE),
/* harmony export */   SEND_MESSAGE_ACTION_INTERVAL: () => (/* binding */ SEND_MESSAGE_ACTION_INTERVAL),
/* harmony export */   SERVICE_NOTIFICATIONS_USER_ID: () => (/* binding */ SERVICE_NOTIFICATIONS_USER_ID),
/* harmony export */   SESSION_ACCOUNT_PREFIX: () => (/* binding */ SESSION_ACCOUNT_PREFIX),
/* harmony export */   SESSION_LEGACY_USER_KEY: () => (/* binding */ SESSION_LEGACY_USER_KEY),
/* harmony export */   SHARED_MEDIA_SLICE: () => (/* binding */ SHARED_MEDIA_SLICE),
/* harmony export */   SHARED_STATE_CACHE_KEY: () => (/* binding */ SHARED_STATE_CACHE_KEY),
/* harmony export */   SLIDE_TRANSITION_DURATION: () => (/* binding */ SLIDE_TRANSITION_DURATION),
/* harmony export */   SNAP_EFFECT_CONTAINER_ID: () => (/* binding */ SNAP_EFFECT_CONTAINER_ID),
/* harmony export */   SNAP_EFFECT_ID: () => (/* binding */ SNAP_EFFECT_ID),
/* harmony export */   SPONSORED_MESSAGE_CACHE_MS: () => (/* binding */ SPONSORED_MESSAGE_CACHE_MS),
/* harmony export */   STARS_CURRENCY_CODE: () => (/* binding */ STARS_CURRENCY_CODE),
/* harmony export */   STARS_ICON_PLACEHOLDER: () => (/* binding */ STARS_ICON_PLACEHOLDER),
/* harmony export */   STICKER_PICKER_MAX_SHARED_COVERS: () => (/* binding */ STICKER_PICKER_MAX_SHARED_COVERS),
/* harmony export */   STICKER_SIZE_AUTH: () => (/* binding */ STICKER_SIZE_AUTH),
/* harmony export */   STICKER_SIZE_AUTH_MOBILE: () => (/* binding */ STICKER_SIZE_AUTH_MOBILE),
/* harmony export */   STICKER_SIZE_DISCUSSION_GROUPS: () => (/* binding */ STICKER_SIZE_DISCUSSION_GROUPS),
/* harmony export */   STICKER_SIZE_FOLDER_SETTINGS: () => (/* binding */ STICKER_SIZE_FOLDER_SETTINGS),
/* harmony export */   STICKER_SIZE_GENERAL_SETTINGS: () => (/* binding */ STICKER_SIZE_GENERAL_SETTINGS),
/* harmony export */   STICKER_SIZE_INLINE_BOT_RESULT: () => (/* binding */ STICKER_SIZE_INLINE_BOT_RESULT),
/* harmony export */   STICKER_SIZE_INLINE_DESKTOP_FACTOR: () => (/* binding */ STICKER_SIZE_INLINE_DESKTOP_FACTOR),
/* harmony export */   STICKER_SIZE_INLINE_MOBILE_FACTOR: () => (/* binding */ STICKER_SIZE_INLINE_MOBILE_FACTOR),
/* harmony export */   STICKER_SIZE_INVITES: () => (/* binding */ STICKER_SIZE_INVITES),
/* harmony export */   STICKER_SIZE_JOIN_REQUESTS: () => (/* binding */ STICKER_SIZE_JOIN_REQUESTS),
/* harmony export */   STICKER_SIZE_MODAL: () => (/* binding */ STICKER_SIZE_MODAL),
/* harmony export */   STICKER_SIZE_PASSCODE: () => (/* binding */ STICKER_SIZE_PASSCODE),
/* harmony export */   STICKER_SIZE_PICKER: () => (/* binding */ STICKER_SIZE_PICKER),
/* harmony export */   STICKER_SIZE_PICKER_HEADER: () => (/* binding */ STICKER_SIZE_PICKER_HEADER),
/* harmony export */   STICKER_SIZE_SEARCH: () => (/* binding */ STICKER_SIZE_SEARCH),
/* harmony export */   STICKER_SIZE_TWO_FA: () => (/* binding */ STICKER_SIZE_TWO_FA),
/* harmony export */   STORY_EXPIRE_PERIOD: () => (/* binding */ STORY_EXPIRE_PERIOD),
/* harmony export */   STORY_MIN_REACTIONS_SORT: () => (/* binding */ STORY_MIN_REACTIONS_SORT),
/* harmony export */   STORY_VIEWERS_EXPIRE_PERIOD: () => (/* binding */ STORY_VIEWERS_EXPIRE_PERIOD),
/* harmony export */   STORY_VIEWS_MIN_CONTACTS_FILTER: () => (/* binding */ STORY_VIEWS_MIN_CONTACTS_FILTER),
/* harmony export */   STORY_VIEWS_MIN_SEARCH: () => (/* binding */ STORY_VIEWS_MIN_SEARCH),
/* harmony export */   STRICTERDOM_ENABLED: () => (/* binding */ STRICTERDOM_ENABLED),
/* harmony export */   SUPPORTED_AUDIO_CONTENT_TYPES: () => (/* binding */ SUPPORTED_AUDIO_CONTENT_TYPES),
/* harmony export */   SUPPORTED_PHOTO_CONTENT_TYPES: () => (/* binding */ SUPPORTED_PHOTO_CONTENT_TYPES),
/* harmony export */   SUPPORTED_TRANSLATION_LANGUAGES: () => (/* binding */ SUPPORTED_TRANSLATION_LANGUAGES),
/* harmony export */   SUPPORTED_VIDEO_CONTENT_TYPES: () => (/* binding */ SUPPORTED_VIDEO_CONTENT_TYPES),
/* harmony export */   SVG_EXTENSIONS: () => (/* binding */ SVG_EXTENSIONS),
/* harmony export */   SVG_NAMESPACE: () => (/* binding */ SVG_NAMESPACE),
/* harmony export */   TME_LINK_PREFIX: () => (/* binding */ TME_LINK_PREFIX),
/* harmony export */   TME_WEB_DOMAINS: () => (/* binding */ TME_WEB_DOMAINS),
/* harmony export */   TMP_CHAT_ID: () => (/* binding */ TMP_CHAT_ID),
/* harmony export */   TON_CURRENCY_CODE: () => (/* binding */ TON_CURRENCY_CODE),
/* harmony export */   TOPICS_SLICE: () => (/* binding */ TOPICS_SLICE),
/* harmony export */   TOPICS_SLICE_SECOND_LOAD: () => (/* binding */ TOPICS_SLICE_SECOND_LOAD),
/* harmony export */   TOPIC_HEIGHT_PX: () => (/* binding */ TOPIC_HEIGHT_PX),
/* harmony export */   TOPIC_LIST_SENSITIVE_AREA: () => (/* binding */ TOPIC_LIST_SENSITIVE_AREA),
/* harmony export */   TOP_CHAT_MESSAGES_PRELOAD_LIMIT: () => (/* binding */ TOP_CHAT_MESSAGES_PRELOAD_LIMIT),
/* harmony export */   TOP_SYMBOL_SET_ID: () => (/* binding */ TOP_SYMBOL_SET_ID),
/* harmony export */   UPLOAD_WORKERS: () => (/* binding */ UPLOAD_WORKERS),
/* harmony export */   USERNAME_PURCHASE_ERROR: () => (/* binding */ USERNAME_PURCHASE_ERROR),
/* harmony export */   VERIFICATION_CODES_USER_ID: () => (/* binding */ VERIFICATION_CODES_USER_ID),
/* harmony export */   VERIFY_AGE_MIN_DEFAULT: () => (/* binding */ VERIFY_AGE_MIN_DEFAULT),
/* harmony export */   VIDEO_STICKER_MIME_TYPE: () => (/* binding */ VIDEO_STICKER_MIME_TYPE),
/* harmony export */   VIDEO_WEBM_TYPE: () => (/* binding */ VIDEO_WEBM_TYPE),
/* harmony export */   VIEW_TRANSITION_CLASS_NAME: () => (/* binding */ VIEW_TRANSITION_CLASS_NAME),
/* harmony export */   WEB_APP_PLATFORM: () => (/* binding */ WEB_APP_PLATFORM),
/* harmony export */   WEB_VERSION_BASE: () => (/* binding */ WEB_VERSION_BASE)
/* harmony export */ });
const APP_CODE_NAME = 'A';
const APP_NAME =  false || `Telegram Web ${APP_CODE_NAME}`;
const RELEASE_DATETIME = 1757630017257;
const PRODUCTION_HOSTNAME = 'web.telegram.org';
const PRODUCTION_URL = 'https://web.telegram.org/a';
const WEB_VERSION_BASE = 'https://web.telegram.org/'; // Used to redirect to other versions
const BASE_URL = "https://web.telegram.org/a";
const ACCOUNT_QUERY = 'account';
const IS_MOCKED_CLIENT = "" === '1';
const IS_TEST = "development" === 'test';
const IS_PERF = "development" === 'perf';
const IS_BETA = "development" === 'staging';
const IS_PACKAGED_ELECTRON = false;
const ELECTRON_WINDOW_DRAG_EVENT_START = 'tt-electron-window-drag-start';
const ELECTRON_WINDOW_DRAG_EVENT_END = 'tt-electron-window-drag-end';
const PAID_MESSAGES_PURPOSE = 'paid_messages';
const DEBUG = "development" !== 'production';
const DEBUG_MORE = false;
const DEBUG_LOG_FILENAME = 'tt-log.json';
const STRICTERDOM_ENABLED = DEBUG;
const BOT_VERIFICATION_PEERS_LIMIT = 20;
const BETA_CHANGELOG_URL = 'https://telegra.ph/WebA-Beta-03-20';
const ELECTRON_HOST_URL = "https://telegram-a-host";
const DEBUG_ALERT_MSG = 'Shoot!\nSomething went wrong, please see the error details in Dev Tools Console.';
const DEBUG_GRAMJS = false;
const PAGE_TITLE = "Telegram Web A";
const INACTIVE_MARKER = '[Inactive]';
const DEBUG_PAYMENT_SMART_GLOCAL = false;
const SESSION_LEGACY_USER_KEY = 'user_auth';
const SESSION_ACCOUNT_PREFIX = 'account';
const LEGACY_PASSCODE_CACHE_NAME = 'tt-passcode';
const MULTIACCOUNT_MAX_SLOTS = 6;
const GLOBAL_STATE_CACHE_DISABLED = false;
const GLOBAL_STATE_CACHE_PREFIX = 'tt-global-state';
const SHARED_STATE_CACHE_KEY = 'tt-shared-state';
const GLOBAL_STATE_CACHE_USER_LIST_LIMIT = 500;
const GLOBAL_STATE_CACHE_CHAT_LIST_LIMIT = 200;
const GLOBAL_STATE_CACHE_ARCHIVED_CHAT_LIST_LIMIT = 10;
const GLOBAL_STATE_CACHE_CUSTOM_EMOJI_LIMIT = 150;
const IS_SCREEN_LOCKED_CACHE_KEY = 'tt-is-screen-locked';
const MEDIA_CACHE_DISABLED = false;
const MEDIA_CACHE_NAME = 'tt-media';
const MEDIA_CACHE_NAME_AVATARS = 'tt-media-avatars';
const MEDIA_PROGRESSIVE_CACHE_DISABLED = false;
const MEDIA_PROGRESSIVE_CACHE_NAME = 'tt-media-progressive';
const MEDIA_CACHE_MAX_BYTES = 512 * 1024; // 512 KB
const CUSTOM_BG_CACHE_NAME = 'tt-custom-bg';
const LANG_CACHE_NAME = 'tt-lang-packs-v50';
const ASSET_CACHE_NAME = 'tt-assets';
const AUTODOWNLOAD_FILESIZE_MB_LIMITS = [1, 5, 10, 50, 100, 500];
const DATA_BROADCAST_CHANNEL_PREFIX = 'tt-global';
const ESTABLISH_BROADCAST_CHANNEL_PREFIX = 'tt-establish';
const MULTITAB_LOCALSTORAGE_KEY_PREFIX = 'tt-multitab';
const DC_IDS = [1, 2, 3, 4, 5];
const DOWNLOAD_WORKERS = 16;
const UPLOAD_WORKERS = 16;
const isBigScreen = typeof window !== 'undefined' && window.innerHeight >= 900;
const MIN_PASSWORD_LENGTH = 1;
const MESSAGE_LIST_SLICE = isBigScreen ? 60 : 40;
const MESSAGE_LIST_VIEWPORT_LIMIT = MESSAGE_LIST_SLICE * 2;
const ARCHIVE_MINIMIZED_HEIGHT = 36;
const CHAT_HEIGHT_PX = 72;
const TOPIC_HEIGHT_PX = 65;
const PEER_PICKER_ITEM_HEIGHT_PX = 56;
const CHAT_LIST_SLICE = isBigScreen ? 30 : 25;
const CHAT_LIST_LOAD_SLICE = 100;
const SHARED_MEDIA_SLICE = 42;
const CHAT_MEDIA_SLICE = 42;
const MESSAGE_SEARCH_SLICE = 42;
const GLOBAL_SEARCH_SLICE = 20;
const GLOBAL_TOPIC_SEARCH_SLICE = 5;
const MEMBERS_SLICE = 30;
const MEMBERS_LOAD_SLICE = 200;
const PROFILE_SENSITIVE_AREA = 500;
const TOPIC_LIST_SENSITIVE_AREA = 600;

// Public Posts Search defaults
const PUBLIC_POSTS_SEARCH_DEFAULT_STARS_AMOUNT = 10;
const PUBLIC_POSTS_SEARCH_DEFAULT_TOTAL_DAILY = 2;

// Suggested Posts defaults
const TON_CURRENCY_CODE = 'TON';
const VERIFY_AGE_MIN_DEFAULT = 18;
const STORY_VIEWS_MIN_SEARCH = 15;
const STORY_MIN_REACTIONS_SORT = 10;
const STORY_VIEWS_MIN_CONTACTS_FILTER = 20;
const MEDIA_TIMESTAMP_SAVE_MINIMUM_DURATION = 30; // 30s

const GLOBAL_SUGGESTED_CHANNELS_ID = 'global';

// As in Telegram for Android
// https://github.com/DrKLO/Telegram/blob/51e9947527/TMessagesProj/src/main/java/org/telegram/messenger/MediaDataController.java#L7781
const REACTION_UNREAD_SLICE = 100;
const MENTION_UNREAD_SLICE = 100;
const TOPICS_SLICE = 20;
const TOPICS_SLICE_SECOND_LOAD = 500;
const TOP_CHAT_MESSAGES_PRELOAD_LIMIT = 20;
const SPONSORED_MESSAGE_CACHE_MS = 300000; // 5 min

const DEFAULT_CHARGE_FOR_MESSAGES = 250;
const MINIMUM_CHARGE_FOR_MESSAGES = 1;
const DEFAULT_MAXIMUM_CHARGE_FOR_MESSAGES = 10000;
const DEFAULT_VOLUME = 1;
const DEFAULT_PLAYBACK_RATE = 1;
const PLAYBACK_RATE_FOR_AUDIO_MIN_DURATION = 20 * 60; // 20 min

const ANIMATION_LEVEL_CUSTOM = -1;
const ANIMATION_LEVEL_MIN = 0;
const ANIMATION_LEVEL_MED = 1;
const ANIMATION_LEVEL_MAX = 2;
const ANIMATION_LEVEL_DEFAULT = ANIMATION_LEVEL_MED;
const DEFAULT_MESSAGE_TEXT_SIZE_PX = 16;
const IOS_DEFAULT_MESSAGE_TEXT_SIZE_PX = 17;
const MACOS_DEFAULT_MESSAGE_TEXT_SIZE_PX = 15;
const PREVIEW_AVATAR_COUNT = 3;
const DRAFT_DEBOUNCE = 10000; // 10s
const SEND_MESSAGE_ACTION_INTERVAL = 3000; // 3s
// 10000s from https://corefork.telegram.org/api/url-authorization#automatic-authorization
const APP_CONFIG_REFETCH_INTERVAL = 10000 * 1000;
const GENERAL_REFETCH_INTERVAL = 60 * 60 * 1000; // 1h

const EDITABLE_INPUT_ID = 'editable-message-text';
const EDITABLE_INPUT_MODAL_ID = 'editable-message-text-modal';
const EDITABLE_STORY_INPUT_ID = 'editable-story-input-text';
// eslint-disable-next-line @stylistic/max-len
const EDITABLE_INPUT_CSS_SELECTOR = `.messages-layout .Transition_slide-active #${EDITABLE_INPUT_ID}, .messages-layout .Transition > .Transition_slide-to #${EDITABLE_INPUT_ID}`;
const EDITABLE_INPUT_MODAL_CSS_SELECTOR = `#${EDITABLE_INPUT_MODAL_ID}`;
const EDITABLE_STORY_INPUT_CSS_SELECTOR = `#${EDITABLE_STORY_INPUT_ID}`;
const CUSTOM_APPENDIX_ATTRIBUTE = 'data-has-custom-appendix';
const MESSAGE_CONTENT_CLASS_NAME = 'message-content';
const MESSAGE_CONTENT_SELECTOR = '.message-content';
const VIEW_TRANSITION_CLASS_NAME = 'active-view-transition';
const RESIZE_HANDLE_CLASS_NAME = 'resizeHandle';
const RESIZE_HANDLE_SELECTOR = `.${RESIZE_HANDLE_CLASS_NAME}`;
const SNAP_EFFECT_CONTAINER_ID = 'snap-effect-container';
const SNAP_EFFECT_ID = 'snap-effect';
const STARS_ICON_PLACEHOLDER = '⭐';
const STARS_CURRENCY_CODE = 'XTR';
const MIN_SCREEN_WIDTH_FOR_STATIC_RIGHT_COLUMN = 1275; // px
const MIN_SCREEN_WIDTH_FOR_STATIC_LEFT_COLUMN = 925; // px
const MOBILE_SCREEN_MAX_WIDTH = 600; // px
const MOBILE_SCREEN_LANDSCAPE_MAX_WIDTH = 950; // px
const MOBILE_SCREEN_LANDSCAPE_MAX_HEIGHT = 450; // px

const MAX_INT_32 = 2 ** 31 - 1;
const TMP_CHAT_ID = '0';
const ANIMATION_END_DELAY = 100;
const ANIMATION_WAVE_MIN_INTERVAL = 200;
const MESSAGE_APPEARANCE_DELAY = 10;
const PAID_SEND_DELAY = 5000;
const SCROLL_MIN_DURATION = 300;
const SCROLL_MAX_DURATION = 600;
const SCROLL_MAX_DISTANCE = 800;
const SCROLL_SHORT_TRANSITION_MAX_DISTANCE = 300; // px

// Average duration of message sending animation
const API_UPDATE_THROTTLE = Math.round((SCROLL_MIN_DURATION + SCROLL_MAX_DURATION) / 2);
const API_THROTTLE_RESET_UPDATES = new Set(['newMessage', 'newScheduledMessage', 'deleteMessages', 'deleteScheduledMessages', 'deleteHistory', 'deleteParticipantHistory']);
const LOCK_SCREEN_ANIMATION_DURATION_MS = 200;
const STICKER_SIZE_INLINE_DESKTOP_FACTOR = 13;
const STICKER_SIZE_INLINE_MOBILE_FACTOR = 11;
const STICKER_SIZE_AUTH = 160;
const STICKER_SIZE_AUTH_MOBILE = 120;
const STICKER_SIZE_PICKER = 72;
const EMOJI_SIZE_PICKER = 36;
const COMPOSER_EMOJI_SIZE_PICKER = 32;
const STICKER_SIZE_GENERAL_SETTINGS = 40;
const STICKER_SIZE_PICKER_HEADER = 32;
const STICKER_PICKER_MAX_SHARED_COVERS = 20;
const STICKER_SIZE_SEARCH = 72;
const STICKER_SIZE_MODAL = 72;
const EMOJI_SIZE_MODAL = 36;
const STICKER_SIZE_TWO_FA = 160;
const STICKER_SIZE_PASSCODE = 160;
const STICKER_SIZE_DISCUSSION_GROUPS = 140;
const STICKER_SIZE_FOLDER_SETTINGS = 100;
const STICKER_SIZE_INLINE_BOT_RESULT = 100;
const STICKER_SIZE_JOIN_REQUESTS = 140;
const STICKER_SIZE_INVITES = 140;
const RECENT_STICKERS_LIMIT = 20;
const RECENT_STATUS_LIMIT = 20;
const EMOJI_STATUS_LOOP_LIMIT = 2;
const EMOJI_SIZES = 7;
const TOP_SYMBOL_SET_ID = 'top';
const POPULAR_SYMBOL_SET_ID = 'popular';
const RECENT_SYMBOL_SET_ID = 'recent';
const COLLECTIBLE_STATUS_SET_ID = 'collectibleStatus';
const FAVORITE_SYMBOL_SET_ID = 'favorite';
const EFFECT_STICKERS_SET_ID = 'effectStickers';
const EFFECT_EMOJIS_SET_ID = 'effectEmojis';
const CHAT_STICKER_SET_ID = 'chatStickers';
const DEFAULT_TOPIC_ICON_STICKER_ID = 'topic-default-icon';
const DEFAULT_STATUS_ICON_ID = 'status-default-icon';
const EMOJI_IMG_REGEX = /<img[^>]+alt="([^"]+)"(?![^>]*data-document-id)[^>]*>/gm;
const BASE_EMOJI_KEYWORD_LANG = 'en';
const MENU_TRANSITION_DURATION = 200;
const SLIDE_TRANSITION_DURATION = 450;
const BIRTHDAY_NUMBERS_SET = 'FestiveFontEmoji';
const RESTRICTED_EMOJI_SET = 'RestrictedEmoji';
const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';
const SVG_EXTENSIONS = new Set(['svg', 'svgz']);
const VIDEO_WEBM_TYPE = 'video/webm';
const GIF_MIME_TYPE = 'image/gif';
const LOTTIE_STICKER_MIME_TYPE = 'application/x-tgsticker';
const VIDEO_STICKER_MIME_TYPE = VIDEO_WEBM_TYPE;
const SUPPORTED_PHOTO_CONTENT_TYPES = new Set(['image/png', 'image/jpeg', GIF_MIME_TYPE]);
const SUPPORTED_VIDEO_CONTENT_TYPES = new Set(['video/mp4', 'video/quicktime']);
const SUPPORTED_AUDIO_CONTENT_TYPES = new Set(['audio/mp3', 'audio/ogg', 'audio/wav', 'audio/mpeg', 'audio/flac', 'audio/aac', 'audio/m4a', 'audio/mp4', 'audio/x-m4a']);
const CONTENT_TYPES_WITH_PREVIEW = new Set([...SUPPORTED_PHOTO_CONTENT_TYPES, ...SUPPORTED_VIDEO_CONTENT_TYPES]);

// Taken from https://github.com/telegramdesktop/tdesktop/blob/41d9a9fcbd0c809c60ddbd9350791b1436aff7d9/Telegram/SourceFiles/ui/boxes/choose_language_box.cpp#L28
const SUPPORTED_TRANSLATION_LANGUAGES = [
// Official
'en', 'ar', 'be', 'ca', 'zh', 'nl', 'fr', 'de', 'id', 'it', 'ja', 'ko', 'pl', 'pt', 'ru', 'es', 'uk',
// Unofficial
'af', 'sq', 'am', 'hy', 'az', 'eu', 'bn', 'bs', 'bg', 'ceb', 'zh-CN', 'zh-TW', 'co', 'hr', 'cs', 'da', 'eo', 'et', 'fi', 'fy', 'gl', 'ka', 'el', 'gu', 'ht', 'ha', 'haw', 'he', 'iw', 'hi', 'hmn', 'hu', 'is', 'ig', 'ga', 'jv', 'kn', 'kk', 'km', 'rw', 'ku', 'ky', 'lo', 'la', 'lv', 'lt', 'lb', 'mk', 'mg', 'ms', 'ml', 'mt', 'mi', 'mr', 'mn', 'my', 'ne', 'no', 'ny', 'or', 'ps', 'fa', 'pa', 'ro', 'sm', 'gd', 'sr', 'st', 'sn', 'sd', 'si', 'sk', 'sl', 'so', 'su', 'sw', 'sv', 'tl', 'tg', 'ta', 'tt', 'te', 'th', 'tr', 'tk', 'ur', 'ug', 'uz', 'vi', 'cy', 'xh', 'yi', 'yo', 'zu'];

// eslint-disable-next-line @stylistic/max-len
const RE_LINK_TEMPLATE = '((ftp|https?):\\/\\/)?((www\\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\\.[a-zA-Z][-a-zA-Z0-9]{1,62})\\b([-a-zA-Z0-9()@:%_+.,~#?&/=]*)';
const RE_MENTION_TEMPLATE = '(@[\\w\\d_-]+)';
const RE_TG_LINK = /^tg:(\/\/)?/i;
const RE_TME_LINK = /^(https?:\/\/)?([-a-zA-Z0-9@:%_+~#=]{1,32}\.)?t\.me/i;
const RE_TELEGRAM_LINK = /^(https?:\/\/)?telegram\.org\//i;
const TME_LINK_PREFIX = 'https://t.me/';
const BOT_FATHER_USERNAME = 'botfather';
const USERNAME_PURCHASE_ERROR = 'USERNAME_PURCHASE_AVAILABLE';
const MESSAGE_ID_REQUIRED_ERROR = 'MESSAGE_ID_REQUIRED';
const PURCHASE_USERNAME = 'auction';
const ACCEPTABLE_USERNAME_ERRORS = new Set([USERNAME_PURCHASE_ERROR, 'USERNAME_INVALID']);
const TME_WEB_DOMAINS = new Set(['t.me', 'web.t.me', 'a.t.me', 'k.t.me', 'z.t.me']);
const WEB_APP_PLATFORM = 'weba';
const LANG_PACK = 'weba';
const NSFW_RESTRICTION_REASON = 'sensitive';

// eslint-disable-next-line @stylistic/max-len
const COUNTRIES_WITH_12H_TIME_FORMAT = new Set(['AU', 'BD', 'CA', 'CO', 'EG', 'HN', 'IE', 'IN', 'JO', 'MX', 'MY', 'NI', 'NZ', 'PH', 'PK', 'SA', 'SV', 'US']);
const API_CHAT_TYPES = ['bots', 'channels', 'chats', 'users', 'groups'];
const HEART_REACTION = {
  type: 'emoji',
  emoticon: '❤'
};

// MTProto constants
const SERVICE_NOTIFICATIONS_USER_ID = '777000';
const REPLIES_USER_ID = '1271266957'; // TODO For Test connection ID must be equal to 708513
const VERIFICATION_CODES_USER_ID = '489000';
const ANONYMOUS_USER_ID = '2666000';
const RESTRICTED_EMOJI_SET_ID = '7173162320003080';
const CHANNEL_ID_BASE = 10 ** 12;
const DEFAULT_GIF_SEARCH_BOT_USERNAME = 'gif';
const ALL_FOLDER_ID = 0;
const ARCHIVED_FOLDER_ID = 1;
const SAVED_FOLDER_ID = -1;
const DELETED_COMMENTS_CHANNEL_ID = '-1000000000777';
const MAX_MEDIA_FILES_FOR_ALBUM = 10;
const MAX_ACTIVE_PINNED_CHATS = 5;
const SCHEDULED_WHEN_ONLINE = 0x7FFFFFFE;
const LANG_PACKS = ['android', 'ios', 'tdesktop', 'macos'];
const FEEDBACK_URL = 'https://bugs.telegram.org/?tag_ids=41&sort=time';
const FAQ_URL = 'https://telegram.org/faq';
const PRIVACY_URL = 'https://telegram.org/privacy';
const MINI_APP_TOS_URL = 'https://telegram.org/tos/mini-apps';
const FRAGMENT_ADS_URL = 'https://fragment.com/ads';
const GENERAL_TOPIC_ID = 1;
const STORY_EXPIRE_PERIOD = 86400; // 1 day
const STORY_VIEWERS_EXPIRE_PERIOD = 86400; // 1 day
const FRESH_AUTH_PERIOD = 86400; // 1 day
const GIVEAWAY_BOOST_PER_PREMIUM = 4;
const GIVEAWAY_MAX_ADDITIONAL_CHANNELS = 10;
const GIVEAWAY_MAX_ADDITIONAL_USERS = 10;
const GIVEAWAY_MAX_ADDITIONAL_COUNTRIES = 10;
const BOOST_PER_SENT_GIFT = 3;
const FRAGMENT_PHONE_CODE = '888';
const FRAGMENT_PHONE_LENGTH = 11;
const LIGHT_THEME_BG_COLOR = '#99BA92';
const DARK_THEME_BG_COLOR = '#0F0F0F';
const DEFAULT_PATTERN_COLOR = '#4A8E3A8C';
const DARK_THEME_PATTERN_COLOR = '#0A0A0A8C';
const PEER_COLOR_BG_OPACITY = '1a';
const PEER_COLOR_BG_ACTIVE_OPACITY = '2b';
const PEER_COLOR_GRADIENT_STEP = 5; // px
const MAX_UPLOAD_FILEPART_SIZE = 524288;
const IGNORE_UNHANDLED_ERRORS = new Set(['USER_CANCELED']);

// Group calls
const GROUP_CALL_VOLUME_MULTIPLIER = 100;
const GROUP_CALL_DEFAULT_VOLUME = 100 * GROUP_CALL_VOLUME_MULTIPLIER;
const ONE_TIME_MEDIA_TTL_SECONDS = 2147483647;

// Premium
const PREMIUM_FEATURE_SECTIONS = ['stories', 'double_limits', 'more_upload', 'faster_download', 'voice_to_text', 'no_ads', 'infinite_reactions', 'premium_stickers', 'animated_emoji', 'advanced_chat_management', 'profile_badge', 'animated_userpics', 'emoji_status', 'translations', 'saved_tags', 'last_seen', 'message_privacy', 'effects', 'todo'];
const PREMIUM_BOTTOM_VIDEOS = ['faster_download', 'voice_to_text', 'advanced_chat_management', 'infinite_reactions', 'profile_badge', 'animated_userpics', 'emoji_status', 'translations', 'saved_tags', 'last_seen', 'message_privacy', 'effects', 'todo'];
const PREMIUM_LIMITS_ORDER = ['channels', 'dialogFolderPinned', 'channelsPublic', 'savedGifs', 'stickersFaved', 'aboutLength', 'captionLength', 'dialogFilters', 'dialogFiltersChats', 'moreAccounts', 'recommendedChannels'];
const DEFAULT_GIFT_PROFILE_FILTER_OPTIONS = {
  sortType: 'byDate',
  shouldIncludeUnlimited: true,
  shouldIncludeLimited: true,
  shouldIncludeUnique: true,
  shouldIncludeDisplayed: true,
  shouldIncludeHidden: true,
  shouldIncludeUpgradable: true
};
const DEFAULT_RESALE_GIFTS_FILTER_OPTIONS = {
  sortType: 'byDate'
};
const ACCOUNT_TTL_OPTIONS = [1, 3, 6, 12, 18, 24];

/***/ }),

/***/ "./src/lib/gramjs/Helpers.ts":
/*!***********************************!*\
  !*** ./src/lib/gramjs/Helpers.ts ***!
  \***********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   CRC32_TABLE: () => (/* binding */ CRC32_TABLE),
/* harmony export */   bigIntMod: () => (/* binding */ bigIntMod),
/* harmony export */   bufferXor: () => (/* binding */ bufferXor),
/* harmony export */   convertToLittle: () => (/* binding */ convertToLittle),
/* harmony export */   crc32: () => (/* binding */ crc32),
/* harmony export */   generateKeyDataFromNonce: () => (/* binding */ generateKeyDataFromNonce),
/* harmony export */   generateRandomBytes: () => (/* binding */ generateRandomBytes),
/* harmony export */   generateRandomLong: () => (/* binding */ generateRandomLong),
/* harmony export */   getByteArray: () => (/* binding */ getByteArray),
/* harmony export */   getRandomInt: () => (/* binding */ getRandomInt),
/* harmony export */   mod: () => (/* binding */ mod),
/* harmony export */   modExp: () => (/* binding */ modExp),
/* harmony export */   readBigIntFromBuffer: () => (/* binding */ readBigIntFromBuffer),
/* harmony export */   readBufferFromBigInt: () => (/* binding */ readBufferFromBigInt),
/* harmony export */   sha1: () => (/* binding */ sha1),
/* harmony export */   sha256: () => (/* binding */ sha256),
/* harmony export */   sleep: () => (/* binding */ sleep),
/* harmony export */   toSignedLittleBuffer: () => (/* binding */ toSignedLittleBuffer)
/* harmony export */ });
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! big-integer */ "./node_modules/big-integer/BigInteger.js");
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(big_integer__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _crypto_crypto__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./crypto/crypto */ "./src/lib/gramjs/crypto/crypto.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];


function readBigIntFromBuffer(buffer, little = true, signed = false) {
  let randBuffer = Buffer.from(buffer);
  const bytesNumber = randBuffer.length;
  if (little) {
    randBuffer = randBuffer.reverse();
  }
  let bigInt = big_integer__WEBPACK_IMPORTED_MODULE_0___default()(randBuffer.toString('hex'), 16);
  if (signed && Math.floor(bigInt.toString(2).length / 8) >= bytesNumber) {
    bigInt = bigInt.subtract(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(2).pow(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(bytesNumber * 8)));
  }
  return bigInt;
}
function toSignedLittleBuffer(big, number = 8) {
  const bigNumber = big_integer__WEBPACK_IMPORTED_MODULE_0___default()(big);
  const byteArray = [];
  for (let i = 0; i < number; i++) {
    byteArray[i] = bigNumber.shiftRight(8 * i).and(255).toJSNumber();
  }
  return Buffer.from(byteArray);
}
function readBufferFromBigInt(bigInt, bytesNumber, little = true, signed = false) {
  const bitLength = bigInt.bitLength().toJSNumber();
  const bytes = Math.ceil(bitLength / 8);
  if (bytesNumber < bytes) {
    throw new Error('OverflowError: int too big to convert');
  }
  if (!signed && bigInt.lesser(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(0))) {
    throw new Error('Cannot convert to unsigned');
  }
  let below = false;
  if (bigInt.lesser(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(0))) {
    below = true;
    bigInt = bigInt.abs();
  }
  const hex = bigInt.toString(16).padStart(bytesNumber * 2, '0');
  let buffer = Buffer.from(hex, 'hex');
  if (signed && below) {
    buffer[buffer.length - 1] = 256 - buffer[buffer.length - 1];
    for (let i = 0; i < buffer.length - 1; i++) {
      buffer[i] = 255 - buffer[i];
    }
  }
  if (little) {
    buffer = buffer.reverse();
  }
  return buffer;
}
function generateRandomLong(signed = true) {
  return readBigIntFromBuffer(generateRandomBytes(8), true, signed);
}
function mod(n, m) {
  return (n % m + m) % m;
}
function bigIntMod(n, m) {
  return n.remainder(m).add(m).remainder(m);
}
function generateRandomBytes(count) {
  return Buffer.from((0,_crypto_crypto__WEBPACK_IMPORTED_MODULE_1__.randomBytes)(count));
}
async function generateKeyDataFromNonce(serverNonceBigInt, newNonceBigInt) {
  const serverNonce = toSignedLittleBuffer(serverNonceBigInt, 16);
  const newNonce = toSignedLittleBuffer(newNonceBigInt, 32);
  const [hash1, hash2, hash3] = await Promise.all([sha1(Buffer.concat([newNonce, serverNonce])), sha1(Buffer.concat([serverNonce, newNonce])), sha1(Buffer.concat([newNonce, newNonce]))]);
  const keyBuffer = Buffer.concat([hash1, hash2.slice(0, 12)]);
  const ivBuffer = Buffer.concat([hash2.slice(12, 20), hash3, newNonce.slice(0, 4)]);
  return {
    key: keyBuffer,
    iv: ivBuffer
  };
}
function convertToLittle(buf) {
  const correct = Buffer.alloc(buf.length * 4);
  for (let i = 0; i < buf.length; i++) {
    correct.writeUInt32BE(buf[i], i * 4);
  }
  return correct;
}
function sha1(data) {
  const shaSum = (0,_crypto_crypto__WEBPACK_IMPORTED_MODULE_1__.createHash)('sha1');
  shaSum.update(data);
  return shaSum.digest();
}
function sha256(data) {
  const shaSum = (0,_crypto_crypto__WEBPACK_IMPORTED_MODULE_1__.createHash)('sha256');
  shaSum.update(data);
  return shaSum.digest();
}
function modExp(a, b, n) {
  a = a.remainder(n);
  let result = (big_integer__WEBPACK_IMPORTED_MODULE_0___default().one);
  let x = a;
  while (b.greater((big_integer__WEBPACK_IMPORTED_MODULE_0___default().zero))) {
    const leastSignificantBit = b.remainder(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(2));
    b = b.divide(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(2));
    if (leastSignificantBit.eq((big_integer__WEBPACK_IMPORTED_MODULE_0___default().one))) {
      result = result.multiply(x);
      result = result.remainder(n);
    }
    x = x.multiply(x);
    x = x.remainder(n);
  }
  return result;
}
function getByteArray(integer, signed = false) {
  const bits = integer.toString(2).length;
  const byteLength = Math.floor((bits + 8 - 1) / 8);
  return readBufferFromBigInt(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(integer), byteLength, false, signed);
}
function getRandomInt(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function sleep(ms) {
  return new Promise(resolve => {
    setTimeout(resolve, ms);
  });
}
function bufferXor(a, b) {
  const res = [];
  for (let i = 0; i < a.length; i++) {
    res.push(a[i] ^ b[i]);
  }
  return Buffer.from(res);
}

// Taken from https://stackoverflow.com/questions/18638900/javascript-crc32/18639999#18639999
const CRC32_TABLE = (() => {
  let c;
  const crcTable = [];
  for (let n = 0; n < 256; n++) {
    c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xEDB88320 ^ c >>> 1 : c >>> 1;
    }
    crcTable[n] = c;
  }
  return crcTable;
})();
function crc32(buf) {
  if (!Buffer.isBuffer(buf)) {
    buf = Buffer.from(buf);
  }
  let crc = -1;
  for (let index = 0; index < buf.length; index++) {
    const byte = buf[index];
    crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ crc >>> 8;
  }
  return (crc ^ -1) >>> 0;
}

/***/ }),

/***/ "./src/lib/gramjs/Password.ts":
/*!************************************!*\
  !*** ./src/lib/gramjs/Password.ts ***!
  \************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   computeCheck: () => (/* binding */ computeCheck),
/* harmony export */   computeDigest: () => (/* binding */ computeDigest)
/* harmony export */ });
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! big-integer */ "./node_modules/big-integer/BigInteger.js");
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(big_integer__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _crypto_crypto__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./crypto/crypto */ "./src/lib/gramjs/crypto/crypto.ts");
/* harmony import */ var _tl_api__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./tl/api */ "./src/lib/gramjs/tl/api.js");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./Helpers */ "./src/lib/gramjs/Helpers.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];




const SIZE_FOR_HASH = 256;

/**
 *
 *
 * @param prime{BigInteger}
 * @param g{BigInteger}
 */

/*
We don't support changing passwords yet
function checkPrimeAndGoodCheck(prime, g) {
    console.error('Unsupported function `checkPrimeAndGoodCheck` call. Arguments:', prime, g)

    const goodPrimeBitsCount = 2048
    if (prime < 0 || prime.bitLength() !== goodPrimeBitsCount) {
        throw new Error(`bad prime count ${prime.bitLength()},expected ${goodPrimeBitsCount}`)
    }
    // TODO this is kinda slow
    if (Factorizator.factorize(prime)[0] !== 1) {
        throw new Error('give "prime" is not prime')
    }
    if (g.eq(BigInt(2))) {
        if ((prime.remainder(BigInt(8))).neq(BigInt(7))) {
            throw new Error(`bad g ${g}, mod8 ${prime % 8}`)
        }
    } else if (g.eq(BigInt(3))) {
        if ((prime.remainder(BigInt(3))).neq(BigInt(2))) {
            throw new Error(`bad g ${g}, mod3 ${prime % 3}`)
        }
        // eslint-disable-next-line no-empty
    } else if (g.eq(BigInt(4))) {

    } else if (g.eq(BigInt(5))) {
        if (!([ BigInt(1), BigInt(4) ].includes(prime.remainder(BigInt(5))))) {
            throw new Error(`bad g ${g}, mod8 ${prime % 5}`)
        }
    } else if (g.eq(BigInt(6))) {
        if (!([ BigInt(19), BigInt(23) ].includes(prime.remainder(BigInt(24))))) {
            throw new Error(`bad g ${g}, mod8 ${prime % 24}`)
        }
    } else if (g.eq(BigInt(7))) {
        if (!([ BigInt(3), BigInt(5), BigInt(6) ].includes(prime.remainder(BigInt(7))))) {
            throw new Error(`bad g ${g}, mod8 ${prime % 7}`)
        }
    } else {
        throw new Error(`bad g ${g}`)
    }
    const primeSub1Div2 = (prime.subtract(BigInt(1))).divide(BigInt(2))
    if (Factorizator.factorize(primeSub1Div2)[0] !== 1) {
        throw new Error('(prime - 1) // 2 is not prime')
    }
}
*/

function checkPrimeAndGood(primeBytes, g) {
  const goodPrime = Buffer.from([0xC7, 0x1C, 0xAE, 0xB9, 0xC6, 0xB1, 0xC9, 0x04, 0x8E, 0x6C, 0x52, 0x2F, 0x70, 0xF1, 0x3F, 0x73, 0x98, 0x0D, 0x40, 0x23, 0x8E, 0x3E, 0x21, 0xC1, 0x49, 0x34, 0xD0, 0x37, 0x56, 0x3D, 0x93, 0x0F, 0x48, 0x19, 0x8A, 0x0A, 0xA7, 0xC1, 0x40, 0x58, 0x22, 0x94, 0x93, 0xD2, 0x25, 0x30, 0xF4, 0xDB, 0xFA, 0x33, 0x6F, 0x6E, 0x0A, 0xC9, 0x25, 0x13, 0x95, 0x43, 0xAE, 0xD4, 0x4C, 0xCE, 0x7C, 0x37, 0x20, 0xFD, 0x51, 0xF6, 0x94, 0x58, 0x70, 0x5A, 0xC6, 0x8C, 0xD4, 0xFE, 0x6B, 0x6B, 0x13, 0xAB, 0xDC, 0x97, 0x46, 0x51, 0x29, 0x69, 0x32, 0x84, 0x54, 0xF1, 0x8F, 0xAF, 0x8C, 0x59, 0x5F, 0x64, 0x24, 0x77, 0xFE, 0x96, 0xBB, 0x2A, 0x94, 0x1D, 0x5B, 0xCD, 0x1D, 0x4A, 0xC8, 0xCC, 0x49, 0x88, 0x07, 0x08, 0xFA, 0x9B, 0x37, 0x8E, 0x3C, 0x4F, 0x3A, 0x90, 0x60, 0xBE, 0xE6, 0x7C, 0xF9, 0xA4, 0xA4, 0xA6, 0x95, 0x81, 0x10, 0x51, 0x90, 0x7E, 0x16, 0x27, 0x53, 0xB5, 0x6B, 0x0F, 0x6B, 0x41, 0x0D, 0xBA, 0x74, 0xD8, 0xA8, 0x4B, 0x2A, 0x14, 0xB3, 0x14, 0x4E, 0x0E, 0xF1, 0x28, 0x47, 0x54, 0xFD, 0x17, 0xED, 0x95, 0x0D, 0x59, 0x65, 0xB4, 0xB9, 0xDD, 0x46, 0x58, 0x2D, 0xB1, 0x17, 0x8D, 0x16, 0x9C, 0x6B, 0xC4, 0x65, 0xB0, 0xD6, 0xFF, 0x9C, 0xA3, 0x92, 0x8F, 0xEF, 0x5B, 0x9A, 0xE4, 0xE4, 0x18, 0xFC, 0x15, 0xE8, 0x3E, 0xBE, 0xA0, 0xF8, 0x7F, 0xA9, 0xFF, 0x5E, 0xED, 0x70, 0x05, 0x0D, 0xED, 0x28, 0x49, 0xF4, 0x7B, 0xF9, 0x59, 0xD9, 0x56, 0x85, 0x0C, 0xE9, 0x29, 0x85, 0x1F, 0x0D, 0x81, 0x15, 0xF6, 0x35, 0xB1, 0x05, 0xEE, 0x2E, 0x4E, 0x15, 0xD0, 0x4B, 0x24, 0x54, 0xBF, 0x6F, 0x4F, 0xAD, 0xF0, 0x34, 0xB1, 0x04, 0x03, 0x11, 0x9C, 0xD8, 0xE3, 0xB9, 0x2F, 0xCC, 0x5B]);
  if (goodPrime.equals(primeBytes)) {
    if ([3, 4, 5, 7].includes(g)) {
      return; // It's good
    }
  }
  throw new Error('Changing passwords unsupported');
  // checkPrimeAndGoodCheck(readBigIntFromBuffer(primeBytes, false), g)
}
function isGoodLarge(number, p) {
  return number.greater(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(0)) && p.subtract(number).greater(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(0));
}
function numBytesForHash(number) {
  return Buffer.concat([Buffer.alloc(SIZE_FOR_HASH - number.length), number]);
}
function bigNumForHash(g) {
  return (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.readBufferFromBigInt)(g, SIZE_FOR_HASH, false);
}
function isGoodModExpFirst(modexp, prime) {
  const diff = prime.subtract(modexp);
  const minDiffBitsCount = 2048 - 64;
  const maxModExpSize = 256;
  return !(diff.lesser(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(0)) || diff.bitLength().toJSNumber() < minDiffBitsCount || modexp.bitLength().toJSNumber() < minDiffBitsCount || Math.floor((modexp.bitLength().toJSNumber() + 7) / 8) > maxModExpSize);
}
function xor(a, b) {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) {
    a[i] ^= b[i];
  }
  return a;
}
function pbkdf2sha512(password, salt, iterations) {
  return (0,_crypto_crypto__WEBPACK_IMPORTED_MODULE_1__.pbkdf2)(password, salt, iterations);
}

/**
 *
 * @param algo {constructors.PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow}
 * @param password
 * @returns {Buffer|*}
 */
async function computeHash(algo, password) {
  const hash1 = await (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.sha256)(Buffer.concat([algo.salt1, Buffer.from(password, 'utf-8'), algo.salt1]));
  const hash2 = await (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.sha256)(Buffer.concat([algo.salt2, hash1, algo.salt2]));
  const hash3 = await pbkdf2sha512(hash2, algo.salt1, 100000);
  return (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.sha256)(Buffer.concat([algo.salt2, hash3, algo.salt2]));
}
async function computeDigest(algo, password) {
  try {
    checkPrimeAndGood(algo.p, algo.g);
  } catch (e) {
    throw new Error('bad p/g in password');
  }
  const value = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.modExp)(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(algo.g), (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.readBigIntFromBuffer)(await computeHash(algo, password), false), (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.readBigIntFromBuffer)(algo.p, false));
  return bigNumForHash(value);
}

/**
 *
 * @param request {constructors.account.Password}
 * @param password {string}
 */
async function computeCheck(request, password) {
  const algo = request.currentAlgo;
  if (!(algo instanceof _tl_api__WEBPACK_IMPORTED_MODULE_2__["default"].PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow)) {
    throw new Error(`Unsupported password algorithm ${algo?.className}`);
  }
  const srpB = request.srp_B;
  const srpId = request.srpId;
  if (!srpB || !srpId) {
    throw new Error(`Undefined srp_b  ${request.className}`);
  }
  const pwHash = await computeHash(algo, password);
  const p = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.readBigIntFromBuffer)(algo.p, false);
  const {
    g
  } = algo;
  const B = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.readBigIntFromBuffer)(srpB, false);
  try {
    checkPrimeAndGood(algo.p, g);
  } catch (e) {
    throw new Error('bad /g in password');
  }
  if (!isGoodLarge(B, p)) {
    throw new Error('bad b in check');
  }
  const x = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.readBigIntFromBuffer)(pwHash, false);
  const pForHash = numBytesForHash(algo.p);
  const gForHash = bigNumForHash(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(g));
  const bForHash = numBytesForHash(srpB);
  const gX = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.modExp)(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(g), x, p);
  const k = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.readBigIntFromBuffer)(await (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.sha256)(Buffer.concat([pForHash, gForHash])), false);
  const kgX = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.bigIntMod)(k.multiply(gX), p);
  const generateAndCheckRandom = async () => {
    const randomSize = 256;
    while (true) {
      const random = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.generateRandomBytes)(randomSize);
      const a = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.readBigIntFromBuffer)(random, false);
      const A = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.modExp)(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(g), a, p);
      if (isGoodModExpFirst(A, p)) {
        const aForHash = bigNumForHash(A);
        const u = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.readBigIntFromBuffer)(await (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.sha256)(Buffer.concat([aForHash, bForHash])), false);
        if (u.greater(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(0))) {
          return {
            a,
            aForHash,
            u
          };
        }
      }
    }
  };
  const {
    a,
    aForHash,
    u
  } = await generateAndCheckRandom();
  const gB = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.bigIntMod)(B.subtract(kgX), p);
  if (!isGoodModExpFirst(gB, p)) {
    throw new Error('bad gB');
  }
  const ux = u.multiply(x);
  const aUx = a.add(ux);
  const S = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.modExp)(gB, aUx, p);
  const [K, pSha, gSha, salt1Sha, salt2Sha] = await Promise.all([(0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.sha256)(bigNumForHash(S)), (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.sha256)(pForHash), (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.sha256)(gForHash), (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.sha256)(algo.salt1), (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.sha256)(algo.salt2)]);
  const M1 = await (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.sha256)(Buffer.concat([xor(pSha, gSha), salt1Sha, salt2Sha, aForHash, bForHash, K]));
  return new _tl_api__WEBPACK_IMPORTED_MODULE_2__["default"].InputCheckPasswordSRP({
    srpId,
    A: Buffer.from(aForHash),
    M1
  });
}

/***/ }),

/***/ "./src/lib/gramjs/Utils.ts":
/*!*********************************!*\
  !*** ./src/lib/gramjs/Utils.ts ***!
  \*********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getDC: () => (/* binding */ getDC),
/* harmony export */   getDisplayName: () => (/* binding */ getDisplayName),
/* harmony export */   getDownloadPartSize: () => (/* binding */ getDownloadPartSize),
/* harmony export */   getInputPeer: () => (/* binding */ getInputPeer),
/* harmony export */   getMessageId: () => (/* binding */ getMessageId),
/* harmony export */   getUploadPartSize: () => (/* binding */ getUploadPartSize),
/* harmony export */   strippedPhotoToJpg: () => (/* binding */ strippedPhotoToJpg)
/* harmony export */ });
/* harmony import */ var _tl__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./tl */ "./src/lib/gramjs/tl/index.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];


// eslint-disable-next-line @stylistic/max-len
const JPEG_HEADER = Buffer.from('ffd8ffe000104a46494600010100000100010000ffdb004300281c1e231e19282321232d2b28303c64413c37373c7b585d4964918099968f808c8aa0b4e6c3a0aadaad8a8cc8ffcbdaeef5ffffff9bc1fffffffaffe6fdfff8ffdb0043012b2d2d3c353c76414176f8a58ca5f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8ffc00011080000000003012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00', 'hex');
const JPEG_FOOTER = Buffer.from('ffd9', 'hex');
function _raiseCastFail(entity, target) {
  throw new Error(`Cannot cast ${entity.className} to any kind of ${target}`);
}

/**
 Gets the input peer for the given "entity" (user, chat or channel).

 A ``TypeError`` is raised if the given entity isn't a supported type
 or if ``check_hash is True`` but the entity's ``accessHash is None``
 *or* the entity contains ``min`` information. In this case, the hash
 cannot be used for general purposes, and thus is not returned to avoid
 any issues which can derive from invalid access hashes.

 Note that ``check_hash`` **is ignored** if an input peer is already
 passed since in that case we assume the user knows what they're doing.
 This is key to getting entities by explicitly passing ``hash = 0``.

 * @param entity
 * @param allowSelf
 * @param checkHash
 */
function getInputPeer(entity, allowSelf = true, checkHash = true) {
  if (entity instanceof _tl__WEBPACK_IMPORTED_MODULE_0__.Api.User) {
    if (entity.self && allowSelf) {
      return new _tl__WEBPACK_IMPORTED_MODULE_0__.Api.InputPeerSelf();
    } else if (entity.accessHash !== undefined || !checkHash) {
      return new _tl__WEBPACK_IMPORTED_MODULE_0__.Api.InputPeerUser({
        userId: entity.id,
        accessHash: entity.accessHash
      });
    } else {
      throw new Error('User without accessHash or min info cannot be input');
    }
  }
  if (entity instanceof _tl__WEBPACK_IMPORTED_MODULE_0__.Api.Chat || entity instanceof _tl__WEBPACK_IMPORTED_MODULE_0__.Api.ChatEmpty || entity instanceof _tl__WEBPACK_IMPORTED_MODULE_0__.Api.ChatForbidden) {
    return new _tl__WEBPACK_IMPORTED_MODULE_0__.Api.InputPeerChat({
      chatId: entity.id
    });
  }
  if (entity instanceof _tl__WEBPACK_IMPORTED_MODULE_0__.Api.Channel) {
    if (entity.accessHash !== undefined || !checkHash) {
      return new _tl__WEBPACK_IMPORTED_MODULE_0__.Api.InputPeerChannel({
        channelId: entity.id,
        accessHash: entity.accessHash
      });
    } else {
      throw new TypeError('Channel without accessHash or min info cannot be input');
    }
  }
  if (entity instanceof _tl__WEBPACK_IMPORTED_MODULE_0__.Api.ChannelForbidden) {
    // "channelForbidden are never min", and since their hash is
    // also not optional, we assume that this truly is the case.
    return new _tl__WEBPACK_IMPORTED_MODULE_0__.Api.InputPeerChannel({
      channelId: entity.id,
      accessHash: entity.accessHash
    });
  }
  if (entity instanceof _tl__WEBPACK_IMPORTED_MODULE_0__.Api.UserEmpty) {
    return new _tl__WEBPACK_IMPORTED_MODULE_0__.Api.InputPeerEmpty();
  }
  _raiseCastFail(entity, 'InputPeer');
  return new _tl__WEBPACK_IMPORTED_MODULE_0__.Api.InputPeerEmpty();
}

/**
 * Adds the JPG header and footer to a stripped image.
 * Ported from https://github.com/telegramdesktop/
 * tdesktop/blob/bec39d89e19670eb436dc794a8f20b657cb87c71/Telegram/SourceFiles/ui/image/image.cpp#L225

 * @param stripped{Buffer}
 * @returns {Buffer}
 */
function strippedPhotoToJpg(stripped) {
  // Note: Changes here should update _stripped_real_length
  if (stripped.length < 3 || stripped[0] !== 1) {
    return stripped;
  }
  const header = Buffer.from(JPEG_HEADER);
  header[164] = stripped[1];
  header[166] = stripped[2];
  return Buffer.concat([header, stripped.slice(3), JPEG_FOOTER]);
}

/**
 * Gets the appropriated part size when downloading files,
 * given an initial file size.
 * @param fileSize
 * @returns {Number}
 */
function getDownloadPartSize(fileSize) {
  if (fileSize <= 65536) {
    // 64KB
    return 64;
  }
  if (fileSize <= 104857600) {
    // 100MB
    return 128;
  }
  if (fileSize <= 786432000) {
    // 750MB
    return 256;
  }
  if (fileSize <= 2097152000) {
    // 2000MB
    return 512;
  }
  if (fileSize <= 4194304000) {
    // 4000MB
    return 1024;
  }
  throw new Error('File size too large');
}

/**
 * Gets the appropriated part size when uploading files,
 * given an initial file size.
 * @param fileSize
 * @returns {Number}
 */
function getUploadPartSize(fileSize) {
  if (fileSize <= 104857600) {
    // 100MB
    return 128;
  }
  if (fileSize <= 786432000) {
    // 750MB
    return 256;
  }
  if (fileSize <= 2097152000) {
    // 2000MB
    return 512;
  }
  if (fileSize <= 4194304000) {
    // 4000MB
    return 512;
  }
  throw new Error('File size too large');
}
function getMessageId(message) {
  if (message === undefined) {
    return undefined;
  }
  if (typeof message === 'number') {
    return message;
  }
  if (message.SUBCLASS_OF_ID === 0x790009e3) {
    // crc32(b'Message')
    return message.id;
  }
  throw new Error(`Invalid message type: ${message.constructor.name}`);
}

/**
 * Gets the display name for the given :tl:`User`,
 :tl:`Chat` or :tl:`Channel`. Returns an empty string otherwise
 * @param entity
 */
function getDisplayName(entity) {
  if (entity instanceof _tl__WEBPACK_IMPORTED_MODULE_0__.Api.User) {
    if (entity.lastName && entity.firstName) {
      return `${entity.firstName} ${entity.lastName}`;
    } else if (entity.firstName) {
      return entity.firstName;
    } else if (entity.lastName) {
      return entity.lastName;
    } else {
      return '';
    }
  } else if (entity instanceof _tl__WEBPACK_IMPORTED_MODULE_0__.Api.Chat || entity instanceof _tl__WEBPACK_IMPORTED_MODULE_0__.Api.Channel) {
    return entity.title;
  }
  return '';
}

/**
 * Returns the appropriate DC based on the id
 * @param dcId the id of the DC.
 * @param downloadDC whether to use -1 DCs or not
 * (These only support downloading/uploading and not creating a new AUTH key)
 * @return {{port: number, ipAddress: string, id: number}}
 */
function getDC(dcId, downloadDC = false) {
  // TODO Move to external config
  switch (dcId) {
    case 1:
      return {
        id: 1,
        ipAddress: `zws1${downloadDC ? '-1' : ''}.web.telegram.org`,
        port: 443
      };
    case 2:
      return {
        id: 2,
        ipAddress: `zws2${downloadDC ? '-1' : ''}.web.telegram.org`,
        port: 443
      };
    case 3:
      return {
        id: 3,
        ipAddress: `zws3${downloadDC ? '-1' : ''}.web.telegram.org`,
        port: 443
      };
    case 4:
      return {
        id: 4,
        ipAddress: `zws4${downloadDC ? '-1' : ''}.web.telegram.org`,
        port: 443
      };
    case 5:
      return {
        id: 5,
        ipAddress: `zws5${downloadDC ? '-1' : ''}.web.telegram.org`,
        port: 443
      };
    default:
      throw new Error(`Cannot find the DC with the ID of ${dcId}`);
  }
  // TODO chose based on current connection method
  /*
    if (!this._config) {
        this._config = await this.invoke(new requests.help.GetConfig())
    }
    if (cdn && !this._cdnConfig) {
        this._cdnConfig = await this.invoke(new requests.help.GetCdnConfig())
        for (const pk of this._cdnConfig.publicKeys) {
            addKey(pk.publicKey)
        }
    }
    for (const DC of this._config.dcOptions) {
        if (DC.id === dcId && Boolean(DC.ipv6) === this._useIPV6 && Boolean(DC.cdn) === cdn) {
            return DC
        }
    } */
}

/***/ }),

/***/ "./src/lib/gramjs/client/2fa.ts":
/*!**************************************!*\
  !*** ./src/lib/gramjs/client/2fa.ts ***!
  \**************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getCurrentPassword: () => (/* binding */ getCurrentPassword),
/* harmony export */   getTmpPassword: () => (/* binding */ getTmpPassword),
/* harmony export */   updateTwoFaSettings: () => (/* binding */ updateTwoFaSettings)
/* harmony export */ });
/* harmony import */ var _errors__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../errors */ "./src/lib/gramjs/errors/index.ts");
/* harmony import */ var _tl_api__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../tl/api */ "./src/lib/gramjs/tl/api.js");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* harmony import */ var _Password__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../Password */ "./src/lib/gramjs/Password.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];




/**
 * Changes the 2FA settings of the logged in user.
 Note that this method may be *incredibly* slow depending on the
 prime numbers that must be used during the process to make sure
 that everything is safe.

 Has no effect if both current and new password are omitted.

 * @param client: The telegram client instance
 * @param isCheckPassword: Must be ``true`` if you want to check the current password
 * @param currentPassword: The current password, to authorize changing to ``new_password``.
 Must be set if changing existing 2FA settings.
 Must **not** be set if 2FA is currently disabled.
 Passing this by itself will remove 2FA (if correct).
 * @param newPassword: The password to set as 2FA.
 If 2FA was already enabled, ``currentPassword`` **must** be set.
 Leaving this blank or `undefined` will remove the password.
 * @param hint: Hint to be displayed by Telegram when it asks for 2FA.
 Must be set when changing or creating a new password.
 Has no effect if ``newPassword`` is not set.
 * @param email: Recovery and verification email. If present, you must also
 set `emailCodeCallback`, else it raises an Error.
 * @param emailCodeCallback: If an email is provided, a callback that returns the code sent
 to it must also be set. This callback may be asynchronous.
 It should return a string with the code. The length of the
 code will be passed to the callback as an input parameter.

 If the callback returns an invalid code, it will raise an rpc error with the message
 ``CODE_INVALID``

 * @returns Promise<void>
 * @throws this method can throw:
 "PASSWORD_HASH_INVALID" if you entered a wrong password (or set it to undefined).
 "EMAIL_INVALID" if the entered email is wrong
 "EMAIL_HASH_EXPIRED" if the user took too long to verify their email
 */
async function updateTwoFaSettings(client, {
  isCheckPassword,
  currentPassword,
  newPassword,
  hint = '',
  email,
  emailCodeCallback,
  onEmailCodeError
}) {
  if (!newPassword && !currentPassword) {
    throw new Error('Neither `currentPassword` nor `newPassword` is present');
  }
  if (email && !(emailCodeCallback && onEmailCodeError)) {
    throw new Error('`email` present without `emailCodeCallback` and `onEmailCodeError`');
  }
  const pwd = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_1__["default"].account.GetPassword());
  const newAlgo = pwd.newAlgo;
  if (newAlgo instanceof _tl_api__WEBPACK_IMPORTED_MODULE_1__["default"].PasswordKdfAlgoUnknown) {
    throw new Error('Password algorithm is unknown');
  }
  newAlgo.salt1 = Buffer.concat([newAlgo.salt1, (0,_Helpers__WEBPACK_IMPORTED_MODULE_2__.generateRandomBytes)(32)]);
  if (!pwd.hasPassword && currentPassword) {
    currentPassword = undefined;
  }
  const password = currentPassword ? await (0,_Password__WEBPACK_IMPORTED_MODULE_3__.computeCheck)(pwd, currentPassword) : new _tl_api__WEBPACK_IMPORTED_MODULE_1__["default"].InputCheckPasswordEmpty();
  if (isCheckPassword) {
    await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_1__["default"].auth.CheckPassword({
      password
    }));
    return;
  }
  try {
    await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_1__["default"].account.UpdatePasswordSettings({
      password,
      newSettings: new _tl_api__WEBPACK_IMPORTED_MODULE_1__["default"].account.PasswordInputSettings({
        newAlgo,
        newPasswordHash: newPassword ? await (0,_Password__WEBPACK_IMPORTED_MODULE_3__.computeDigest)(newAlgo, newPassword) : Buffer.alloc(0),
        hint,
        email,
        // not explained what it does and it seems to always be set to empty in tdesktop
        newSecureSettings: undefined
      })
    }));
  } catch (e) {
    if (e instanceof _errors__WEBPACK_IMPORTED_MODULE_0__.EmailUnconfirmedError) {
      while (true) {
        try {
          const code = await emailCodeCallback(e.codeLength);
          if (!code) {
            throw new Error('Code is empty');
          }
          await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_1__["default"].account.ConfirmPasswordEmail({
            code
          }));
          break;
        } catch (err) {
          onEmailCodeError(err);
        }
      }
    } else {
      throw e;
    }
  }
}
async function getTmpPassword(client, currentPassword, ttl = 60) {
  const pwd = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_1__["default"].account.GetPassword());
  if (!pwd) {
    return undefined;
  }
  const inputPassword = await (0,_Password__WEBPACK_IMPORTED_MODULE_3__.computeCheck)(pwd, currentPassword);
  const result = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_1__["default"].account.GetTmpPassword({
    password: inputPassword,
    period: ttl
  }));
  return result;
}
async function getCurrentPassword(client, currentPassword) {
  const pwd = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_1__["default"].account.GetPassword());
  if (!pwd) {
    return undefined;
  }
  return currentPassword ? await (0,_Password__WEBPACK_IMPORTED_MODULE_3__.computeCheck)(pwd, currentPassword) : new _tl_api__WEBPACK_IMPORTED_MODULE_1__["default"].InputCheckPasswordEmpty();
}

/***/ }),

/***/ "./src/lib/gramjs/client/TelegramClient.ts":
/*!*************************************************!*\
  !*** ./src/lib/gramjs/client/TelegramClient.ts ***!
  \*************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! big-integer */ "./node_modules/big-integer/BigInteger.js");
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(big_integer__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! os */ "./node_modules/os-browserify/browser.js");
/* harmony import */ var _util_Deferred__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../util/Deferred */ "./src/util/Deferred.ts");
/* harmony import */ var _errors__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../errors */ "./src/lib/gramjs/errors/index.ts");
/* harmony import */ var _extensions__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../extensions */ "./src/lib/gramjs/extensions/index.ts");
/* harmony import */ var _network__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../network */ "./src/lib/gramjs/network/index.ts");
/* harmony import */ var _tl__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../tl */ "./src/lib/gramjs/tl/index.ts");
/* harmony import */ var _2fa__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./2fa */ "./src/lib/gramjs/client/2fa.ts");
/* harmony import */ var _auth__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./auth */ "./src/lib/gramjs/client/auth.ts");
/* harmony import */ var _downloadFile__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./downloadFile */ "./src/lib/gramjs/client/downloadFile.ts");
/* harmony import */ var _uploadFile__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ./uploadFile */ "./src/lib/gramjs/client/uploadFile.ts");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* harmony import */ var _network_RequestState__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! ../network/RequestState */ "./src/lib/gramjs/network/RequestState.ts");
/* harmony import */ var _sessions_Abstract__WEBPACK_IMPORTED_MODULE_13__ = __webpack_require__(/*! ../sessions/Abstract */ "./src/lib/gramjs/sessions/Abstract.ts");
/* harmony import */ var _sessions_Memory__WEBPACK_IMPORTED_MODULE_14__ = __webpack_require__(/*! ../sessions/Memory */ "./src/lib/gramjs/sessions/Memory.ts");
/* harmony import */ var _tl_AllTLObjects__WEBPACK_IMPORTED_MODULE_15__ = __webpack_require__(/*! ../tl/AllTLObjects */ "./src/lib/gramjs/tl/AllTLObjects.ts");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_16__ = __webpack_require__(/*! ../Utils */ "./src/lib/gramjs/Utils.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];

















const DEFAULT_DC_ID = 2;
const DEFAULT_WEBDOCUMENT_DC_ID = 4;
const EXPORTED_SENDER_RECONNECT_TIMEOUT = 1000; // 1 sec
const EXPORTED_SENDER_RELEASE_TIMEOUT = 30000; // 30 sec
const WEBDOCUMENT_REQUEST_PART_SIZE = 131072; // 128kb

const PING_INTERVAL = 3000; // 3 sec
const PING_TIMEOUT = 5000; // 5 sec
const PING_FAIL_ATTEMPTS = 3;
const PING_FAIL_INTERVAL = 100; // ms

// An unusually long interval is a sign of returning from background mode...
const PING_INTERVAL_TO_WAKE_UP = 5000; // 5 sec
// ... so we send a quick "wake-up" ping to confirm than connection was dropped ASAP
const PING_WAKE_UP_TIMEOUT = 3000; // 3 sec
// We also send a warning to the user even a bit more quickly
const PING_WAKE_UP_WARNING_TIMEOUT = 1000; // 1 sec

const PING_DISCONNECT_DELAY = 60000; // 1 min

// All types, sorted by size
const sizeTypes = ['u', 'v', 'w', 'y', 'd', 'x', 'c', 'm', 'b', 'a', 's', 'f', 'i', 'j'];
class TelegramClient {
  static DEFAULT_OPTIONS = {
    connection: _network__WEBPACK_IMPORTED_MODULE_5__.ConnectionTCPObfuscated,
    fallbackConnection: _network__WEBPACK_IMPORTED_MODULE_5__.HttpConnection,
    useIPV6: false,
    timeout: 10,
    requestRetries: 5,
    connectionRetries: Infinity,
    connectionRetriesToFallback: 1,
    retryDelay: 1000,
    retryMainConnectionDelay: 10000,
    autoReconnect: true,
    sequentialUpdates: false,
    floodSleepLimit: 60,
    deviceModel: undefined,
    systemVersion: undefined,
    appVersion: undefined,
    langCode: 'en',
    langPack: 'weba',
    systemLangCode: 'en',
    baseLogger: 'gramjs',
    useWSS: false,
    additionalDcsDisabled: false,
    dcId: DEFAULT_DC_ID,
    isTestServerRequested: false,
    shouldAllowHttpTransport: false,
    shouldForceHttpTransport: false,
    shouldDebugExportedSenders: false
  };
  _exportedSenderPromises = {};
  _exportedSenderRefCounter = {};
  _waitingForAuthKey = {};
  _exportedSenderReleaseTimeouts = {};
  _loopStarted = false;
  _isSwitchingDc = false;
  _destroyed = false;
  _connectedDeferred = new _util_Deferred__WEBPACK_IMPORTED_MODULE_2__["default"]();
  isPremium = false;
  _lastRequest = Date.now();
  constructor(session, apiId, apiHash, opts = TelegramClient.DEFAULT_OPTIONS) {
    if (!apiId || !apiHash || !Number.isFinite(apiId)) {
      throw Error('Your API ID or Hash are invalid. Please read "Requirements" on README.md');
    }
    const args = {
      ...TelegramClient.DEFAULT_OPTIONS,
      ...opts
    };
    this.apiId = apiId;
    this.apiHash = apiHash;
    this.defaultDcId = args.dcId || DEFAULT_DC_ID;
    this._useIPV6 = args.useIPV6;
    this._shouldForceHttpTransport = args.shouldForceHttpTransport;
    this._shouldAllowHttpTransport = args.shouldAllowHttpTransport;
    this._shouldDebugExportedSenders = args.shouldDebugExportedSenders;
    // this._entityCache = new Set()
    if (typeof args.baseLogger === 'string') {
      this._log = new _extensions__WEBPACK_IMPORTED_MODULE_4__.Logger();
    } else {
      this._log = args.baseLogger;
    }
    // Determine what session we will use
    if (typeof session === 'string' || !session) {
      try {
        throw new Error('not implemented');
      } catch (e) {
        session = new _sessions_Memory__WEBPACK_IMPORTED_MODULE_14__["default"]();
      }
    } else if (!(session instanceof _sessions_Abstract__WEBPACK_IMPORTED_MODULE_13__["default"])) {
      throw new Error('The given session must be str or a session instance');
    }
    this.session = session;
    this.floodSleepLimit = args.floodSleepLimit;
    this._eventBuilders = [];
    this._requestRetries = args.requestRetries;
    this._connectionRetries = args.connectionRetries;
    this._connectionRetriesToFallback = args.connectionRetriesToFallback;
    this._retryDelay = args.retryDelay || 0;
    this._retryMainConnectionDelay = args.retryMainConnectionDelay || 0;
    this._timeout = args.timeout;
    this._autoReconnect = args.autoReconnect;
    this._connection = args.connection;
    this._fallbackConnection = args.fallbackConnection;
    // TODO add proxy support

    this._initWith = x => {
      return new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.InvokeWithLayer({
        layer: _tl_AllTLObjects__WEBPACK_IMPORTED_MODULE_15__.LAYER,
        query: new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.InitConnection({
          apiId: this.apiId,
          deviceModel: args.deviceModel || os__WEBPACK_IMPORTED_MODULE_1__.type().toString() || 'Unknown',
          systemVersion: args.systemVersion || os__WEBPACK_IMPORTED_MODULE_1__.release().toString() || '1.0',
          appVersion: args.appVersion || '1.0',
          langCode: args.langCode,
          langPack: args.langPack,
          systemLangCode: args.systemLangCode,
          query: x,
          proxy: undefined // no proxies yet.
        })
      });
    };
    this._args = args;
  }

  // region Connecting

  /**
     * Connects to the Telegram servers, executing authentication if required.
     * Note that authenticating to the Telegram servers is not the same as authenticating
     * the app, which requires to send a code first.
     * @returns {Promise<void>}
     */
  async connect() {
    await this._initSession();
    if (this._sender === undefined) {
      // only init sender once to avoid multiple loops.
      this._sender = new _network__WEBPACK_IMPORTED_MODULE_5__.MTProtoSender(this.session.getAuthKey(), {
        logger: this._log,
        dcId: this.session.dcId,
        retries: this._connectionRetries,
        retriesToFallback: this._connectionRetriesToFallback,
        shouldForceHttpTransport: this._shouldForceHttpTransport,
        shouldAllowHttpTransport: this._shouldAllowHttpTransport,
        delay: this._retryDelay,
        retryMainConnectionDelay: this._retryMainConnectionDelay,
        autoReconnect: this._autoReconnect,
        connectTimeout: this._timeout,
        authKeyCallback: this._authKeyCallback.bind(this),
        updateCallback: this._handleUpdate.bind(this),
        getShouldDebugExportedSenders: this.getShouldDebugExportedSenders.bind(this),
        isMainSender: true
      });
    }
    const connection = new this._connection({
      ip: this.session.serverAddress,
      port: this.session.port,
      dcId: this.session.dcId,
      loggers: this._log,
      isTestServer: this.session.isTestServer
    });
    const fallbackConnection = new this._fallbackConnection({
      ip: this.session.serverAddress,
      port: this.session.port,
      dcId: this.session.dcId,
      loggers: this._log,
      isTestServer: this.session.isTestServer
    });
    const newConnection = await this._sender.connect(connection, false, fallbackConnection);
    if (!newConnection) {
      // we're already connected so no need to reset auth key.
      if (!this._loopStarted) {
        this._updateLoop();
        this._loopStarted = true;
      }
      return;
    }
    this.session.setAuthKey(this._sender.authKey);
    // `_initWith` is used to announce our API layer to the server
    await this._sender.send(this._initWith(new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.help.GetConfig()));
    if (!this._loopStarted) {
      this._updateLoop();
      this._loopStarted = true;
    }
    this._connectedDeferred.resolve();
    this._isSwitchingDc = false;

    // Prepare file connection on current DC to speed up initial media loading
    const mediaSender = await this._borrowExportedSender(this.session.dcId, false, undefined, 0, this.isPremium);
    if (mediaSender) this.releaseExportedSender(mediaSender);
  }
  async _initSession() {
    await this.session.load();
    if (!this.session.serverAddress || this.session.serverAddress.includes(':') !== this._useIPV6) {
      const DC = (0,_Utils__WEBPACK_IMPORTED_MODULE_16__.getDC)(this.defaultDcId);
      // TODO Fill IP addresses for when `this._useIPV6` is used
      this.session.setDC(this.defaultDcId, DC.ipAddress, this._args.useWSS ? 443 : 80, this._args.isTestServerRequested);
    }
  }
  setPingCallback(callback) {
    this.pingCallback = callback;
  }
  async setForceHttpTransport(forceHttpTransport) {
    this._shouldForceHttpTransport = forceHttpTransport;
    await this.disconnect();
    this._sender = undefined;
    await this.connect();
  }
  async setAllowHttpTransport(allowHttpTransport) {
    this._shouldAllowHttpTransport = allowHttpTransport;
    await this.disconnect();
    this._sender = undefined;
    await this.connect();
  }
  setShouldDebugExportedSenders(shouldDebugExportedSenders) {
    this._shouldDebugExportedSenders = shouldDebugExportedSenders;
  }
  getShouldDebugExportedSenders() {
    return this._shouldDebugExportedSenders;
  }
  async _updateLoop() {
    let lastPongAt;
    const sender = this._sender;
    if (!sender) {
      throw new Error('Sender is not initialized');
    }
    while (!this._destroyed) {
      await (0,_Helpers__WEBPACK_IMPORTED_MODULE_11__.sleep)(PING_INTERVAL);
      if (sender.isReconnecting || this._isSwitchingDc) {
        lastPongAt = undefined;
        continue;
      }
      try {
        const ping = () => {
          if (this._destroyed) {
            return undefined;
          }
          return sender.send(new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.PingDelayDisconnect({
            pingId: big_integer__WEBPACK_IMPORTED_MODULE_0___default()((0,_Helpers__WEBPACK_IMPORTED_MODULE_11__.getRandomInt)(Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER)),
            disconnectDelay: PING_DISCONNECT_DELAY
          }));
        };
        const pingAt = Date.now();
        const lastInterval = lastPongAt ? pingAt - lastPongAt : undefined;
        if (!lastInterval || lastInterval < PING_INTERVAL_TO_WAKE_UP) {
          await attempts(() => timeout(ping, PING_TIMEOUT), PING_FAIL_ATTEMPTS, PING_FAIL_INTERVAL);
        } else {
          let wakeUpWarningTimeout = setTimeout(() => {
            this._handleUpdate(new _network__WEBPACK_IMPORTED_MODULE_5__.UpdateConnectionState(_network__WEBPACK_IMPORTED_MODULE_5__.UpdateConnectionState.disconnected));
            wakeUpWarningTimeout = undefined;
          }, PING_WAKE_UP_WARNING_TIMEOUT);
          await timeout(ping, PING_WAKE_UP_TIMEOUT);
          if (wakeUpWarningTimeout) {
            clearTimeout(wakeUpWarningTimeout);
            wakeUpWarningTimeout = undefined;
          }
          this._handleUpdate(new _network__WEBPACK_IMPORTED_MODULE_5__.UpdateConnectionState(_network__WEBPACK_IMPORTED_MODULE_5__.UpdateConnectionState.connected));
        }
        lastPongAt = Date.now();
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(err);
        lastPongAt = undefined;
        if (sender.isReconnecting || this._isSwitchingDc) {
          continue;
        }
        if (this._destroyed) {
          break;
        }
        sender.reconnect();
      }

      // We need to send some content-related request at least hourly
      // for Telegram to keep delivering updates, otherwise they will
      // just stop even if we're connected. Do so every 30 minutes.

      if (Date.now() - this._lastRequest > 30 * 60 * 1000) {
        try {
          await this.pingCallback?.();
        } catch (e) {
          // we don't care about errors here
        }
        lastPongAt = undefined;
      }
    }
    await this.disconnect();
  }

  /**
     * Disconnects from the Telegram server
     * @returns {Promise<void>}
     */
  async disconnect() {
    this._sender?.disconnect();
    await Promise.all(Object.values(this._exportedSenderPromises).map(promises => {
      return Object.values(promises).map(promise => {
        return promise?.then(sender => {
          return sender?.disconnect();
        });
      });
    }).flat());
    Object.values(this._exportedSenderReleaseTimeouts).forEach(timeouts => {
      Object.values(timeouts).forEach(releaseTimeout => {
        clearTimeout(releaseTimeout);
      });
    });
    this._exportedSenderRefCounter = {};
    this._exportedSenderPromises = {};
    this._waitingForAuthKey = {};
  }

  /**
     * Disconnects all senders and removes all handlers
     * @returns {Promise<void>}
     */
  async destroy() {
    this._destroyed = true;
    try {
      await this.disconnect();
      this._sender?.destroy();
    } catch (err) {
      // Do nothing
    }
    this.session.delete();
    this._eventBuilders = [];
  }
  async _switchDC(newDc) {
    if (!this._sender) {
      throw new Error('Sender is not initialized');
    }
    this._log.info(`Reconnecting to new data center ${newDc}`);
    const DC = (0,_Utils__WEBPACK_IMPORTED_MODULE_16__.getDC)(newDc);
    const isTestServer = this.session.isTestServer || this._args.isTestServerRequested;
    this.session.setDC(newDc, DC.ipAddress, DC.port, isTestServer);
    // authKey's are associated with a server, which has now changed
    // so it's not valid anymore. Set to None to force recreating it.
    await this._sender.authKey.setKey(undefined);
    this.session.setAuthKey(undefined);
    this._isSwitchingDc = true;
    await this.disconnect();
    this._sender = undefined;
    return this.connect();
  }
  _authKeyCallback(authKey, dcId) {
    this.session.setAuthKey(authKey, dcId);
  }

  // endregion
  // export region

  async _cleanupExportedSender(dcId, index) {
    if (this.session.dcId !== dcId) {
      this.session.setAuthKey(undefined, dcId);
    }
    // eslint-disable-next-line no-console
    if (this._shouldDebugExportedSenders) console.log(`🧹 Cleanup idx=${index} dcId=${dcId}`);
    const sender = await this._exportedSenderPromises[dcId][index];
    delete this._exportedSenderPromises[dcId][index];
    delete this._exportedSenderRefCounter[dcId][index];
    sender?.disconnect();
  }
  async _cleanupExportedSenders(dcId) {
    const promises = Object.values(this._exportedSenderPromises[dcId]);
    if (!promises.length) {
      return;
    }
    if (this.session.dcId !== dcId) {
      this.session.setAuthKey(undefined, dcId);
    }
    this._exportedSenderPromises[dcId] = {};
    this._exportedSenderRefCounter[dcId] = {};
    await Promise.all(promises.map(async promise => {
      const sender = await promise;
      sender?.disconnect();
    }));
  }
  async _connectSender(sender, dcId, index, isPremium = false) {
    // if we don't already have an auth key we want to use normal DCs not -1
    let hasAuthKey = Boolean(sender.authKey.getKey());
    let firstConnectResolver;
    if (!hasAuthKey) {
      if (this._waitingForAuthKey[dcId]) {
        await this._waitingForAuthKey[dcId];
        const authKey = this.session.getAuthKey(dcId);
        hasAuthKey = Boolean(sender.authKey?.getKey());
        if (hasAuthKey) {
          await sender.authKey.setKey(authKey.getKey());
        }
      } else {
        this._waitingForAuthKey[dcId] = new Promise(resolve => {
          firstConnectResolver = resolve;
        });
      }
    }
    const dc = (0,_Utils__WEBPACK_IMPORTED_MODULE_16__.getDC)(dcId, hasAuthKey);
    while (true) {
      try {
        await sender.connect(new this._connection({
          ip: dc.ipAddress,
          port: dc.port,
          dcId,
          loggers: this._log,
          isTestServer: this.session.isTestServer,
          // Premium DCs are not stable for obtaining auth keys, so need to we first connect to regular ones
          isPremium: hasAuthKey ? isPremium : false
        }), false, new this._fallbackConnection({
          ip: dc.ipAddress,
          port: dc.port,
          dcId,
          loggers: this._log,
          isTestServer: this.session.isTestServer,
          isPremium: hasAuthKey ? isPremium : false
        }));
        if (this.session.dcId !== dcId && !sender._authenticated) {
          // Prevent another connection from trying to export the auth key while we're doing it
          await navigator.locks.request('GRAMJS_AUTH_EXPORT', async () => {
            this._log.info(`Exporting authorization for data center ${dc.ipAddress}`);
            const auth = await this.invoke(new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.auth.ExportAuthorization({
              dcId
            }));
            const req = this._initWith(new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.auth.ImportAuthorization({
              id: auth.id,
              bytes: auth.bytes
            }));
            await sender.send(req);
            sender._authenticated = true;
          });
        }
        sender._dcId = dcId;
        sender.userDisconnected = false;
        if (firstConnectResolver) {
          firstConnectResolver();
          delete this._waitingForAuthKey[dcId];
        }
        if (this._shouldDebugExportedSenders) {
          // eslint-disable-next-line no-console
          console.warn(`✅ Connected to exported sender idx=${index} dc=${dcId}`);
        }
        return sender;
      } catch (err) {
        if (this._shouldDebugExportedSenders) {
          // eslint-disable-next-line no-console
          console.error(`☠️ ERROR! idx=${index} dcId=${dcId} ${err.message}`);
        }
        // eslint-disable-next-line no-console
        console.error(err);
        await (0,_Helpers__WEBPACK_IMPORTED_MODULE_11__.sleep)(1000);
        sender.disconnect();
      }
    }
  }
  releaseExportedSender(sender) {
    const dcId = sender._dcId;
    const index = sender._senderIndex;
    if (!this._exportedSenderRefCounter[dcId]) return;
    if (!this._exportedSenderRefCounter[dcId][index]) return;
    this._exportedSenderRefCounter[dcId][index] -= 1;
    if (this._exportedSenderRefCounter[dcId][index] <= 0) {
      if (!this._exportedSenderReleaseTimeouts[dcId]) this._exportedSenderReleaseTimeouts[dcId] = {};
      this._exportedSenderReleaseTimeouts[dcId][index] = setTimeout(() => {
        // eslint-disable-next-line no-console
        if (this._shouldDebugExportedSenders) console.log(`[CC] [idx=${index} dcId=${dcId}] 🚪 Release`);
        sender.disconnect();
        this._exportedSenderReleaseTimeouts[dcId][index] = undefined;
        this._exportedSenderPromises[dcId][index] = undefined;
      }, EXPORTED_SENDER_RELEASE_TIMEOUT);
    }
  }
  async _borrowExportedSender(dcId, shouldReconnect, existingSender, index, isPremium) {
    const i = index || 0;
    let shouldAnnounceLayer = false;
    if (!this._exportedSenderPromises[dcId]) {
      this._exportedSenderPromises[dcId] = {};
      shouldAnnounceLayer = true;
    }
    if (!this._exportedSenderRefCounter[dcId]) this._exportedSenderRefCounter[dcId] = {};
    if (!this._exportedSenderPromises[dcId][i] || shouldReconnect) {
      if (this._shouldDebugExportedSenders) {
        // eslint-disable-next-line no-console
        console.warn(`🕒 Connecting to exported sender idx=${i} dc=${dcId}` + ` ${shouldReconnect ? '(reconnect)' : ''}`);
      }
      this._exportedSenderRefCounter[dcId][i] = 0;
      this._exportedSenderPromises[dcId][i] = this._connectSender(existingSender || this._createExportedSender(dcId, i), dcId, index, isPremium);
    }
    let sender;
    try {
      sender = await this._exportedSenderPromises[dcId][i];
      if (!sender?.isConnected()) {
        if (sender?.isConnecting) {
          await (0,_Helpers__WEBPACK_IMPORTED_MODULE_11__.sleep)(EXPORTED_SENDER_RECONNECT_TIMEOUT);
          return this._borrowExportedSender(dcId, false, sender, i, isPremium);
        } else {
          return this._borrowExportedSender(dcId, true, sender, i, isPremium);
        }
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(err);
      return this._borrowExportedSender(dcId, true, undefined, i, isPremium);
    }
    this._exportedSenderRefCounter[dcId][i] += 1;
    if (!this._exportedSenderReleaseTimeouts[dcId]) this._exportedSenderReleaseTimeouts[dcId] = {};
    if (this._exportedSenderReleaseTimeouts[dcId][i]) {
      clearTimeout(this._exportedSenderReleaseTimeouts[dcId][i]);
      this._exportedSenderReleaseTimeouts[dcId][i] = undefined;
    }
    if (shouldAnnounceLayer) {
      // Dummy request to let DC know about our API layer
      sender.send(this._initWith(new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.help.GetConfig()));
    }
    return sender;
  }
  _createExportedSender(dcId, index) {
    return new _network__WEBPACK_IMPORTED_MODULE_5__.MTProtoSender(this.session.getAuthKey(dcId), {
      logger: this._log,
      dcId,
      senderIndex: index,
      retries: this._connectionRetries,
      retriesToFallback: this._connectionRetriesToFallback,
      delay: this._retryDelay,
      retryMainConnectionDelay: this._retryMainConnectionDelay,
      shouldForceHttpTransport: this._shouldForceHttpTransport,
      shouldAllowHttpTransport: this._shouldAllowHttpTransport,
      autoReconnect: this._autoReconnect,
      connectTimeout: this._timeout,
      authKeyCallback: this._authKeyCallback.bind(this),
      isMainSender: dcId === this.session.dcId,
      isExported: true,
      updateCallback: this._handleUpdate.bind(this),
      getShouldDebugExportedSenders: this.getShouldDebugExportedSenders.bind(this),
      onConnectionBreak: () => this._cleanupExportedSender(dcId, index)
    });
  }
  getSender(dcId, index, isPremium) {
    return dcId ? this._borrowExportedSender(dcId, undefined, undefined, index, isPremium) : Promise.resolve(this._sender);
  }

  // end region

  // download region

  /**
     * Complete flow to download a file.
     * @param inputLocation {Api.InputFileLocation}
     * @param [args[partSizeKb] {number}]
     * @param [args[fileSize] {number}]
     * @param [args[progressCallback] {Function}]
     * @param [args[start] {number}]
     * @param [args[end] {number}]
     * @param [args[dcId] {number}]
     * @param [args[workers] {number}]
     * @param [args[isPriority] {boolean}]
     * @returns {Promise<Buffer>}
     */
  downloadFile(inputLocation, args) {
    return (0,_downloadFile__WEBPACK_IMPORTED_MODULE_9__.downloadFile)(this, inputLocation, args, this._shouldDebugExportedSenders);
  }
  downloadMedia(entityOrMedia, args) {
    let media;
    if (entityOrMedia instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.Message || entityOrMedia instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.StoryItem) {
      media = entityOrMedia.media;
    } else if (entityOrMedia instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.MessageService) {
      const action = entityOrMedia.action;
      if ('photo' in action) {
        media = action.photo;
      }
    } else {
      media = entityOrMedia;
    }
    if (media instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.MessageMediaWebPage) {
      if (media.webpage instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.WebPage) {
        media = media.webpage.document || media.webpage.photo;
      }
    }
    if (media instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.MessageMediaPhoto || media instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.Photo) {
      return this._downloadPhoto(media, args);
    } else if (media instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.MessageMediaDocument || media instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.Document) {
      return this._downloadDocument(media, args);
    } else if (media instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.WebDocument || media instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.WebDocumentNoProxy) {
      return this._downloadWebDocument(media);
    }
    return undefined;
  }
  downloadProfilePhoto(entity, isBig = false) {
    const photo = entity.photo;
    if (!(photo instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.UserProfilePhoto || photo instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.ChatPhoto)) return undefined;
    const dcId = photo.dcId;
    const loc = new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.InputPeerPhotoFileLocation({
      peer: (0,_Utils__WEBPACK_IMPORTED_MODULE_16__.getInputPeer)(entity),
      photoId: photo.photoId,
      big: isBig || undefined
    });
    return this.downloadFile(loc, {
      dcId,
      isPriority: true
    }); // Profile photo cannot be larger than 2GB, right?
  }
  downloadStickerSetThumb(stickerSet) {
    if (!stickerSet.thumbs?.length && !stickerSet.thumbDocumentId) {
      return undefined;
    }
    const thumbVersion = stickerSet.thumbVersion;
    if (!stickerSet.thumbDocumentId) {
      return this.downloadFile(new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.InputStickerSetThumb({
        stickerset: new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.InputStickerSetID({
          id: stickerSet.id,
          accessHash: stickerSet.accessHash
        }),
        thumbVersion
      }), {
        dcId: stickerSet.thumbDcId
      }); // Sticker thumb cannot be larger than 2GB, right?
    }
    return this.invoke(new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.messages.GetCustomEmojiDocuments({
      documentId: [stickerSet.thumbDocumentId]
    })).then(docs => {
      const doc = docs[0];
      if (!doc || doc instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.DocumentEmpty) {
        return undefined;
      }
      return this.downloadFile(new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.InputDocumentFileLocation({
        id: doc.id,
        accessHash: doc.accessHash,
        fileReference: doc.fileReference,
        thumbSize: ''
      }), {
        fileSize: doc.size.toJSNumber(),
        dcId: doc.dcId
      }); // Sticker thumb cannot be larger than 2GB, right?
    });
  }
  pickFileSize(sizes, sizeType) {
    if (!sizes?.length) return undefined;
    if (!sizeType) {
      const maxSize = sizes.reduce((max, current) => {
        if (!('w' in current)) return max;
        if (!max || !('w' in max)) return current;
        return max.w > current.w ? max : current;
      }, undefined);
      return maxSize;
    }
    const indexOfSize = sizeTypes.indexOf(sizeType);
    let size;
    for (let i = indexOfSize; i < sizeTypes.length; i++) {
      size = sizes.find(s => 'type' in s && s.type === sizeTypes[i]);
      if (size) {
        return size;
      }
    }
    return undefined;
  }
  _downloadCachedPhotoSize(size) {
    // No need to download anything, simply write the bytes
    let data;
    if (size instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.PhotoStrippedSize) {
      data = (0,_Utils__WEBPACK_IMPORTED_MODULE_16__.strippedPhotoToJpg)(size.bytes);
    } else {
      data = size.bytes;
    }
    return data;
  }
  _downloadPhoto(media, args) {
    let photo = media;
    if (media instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.MessageMediaPhoto && media.photo instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.Photo) {
      photo = media.photo;
    }
    if (!(photo instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.Photo)) {
      return undefined;
    }
    const isVideoSize = args.sizeType === 'u' || args.sizeType === 'v';
    const videoSizes = isVideoSize ? photo.videoSizes : [];
    const size = this.pickFileSize([...videoSizes, ...photo.sizes], args.sizeType);
    if (!size || size instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.PhotoSizeEmpty || size instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.VideoSizeEmojiMarkup || size instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.VideoSizeStickerMarkup) {
      return undefined;
    }
    if (size instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.PhotoCachedSize || size instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.PhotoStrippedSize) {
      return this._downloadCachedPhotoSize(size);
    }
    let fileSize;
    if (size instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.PhotoSizeProgressive) {
      fileSize = Math.max(...size.sizes);
    } else {
      fileSize = 'size' in size ? size.size : 512;
    }
    return this.downloadFile(new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.InputPhotoFileLocation({
      id: photo.id,
      accessHash: photo.accessHash,
      fileReference: photo.fileReference,
      thumbSize: size.type
    }), {
      dcId: photo.dcId,
      fileSize,
      progressCallback: args.progressCallback
    });
  }
  _downloadDocument(media, args) {
    let doc = media;
    if (doc instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.MessageMediaDocument && doc.document instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.Document) {
      doc = doc.document;
    }
    if (!(doc instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.Document)) {
      return undefined;
    }
    let size;
    if (args.sizeType) {
      size = this.pickFileSize([...(doc.thumbs || []), ...(doc.videoThumbs || [])], args.sizeType);
      if (!size && doc.mimeType.startsWith('video/')) {
        return undefined;
      }
      if (size && (size instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.PhotoCachedSize || size instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.PhotoStrippedSize)) {
        return this._downloadCachedPhotoSize(size);
      }
    }
    return this.downloadFile(new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.InputDocumentFileLocation({
      id: doc.id,
      accessHash: doc.accessHash,
      fileReference: doc.fileReference,
      thumbSize: size && 'type' in size ? size.type : ''
    }), {
      fileSize: size && 'size' in size ? size.size : doc.size.toJSNumber(),
      progressCallback: args.progressCallback,
      start: args.start,
      end: args.end,
      dcId: doc.dcId,
      workers: args.workers
    });
  }
  async _downloadWebDocument(media) {
    if (media instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.WebDocumentNoProxy) {
      const arrayBuff = await fetch(media.url).then(res => res.arrayBuffer());
      return Buffer.from(arrayBuff);
    }
    try {
      const buff = [];
      let offset = 0;
      while (true) {
        const downloaded = new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.upload.GetWebFile({
          location: new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.InputWebFileLocation({
            url: media.url,
            accessHash: media.accessHash
          }),
          offset,
          limit: WEBDOCUMENT_REQUEST_PART_SIZE
        });
        const sender = await this._borrowExportedSender(this._config?.webfileDcId || DEFAULT_WEBDOCUMENT_DC_ID);
        if (!sender) {
          throw new Error('Failed to obtain sender');
        }
        const res = await sender.send(downloaded);
        this.releaseExportedSender(sender);
        offset += WEBDOCUMENT_REQUEST_PART_SIZE;
        if (res.bytes.length) {
          buff.push(res.bytes);
          if (res.bytes.length < WEBDOCUMENT_REQUEST_PART_SIZE) {
            break;
          }
        } else {
          break;
        }
      }
      return Buffer.concat(buff);
    } catch (err) {
      // the file is no longer saved in telegram's cache.
      if (err instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.RPCError && err.errorMessage === 'WEBFILE_NOT_AVAILABLE') {
        return Buffer.alloc(0);
      } else {
        throw err;
      }
    }
  }
  async downloadStaticMap(accessHash, long, lat, w, h, zoom, scale, accuracyRadius) {
    try {
      const buff = [];
      let offset = 0;
      while (true) {
        try {
          const downloaded = new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.upload.GetWebFile({
            location: new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.InputWebFileGeoPointLocation({
              geoPoint: new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.InputGeoPoint({
                lat,
                long,
                accuracyRadius
              }),
              accessHash,
              w,
              h,
              zoom,
              scale
            }),
            offset,
            limit: WEBDOCUMENT_REQUEST_PART_SIZE
          });
          const sender = await this._borrowExportedSender(DEFAULT_WEBDOCUMENT_DC_ID);
          if (!sender) {
            throw new Error('Failed to obtain sender');
          }
          const res = await sender.send(downloaded);
          this.releaseExportedSender(sender);
          offset += WEBDOCUMENT_REQUEST_PART_SIZE;
          if (res.bytes.length) {
            buff.push(res.bytes);
            if (res.bytes.length < WEBDOCUMENT_REQUEST_PART_SIZE) {
              break;
            }
          } else {
            break;
          }
        } catch (err) {
          if (err instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.FloodWaitError) {
            // eslint-disable-next-line no-console
            console.warn(`getWebFile: sleeping for ${err.seconds}s on flood wait`);
            await (0,_Helpers__WEBPACK_IMPORTED_MODULE_11__.sleep)(err.seconds * 1000);
            continue;
          }
        }
      }
      return Buffer.concat(buff);
    } catch (err) {
      if (err instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.RPCError && err.errorMessage === 'WEBFILE_NOT_AVAILABLE') {
        return Buffer.alloc(0);
      } else {
        throw err;
      }
    }
  }

  // region Invoking Telegram request
  /**
     * Invokes a MTProtoRequest (sends and receives it) and returns its result
     * @param request
     * @param dcId Optional dcId to use when sending the request
     * @param abortSignal Optional AbortSignal to cancel the request
     * @param shouldRetryOnTimeout Whether to retry the request if it times out
     * @returns {Promise}
     */

  async invoke(request, dcId, abortSignal, shouldRetryOnTimeout) {
    if (request.classType !== 'request') {
      throw new Error('You can only invoke MTProtoRequests');
    }
    const isExported = dcId !== undefined;
    let sender = !isExported ? this._sender : await this.getSender(dcId);
    this._lastRequest = Date.now();
    await this._connectedDeferred.promise;
    const state = new _network_RequestState__WEBPACK_IMPORTED_MODULE_12__["default"](request, abortSignal);
    let attempt = 0;
    for (attempt = 0; attempt < this._requestRetries; attempt++) {
      sender.addStateToQueue(state);
      try {
        const result = await state.promise;
        state.finished.resolve();
        if (isExported) this.releaseExportedSender(sender);
        return result;
      } catch (e) {
        if (e instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.ServerError || e instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.RPCError && (e.errorMessage === 'RPC_CALL_FAIL' || e.errorMessage === 'RPC_MCGET_FAIL' || e.errorMessage.match(/INTERDC_\d_CALL(_RICH)?_ERROR/))) {
          this._log.warn(`Telegram is having internal issues ${e.constructor.name}`);
          await (0,_Helpers__WEBPACK_IMPORTED_MODULE_11__.sleep)(2000);
        } else if (e instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.FloodWaitError || e instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.FloodTestPhoneWaitError) {
          if (e.seconds <= this.floodSleepLimit) {
            this._log.info(`Sleeping for ${e.seconds}s on flood wait`);
            await (0,_Helpers__WEBPACK_IMPORTED_MODULE_11__.sleep)(e.seconds * 1000);
          } else {
            state.finished.resolve();
            if (isExported) this.releaseExportedSender(sender);
            throw e;
          }
        } else if (e instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.PhoneMigrateError || e instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.NetworkMigrateError || e instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.UserMigrateError) {
          this._log.info(`Phone migrated to ${e.newDc}`);
          const shouldRaise = e instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.PhoneMigrateError || e instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.NetworkMigrateError;
          if (shouldRaise && (await (0,_auth__WEBPACK_IMPORTED_MODULE_8__.checkAuthorization)(this))) {
            state.finished.resolve();
            if (isExported) this.releaseExportedSender(sender);
            throw e;
          }
          await this._switchDC(e.newDc);
          if (isExported) this.releaseExportedSender(sender);
          sender = dcId === undefined ? this._sender : await this.getSender(dcId);
        } else if (e instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.MsgWaitError) {
          // We need to resend this after the old one was confirmed.
          await state.isReady();
          state.after = undefined;
        } else if (e instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.RPCError && e.errorMessage === 'CONNECTION_NOT_INITED') {
          await this.disconnect();
          await (0,_Helpers__WEBPACK_IMPORTED_MODULE_11__.sleep)(2000);
          await this.connect();
        } else if (e instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.TimedOutError) {
          if (!shouldRetryOnTimeout) {
            state.finished.resolve();
            if (isExported) this.releaseExportedSender(sender);
            throw e;
          }
        } else {
          state.finished.resolve();
          if (isExported) this.releaseExportedSender(sender);
          throw e;
        }
      }
      state.resetPromise();
    }
    if (isExported) this.releaseExportedSender(sender);
    throw new Error(`Request was unsuccessful ${attempt} time(s)`);
  }
  async invokeBeacon(request, dcId) {
    if (request.classType !== 'request') {
      throw new Error('You can only invoke MTProtoRequests');
    }
    const isExported = dcId !== undefined;
    const sender = !isExported ? this._sender : await this.getSender(dcId);
    sender.sendBeacon(request);
    if (isExported) this.releaseExportedSender(sender);
  }
  setIsPremium(isPremium) {
    this.isPremium = isPremium;
  }
  async getMe() {
    try {
      return (await this.invoke(new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.users.GetUsers({
        id: [new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.InputUserSelf()]
      })))[0];
    } catch (e) {
      this._log.warn('error while getting me');
      this._log.warn(e);
    }
    return undefined;
  }
  async loadConfig() {
    if (!this._config) {
      this._config = await this.invoke(new _tl__WEBPACK_IMPORTED_MODULE_6__.Api.help.GetConfig());
    }
  }
  async start(authParams) {
    if (!this.isConnected()) {
      await this.connect();
    }
    this.loadConfig();
    if (await (0,_auth__WEBPACK_IMPORTED_MODULE_8__.checkAuthorization)(this, authParams.shouldThrowIfUnauthorized)) {
      return;
    }
    const apiCredentials = {
      apiId: this.apiId,
      apiHash: this.apiHash
    };
    await (0,_auth__WEBPACK_IMPORTED_MODULE_8__.authFlow)(this, apiCredentials, authParams);
  }
  uploadFile(fileParams) {
    return (0,_uploadFile__WEBPACK_IMPORTED_MODULE_10__.uploadFile)(this, fileParams, this._shouldDebugExportedSenders);
  }
  updateTwoFaSettings(params) {
    return (0,_2fa__WEBPACK_IMPORTED_MODULE_7__.updateTwoFaSettings)(this, params);
  }
  getTmpPassword(currentPassword, ttl) {
    return (0,_2fa__WEBPACK_IMPORTED_MODULE_7__.getTmpPassword)(this, currentPassword, ttl);
  }
  getCurrentPassword(currentPassword) {
    return (0,_2fa__WEBPACK_IMPORTED_MODULE_7__.getCurrentPassword)(this, currentPassword);
  }

  // event region
  addEventHandler(callback, event) {
    this._eventBuilders.push([event, callback]);
  }
  _handleUpdate(update) {
    // this.session.processEntities(update)
    // this._entityCache.add(update)

    if (update instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.Updates || update instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.UpdatesCombined) {
      // TODO deal with entities
      const entities = [];
      for (const x of [...update.users, ...update.chats]) {
        entities.push(x);
      }
      this._processUpdate(update, entities);
    } else if (update instanceof _tl__WEBPACK_IMPORTED_MODULE_6__.Api.UpdateShort) {
      this._processUpdate(update.update, undefined);
    } else {
      this._processUpdate(update, undefined);
    }
  }
  _processUpdate(update, entities) {
    update._entities = entities || [];
    const args = {
      update
    };
    this._dispatchUpdate(args);
  }

  // endregion

  async _dispatchUpdate(args) {
    for (const [builder, callback] of this._eventBuilders) {
      const event = builder.build(args.update);
      if (event) {
        await callback(event);
      }
    }
  }
  isConnected() {
    if (this._sender) {
      if (this._sender.isConnected()) {
        return true;
      }
    }
    return false;
  }
}
function timeout(cb, ms) {
  let isResolved = false;
  return Promise.race([cb(), (0,_Helpers__WEBPACK_IMPORTED_MODULE_11__.sleep)(ms).then(() => isResolved ? undefined : Promise.reject(new Error('TIMEOUT')))]).finally(() => {
    isResolved = true;
  });
}
async function attempts(cb, times, pause) {
  for (let i = 0; i < times; i++) {
    try {
      // We need to `return await` here so it can be caught locally

      return await cb();
    } catch (err) {
      if (i === times - 1) {
        throw err;
      }
      await (0,_Helpers__WEBPACK_IMPORTED_MODULE_11__.sleep)(pause);
    }
  }
  return undefined;
}
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (TelegramClient);

/***/ }),

/***/ "./src/lib/gramjs/client/auth.ts":
/*!***************************************!*\
  !*** ./src/lib/gramjs/client/auth.ts ***!
  \***************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   authFlow: () => (/* binding */ authFlow),
/* harmony export */   checkAuthorization: () => (/* binding */ checkAuthorization),
/* harmony export */   signInUserWithPreferredMethod: () => (/* binding */ signInUserWithPreferredMethod)
/* harmony export */ });
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! big-integer */ "./node_modules/big-integer/BigInteger.js");
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(big_integer__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _util_serverTime__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../util/serverTime */ "./src/util/serverTime.ts");
/* harmony import */ var _api_gramjs_gramjsBuilders__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../api/gramjs/gramjsBuilders */ "./src/api/gramjs/gramjsBuilders/index.ts");
/* harmony import */ var _errors__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../errors */ "./src/lib/gramjs/errors/index.ts");
/* harmony import */ var _tl_api__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../tl/api */ "./src/lib/gramjs/tl/api.js");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* harmony import */ var _Password__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../Password */ "./src/lib/gramjs/Password.ts");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../Utils */ "./src/lib/gramjs/Utils.ts");








const DEFAULT_INITIAL_METHOD = 'phoneNumber';
async function authFlow(client, apiCredentials, authParams) {
  let me;
  if ('botAuthToken' in authParams) {
    me = await signInBot(client, apiCredentials, authParams);
  } else if ('webAuthToken' in authParams && authParams.webAuthToken) {
    me = await signInUserWithWebToken(client, apiCredentials, authParams);
  } else {
    me = await signInUserWithPreferredMethod(client, apiCredentials, authParams);
  }
  client._log.info(`Signed in successfully as ${(0,_Utils__WEBPACK_IMPORTED_MODULE_7__.getDisplayName)(me)}`);
}
function signInUserWithPreferredMethod(client, apiCredentials, authParams) {
  const {
    initialMethod = DEFAULT_INITIAL_METHOD
  } = authParams;
  if (initialMethod === 'phoneNumber') {
    return signInUser(client, apiCredentials, authParams);
  } else {
    return signInUserWithQrCode(client, apiCredentials, authParams);
  }
}
async function checkAuthorization(client, shouldThrow = false) {
  try {
    await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].updates.GetState());
    return true;
  } catch (err) {
    if (err instanceof Error && err.message === 'Disconnect' || shouldThrow) throw err;
    return false;
  }
}
async function signInUserWithWebToken(client, apiCredentials, authParams) {
  try {
    const {
      apiId,
      apiHash
    } = apiCredentials;
    const sendResult = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.ImportWebTokenAuthorization({
      webAuthToken: authParams.webAuthToken,
      apiId,
      apiHash
    }));
    if (sendResult instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.Authorization) {
      return sendResult.user;
    } else {
      throw new Error('SIGN_UP_REQUIRED');
    }
  } catch (err) {
    if (err instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.RPCError && err.errorMessage === 'SESSION_PASSWORD_NEEDED') {
      return signInWithPassword(client, apiCredentials, authParams, true);
    } else {
      client._log.error(`Failed to login with web token: ${String(err)}`);
      authParams.webAuthTokenFailed();
      return signInUserWithPreferredMethod(client, apiCredentials, {
        ...authParams,
        webAuthToken: undefined
      });
    }
  }
}
async function signInUser(client, apiCredentials, authParams) {
  let phoneNumber;
  let phoneCodeHash;
  let isCodeViaApp = false;
  while (true) {
    try {
      if (typeof authParams.phoneNumber === 'function') {
        try {
          phoneNumber = await authParams.phoneNumber();
        } catch (err) {
          if (err instanceof Error && err.message === 'RESTART_AUTH_WITH_QR') {
            return signInUserWithQrCode(client, apiCredentials, authParams);
          }
          throw err;
        }
      } else {
        phoneNumber = authParams.phoneNumber;
      }
      const sendCodeResult = await sendCode(client, apiCredentials, phoneNumber, authParams.forceSMS);
      phoneCodeHash = sendCodeResult.phoneCodeHash;
      isCodeViaApp = sendCodeResult.isCodeViaApp;
      if (typeof phoneCodeHash !== 'string') {
        throw new Error('Failed to retrieve phone code hash');
      }
      break;
    } catch (err) {
      if (typeof authParams.phoneNumber !== 'function') {
        throw err;
      }
      authParams.onError(err);
    }
  }
  let phoneCode;
  let isRegistrationRequired = false;
  let termsOfService;

  // eslint-disable-next-line no-constant-condition
  while (1) {
    try {
      try {
        phoneCode = await authParams.phoneCode(isCodeViaApp);
      } catch (err) {
        // This is the support for changing phone number from the phone code screen.
        if (err instanceof Error && err.message === 'RESTART_AUTH') {
          return signInUser(client, apiCredentials, authParams);
        }
      }
      if (!phoneCode) {
        throw new Error('Code is empty');
      }

      // May raise PhoneCodeEmptyError, PhoneCodeExpiredError,
      // PhoneCodeHashEmptyError or PhoneCodeInvalidError.
      const result = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.SignIn({
        phoneNumber,
        phoneCodeHash,
        phoneCode
      }));
      if (result instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.AuthorizationSignUpRequired) {
        isRegistrationRequired = true;
        termsOfService = result.termsOfService;
        break;
      }
      return result.user;
    } catch (err) {
      if (err instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.RPCError && err.errorMessage === 'SESSION_PASSWORD_NEEDED') {
        return signInWithPassword(client, apiCredentials, authParams);
      } else if (err instanceof Error) {
        authParams.onError(err);
      } else {
        // eslint-disable-next-line no-console
        console.warn('Unexpected error:', err);
      }
    }
  }
  if (isRegistrationRequired) {
    // eslint-disable-next-line no-constant-condition
    while (1) {
      try {
        const [firstName, lastName] = await authParams.firstAndLastNames();
        if (!firstName) {
          throw new Error('First name is required');
        }
        const {
          user
        } = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.SignUp({
          phoneNumber,
          phoneCodeHash,
          firstName,
          lastName: lastName || _api_gramjs_gramjsBuilders__WEBPACK_IMPORTED_MODULE_2__.DEFAULT_PRIMITIVES.STRING
        }));
        if (termsOfService) {
          // This is a violation of Telegram rules: the user should be presented with and accept TOS.
          await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].help.AcceptTermsOfService({
            id: termsOfService.id
          }));
        }
        return user;
      } catch (err) {
        authParams.onError(err);
      }
    }
  }
  authParams.onError(new Error('Auth failed'));
  return signInUser(client, apiCredentials, authParams);
}
async function signInUserWithQrCode(client, apiCredentials, authParams) {
  let isScanningComplete = false;
  const {
    apiId,
    apiHash
  } = apiCredentials;
  const inputPromise = (async () => {
    // eslint-disable-next-line no-constant-condition
    while (1) {
      if (isScanningComplete) {
        break;
      }
      const result = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.ExportLoginToken({
        apiId,
        apiHash,
        exceptIds: authParams.accountIds?.map(id => big_integer__WEBPACK_IMPORTED_MODULE_0___default()(id)) || []
      }));
      if (!(result instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.LoginToken)) {
        throw new Error('Unexpected');
      }
      const {
        token,
        expires
      } = result;
      await Promise.race([authParams.qrCode({
        token,
        expires
      }), (0,_Helpers__WEBPACK_IMPORTED_MODULE_5__.sleep)((expires - (0,_util_serverTime__WEBPACK_IMPORTED_MODULE_1__.getServerTime)()) * 1000)]);
    }
  })();
  const updatePromise = new Promise(resolve => {
    client.addEventHandler(update => {
      if (update instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].UpdateLoginToken) {
        resolve();
      }
    }, {
      build: update => update
    });
  });
  try {
    // Either we receive an update that QR is successfully scanned,
    // or we receive a rejection caused by user going back to the regular auth form
    await Promise.race([updatePromise, inputPromise]);
  } catch (err) {
    if (err instanceof Error && err.message === 'RESTART_AUTH') {
      return await signInUser(client, apiCredentials, authParams);
    }
    throw err;
  } finally {
    isScanningComplete = true;
  }
  try {
    const result2 = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.ExportLoginToken({
      apiId,
      apiHash,
      exceptIds: authParams.accountIds?.map(id => big_integer__WEBPACK_IMPORTED_MODULE_0___default()(id)) || []
    }));
    if (result2 instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.LoginTokenSuccess && result2.authorization instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.Authorization) {
      return result2.authorization.user;
    } else if (result2 instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.LoginTokenMigrateTo) {
      await client._switchDC(result2.dcId);
      const migratedResult = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.ImportLoginToken({
        token: result2.token
      }));
      if (migratedResult instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.LoginTokenSuccess && migratedResult.authorization instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.Authorization) {
        return migratedResult.authorization.user;
      }
    }
  } catch (err) {
    if (err instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.RPCError && err.errorMessage === 'SESSION_PASSWORD_NEEDED') {
      return signInWithPassword(client, apiCredentials, authParams);
    }
    throw err;
  }

  // This is a workaround for TypeScript (never actually reached)
  // eslint-disable-next-line @typescript-eslint/only-throw-error
  throw undefined;
}
async function sendCode(client, apiCredentials, phoneNumber, forceSMS = false) {
  try {
    const {
      apiId,
      apiHash
    } = apiCredentials;
    const sendResult = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.SendCode({
      phoneNumber,
      apiId,
      apiHash,
      settings: new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].CodeSettings()
    }));
    if (!(sendResult instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.SentCode)) {
      throw Error('Unexpected SentCodeSuccess');
    }

    // If we already sent a SMS, do not resend the phoneCode (hash may be empty)
    if (!forceSMS || sendResult.type instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.SentCodeTypeSms) {
      return {
        phoneCodeHash: sendResult.phoneCodeHash,
        isCodeViaApp: sendResult.type instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.SentCodeTypeApp
      };
    }
    const resendResult = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.ResendCode({
      phoneNumber,
      phoneCodeHash: sendResult.phoneCodeHash
    }));
    if (!(resendResult instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.SentCode)) {
      throw Error('Unexpected SentCodeSuccess');
    }
    return {
      phoneCodeHash: resendResult.phoneCodeHash,
      isCodeViaApp: resendResult.type instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.SentCodeTypeApp
    };
  } catch (err) {
    if (err instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.RPCError && err.errorMessage === 'AUTH_RESTART') {
      return sendCode(client, apiCredentials, phoneNumber, forceSMS);
    } else {
      throw err;
    }
  }
}
async function signInWithPassword(client, apiCredentials, authParams, noReset = false) {
  // eslint-disable-next-line no-constant-condition
  while (1) {
    try {
      const passwordSrpResult = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].account.GetPassword());
      const password = await authParams.password(passwordSrpResult.hint, noReset);
      if (!password) {
        throw new Error('Password is empty');
      }
      const passwordSrpCheck = await (0,_Password__WEBPACK_IMPORTED_MODULE_6__.computeCheck)(passwordSrpResult, password);
      const {
        user
      } = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.CheckPassword({
        password: passwordSrpCheck
      }));
      return user;
    } catch (err) {
      authParams.onError(err);
    }
  }
  return undefined; // Never reached (TypeScript fix)
}
async function signInBot(client, apiCredentials, authParams) {
  const {
    apiId,
    apiHash
  } = apiCredentials;
  const {
    botAuthToken
  } = authParams;
  const {
    user
  } = await client.invoke(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].auth.ImportBotAuthorization({
    apiId,
    apiHash,
    botAuthToken
  }));
  return user;
}

/***/ }),

/***/ "./src/lib/gramjs/client/downloadFile.ts":
/*!***********************************************!*\
  !*** ./src/lib/gramjs/client/downloadFile.ts ***!
  \***********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   downloadFile: () => (/* binding */ downloadFile)
/* harmony export */ });
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! big-integer */ "./node_modules/big-integer/BigInteger.js");
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(big_integer__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _util_Deferred__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../util/Deferred */ "./src/util/Deferred.ts");
/* harmony import */ var _util_foreman__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../util/foreman */ "./src/util/foreman.ts");
/* harmony import */ var _errors__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../errors */ "./src/lib/gramjs/errors/index.ts");
/* harmony import */ var _tl_api__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../tl/api */ "./src/lib/gramjs/tl/api.js");
/* harmony import */ var _api_gramjs_updates_UpdatePremiumFloodWait__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../api/gramjs/updates/UpdatePremiumFloodWait */ "./src/api/gramjs/updates/UpdatePremiumFloodWait.ts");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../Utils */ "./src/lib/gramjs/Utils.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];








// Chunk sizes for `upload.getFile` must be multiple of the smallest size
const MIN_CHUNK_SIZE = 4096;
const DEFAULT_CHUNK_SIZE = 64; // kb
const ONE_MB = 1024 * 1024;
const DISCONNECT_SLEEP = 1000;
const NEW_CONNECTION_QUEUE_THRESHOLD = 5;

// when the sender requests hangs for 60 second we will reimport
const SENDER_TIMEOUT = 60 * 1000;
// Telegram may have server issues so we try several times
const SENDER_RETRIES = 5;
class FileView {
  constructor(size) {
    this.size = size;
    this.type = size && size > self.maxBufferSize ? 'opfs' : 'memory';
  }
  async init() {
    if (this.type === 'opfs') {
      if (!FileSystemFileHandle?.prototype.createSyncAccessHandle) {
        throw new Error('`createSyncAccessHandle` is not available. Cannot download files larger than 2GB.');
      }
      const directory = await navigator.storage.getDirectory();
      const downloadsFolder = await directory.getDirectoryHandle('downloads', {
        create: true
      });
      this.largeFile = await downloadsFolder.getFileHandle(Math.random().toString(), {
        create: true
      });
      this.largeFileAccessHandle = await this.largeFile.createSyncAccessHandle();
    } else {
      this.buffer = this.size ? Buffer.alloc(this.size) : Buffer.alloc(0);
    }
  }
  write(data, offset) {
    if (this.type === 'opfs') {
      this.largeFileAccessHandle.write(data, {
        at: offset
      });
    } else if (this.size) {
      for (let i = 0; i < data.length; i++) {
        if (offset + i >= this.buffer.length) return;
        this.buffer.writeUInt8(data[i], offset + i);
      }
    } else {
      this.buffer = Buffer.concat([this.buffer, data]);
    }
  }
  async getData() {
    if (this.type === 'opfs') {
      return this.largeFile.getFile();
    } else {
      return Promise.resolve(this.buffer);
    }
  }
}
async function downloadFile(client, inputLocation, fileParams, shouldDebugExportedSenders) {
  const {
    dcId
  } = fileParams;
  for (let i = 0; i < SENDER_RETRIES; i++) {
    try {
      return await downloadFile2(client, inputLocation, fileParams, shouldDebugExportedSenders);
    } catch (err) {
      if (err instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.RPCError && (err.errorMessage.startsWith('SESSION_REVOKED') || err.errorMessage.startsWith('CONNECTION_NOT_INITED')) && i < SENDER_RETRIES - 1) {
        await client._cleanupExportedSenders(dcId);
      } else {
        throw err;
      }
    }
  }
  return undefined;
}
const MAX_CONCURRENT_CONNECTIONS = 3;
const MAX_CONCURRENT_CONNECTIONS_PREMIUM = 6;
const MAX_WORKERS_PER_CONNECTION = 10;
const MULTIPLE_CONNECTIONS_MIN_FILE_SIZE = 10485760; // 10MB

const foremans = Array(MAX_CONCURRENT_CONNECTIONS_PREMIUM).fill(undefined).map(() => new _util_foreman__WEBPACK_IMPORTED_MODULE_2__.Foreman(MAX_WORKERS_PER_CONNECTION));
async function downloadFile2(client, inputLocation, fileParams, shouldDebugExportedSenders) {
  let {
    partSizeKb,
    end = 0
  } = fileParams;
  const {
    fileSize,
    dcId,
    progressCallback,
    isPriority,
    start = 0
  } = fileParams;
  const fileId = 'id' in inputLocation ? inputLocation.id : undefined;
  const logWithId = (...args) => {
    if (!shouldDebugExportedSenders) return;
    // eslint-disable-next-line no-console
    console.log(`⬇️ [${fileId?.toString()}/${fileParams.dcId}]`, ...args);
  };
  logWithId('Downloading file...');
  const isPremium = Boolean(client.isPremium);
  if (fileSize) {
    end = end && end < fileSize ? end : fileSize - 1;
  }
  const rangeSize = end ? end - start + 1 : undefined;
  if (!partSizeKb) {
    partSizeKb = fileSize ? (0,_Utils__WEBPACK_IMPORTED_MODULE_7__.getDownloadPartSize)(rangeSize || fileSize) : DEFAULT_CHUNK_SIZE;
  }
  const partSize = partSizeKb * 1024;
  const partsCount = rangeSize ? Math.ceil(rangeSize / partSize) : 1;
  const noParallel = !end;
  const shouldUseMultipleConnections = Boolean(fileSize) && fileSize >= MULTIPLE_CONNECTIONS_MIN_FILE_SIZE && !noParallel;
  let deferred;
  if (partSize % MIN_CHUNK_SIZE !== 0) {
    throw new Error(`The part size must be evenly divisible by ${MIN_CHUNK_SIZE}`);
  }
  client._log.info(`Downloading file in chunks of ${partSize} bytes`);
  const fileView = new FileView(rangeSize);
  const promises = [];
  let offset = start;
  // Used for files with unknown size and for manual cancellations
  let hasEnded = false;
  let progress = 0;
  if (progressCallback) {
    progressCallback(progress);
  }

  // Limit updates to one per file
  let isPremiumFloodWaitSent = false;

  // Allocate memory
  await fileView.init();
  while (true) {
    let limit = partSize;
    let isPrecise = false;
    if (Math.floor(offset / ONE_MB) !== Math.floor((offset + limit - 1) / ONE_MB)) {
      limit = ONE_MB - offset % ONE_MB;
      isPrecise = true;
    }
    if (offset % MIN_CHUNK_SIZE !== 0 || limit % MIN_CHUNK_SIZE !== 0) {
      isPrecise = true;
    }
    const senderIndex = getFreeForemanIndex(isPremium, shouldUseMultipleConnections);
    await foremans[senderIndex].requestWorker(isPriority);
    if (deferred) await deferred.promise;
    if (noParallel) deferred = new _util_Deferred__WEBPACK_IMPORTED_MODULE_1__["default"]();
    if (hasEnded) {
      foremans[senderIndex].releaseWorker();
      break;
    }
    const logWithSenderIndex = (...args) => {
      logWithId(`[${senderIndex}/${dcId}]`, ...args);
    };
    promises.push((async offsetMemo => {
      while (true) {
        let sender;
        try {
          let isDone = false;
          if (shouldDebugExportedSenders) {
            setTimeout(() => {
              if (isDone) return;
              logWithSenderIndex(`❗️️ getSender took too long ${offsetMemo}`);
            }, 8000);
          }
          sender = await client.getSender(dcId, senderIndex, isPremium);
          isDone = true;
          let isDone2 = false;
          if (shouldDebugExportedSenders) {
            setTimeout(() => {
              if (isDone2) return;
              logWithSenderIndex(`❗️️ sender.send took too long ${offsetMemo}`);
            }, 6000);
          }
          // sometimes a session is revoked and will cause this to hang.
          const result = await Promise.race([sender.send(new _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].upload.GetFile({
            location: inputLocation,
            offset: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(offsetMemo),
            limit,
            precise: isPrecise || undefined
          })), (0,_Helpers__WEBPACK_IMPORTED_MODULE_6__.sleep)(SENDER_TIMEOUT).then(() => {
            // If we're on the main DC we just cancel the download and let the user retry later
            if (dcId === client.session.dcId) {
              logWithSenderIndex(`Download timed out ${offsetMemo}`);
              return Promise.reject(new Error('USER_CANCELED'));
            } else {
              logWithSenderIndex(`Download timed out [not main] ${offsetMemo}`);
              return Promise.reject(new Error('SESSION_REVOKED'));
            }
          })]);
          client.releaseExportedSender(sender);
          if (result instanceof _tl_api__WEBPACK_IMPORTED_MODULE_4__["default"].upload.FileCdnRedirect) {
            throw new Error('CDN download not supported');
          }
          isDone2 = true;
          if (progressCallback) {
            if (progressCallback.isCanceled) {
              throw new Error('USER_CANCELED');
            }
            progress += 1 / partsCount;
            logWithSenderIndex(`⬇️️ ${progress * 100}%`);
            progressCallback(progress);
          }
          if (!end && result.bytes.length < limit) {
            hasEnded = true;
          }
          foremans[senderIndex].releaseWorker();
          if (deferred) deferred.resolve();
          fileView.write(result.bytes, offsetMemo - start);
          return;
        } catch (err) {
          if (sender && !sender.isConnected()) {
            await (0,_Helpers__WEBPACK_IMPORTED_MODULE_6__.sleep)(DISCONNECT_SLEEP);
            continue;
          } else if (err instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.FloodWaitError) {
            if (err instanceof _errors__WEBPACK_IMPORTED_MODULE_3__.FloodPremiumWaitError && !isPremiumFloodWaitSent) {
              sender?._updateCallback(new _api_gramjs_updates_UpdatePremiumFloodWait__WEBPACK_IMPORTED_MODULE_5__["default"](false));
              isPremiumFloodWaitSent = true;
            }
            await (0,_Helpers__WEBPACK_IMPORTED_MODULE_6__.sleep)(err.seconds * 1000);
            continue;
          }
          logWithSenderIndex(`Ended not gracefully ${offsetMemo}`);
          foremans[senderIndex].releaseWorker();
          if (deferred) deferred.resolve();
          hasEnded = true;
          if (sender) client.releaseExportedSender(sender);
          throw err;
        }
      }
    })(offset));
    offset += limit;
    if (end && offset > end) {
      break;
    }
  }
  await Promise.all(promises);
  return fileView.getData();
}
function getFreeForemanIndex(isPremium, forceNewConnection) {
  const availableConnections = isPremium ? MAX_CONCURRENT_CONNECTIONS_PREMIUM : MAX_CONCURRENT_CONNECTIONS;
  let foremanIndex = 0;
  let minQueueLength = Infinity;
  for (let i = 0; i < availableConnections; i++) {
    const foreman = foremans[i];
    // If worker is free, return it
    if (!foreman.queueLength) return i;

    // Potentially create a new connection if the current queue is too long
    if (!forceNewConnection && foreman.queueLength <= NEW_CONNECTION_QUEUE_THRESHOLD) {
      return i;
    }

    // If every connection is equally busy, prefer the last one in the list
    if (foreman.queueLength <= minQueueLength) {
      foremanIndex = i;
      minQueueLength = foreman.activeWorkers;
    }
  }
  return foremanIndex;
}

/***/ }),

/***/ "./src/lib/gramjs/client/uploadFile.ts":
/*!*********************************************!*\
  !*** ./src/lib/gramjs/client/uploadFile.ts ***!
  \*********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   uploadFile: () => (/* binding */ uploadFile)
/* harmony export */ });
/* harmony import */ var _util_foreman__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../util/foreman */ "./src/util/foreman.ts");
/* harmony import */ var _errors__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../errors */ "./src/lib/gramjs/errors/index.ts");
/* harmony import */ var _tl_api__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../tl/api */ "./src/lib/gramjs/tl/api.js");
/* harmony import */ var _api_gramjs_updates_UpdatePremiumFloodWait__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../api/gramjs/updates/UpdatePremiumFloodWait */ "./src/api/gramjs/updates/UpdatePremiumFloodWait.ts");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../Utils */ "./src/lib/gramjs/Utils.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];






const KB_TO_BYTES = 1024;
const LARGE_FILE_THRESHOLD = 10 * 1024 * 1024;
const DISCONNECT_SLEEP = 1000;
const MAX_CONCURRENT_CONNECTIONS = 3;
const MAX_CONCURRENT_CONNECTIONS_PREMIUM = 6;
const MAX_WORKERS_PER_CONNECTION = 10;
const foremans = Array(MAX_CONCURRENT_CONNECTIONS_PREMIUM).fill(undefined).map(() => new _util_foreman__WEBPACK_IMPORTED_MODULE_0__.Foreman(MAX_WORKERS_PER_CONNECTION));
async function uploadFile(client, fileParams, shouldDebugExportedSenders) {
  const {
    file,
    onProgress
  } = fileParams;
  const isPremium = Boolean(client.isPremium);
  const {
    name,
    size
  } = file;
  const fileId = (0,_Helpers__WEBPACK_IMPORTED_MODULE_4__.readBigIntFromBuffer)((0,_Helpers__WEBPACK_IMPORTED_MODULE_4__.generateRandomBytes)(8), true, true);
  const isLarge = size > LARGE_FILE_THRESHOLD;
  const logWithId = (...args) => {
    if (!shouldDebugExportedSenders) return;
    // eslint-disable-next-line no-console
    console.log(`⬆️ [${fileId.toString()}]`, ...args);
  };
  logWithId('Uploading file...');
  const partSize = (0,_Utils__WEBPACK_IMPORTED_MODULE_5__.getUploadPartSize)(size) * KB_TO_BYTES;
  const partCount = Math.floor((size + partSize - 1) / partSize);

  // Pick the least busy foreman
  // For some reason, fresh connections give out a higher speed for the first couple of seconds
  // I have no idea why, but this may speed up the download of small files
  const activeCounts = foremans.map(({
    activeWorkers
  }) => activeWorkers);
  let currentForemanIndex = activeCounts.indexOf(Math.min(...activeCounts));
  let progress = 0;
  if (onProgress) {
    onProgress(progress);
  }

  // Limit updates to one per file
  let isPremiumFloodWaitSent = false;
  const promises = [];
  for (let i = 0; i < partCount; i++) {
    const senderIndex = currentForemanIndex % (isPremium ? MAX_CONCURRENT_CONNECTIONS_PREMIUM : MAX_CONCURRENT_CONNECTIONS);
    await foremans[senderIndex].requestWorker();
    if (onProgress?.isCanceled) {
      foremans[senderIndex].releaseWorker();
      break;
    }
    const logWithSenderIndex = (...args) => {
      logWithId(`[${senderIndex}]`, ...args);
    };
    const blobSlice = file.slice(i * partSize, (i + 1) * partSize);
    promises.push((async (jMemo, blobSliceMemo) => {
      while (true) {
        let sender;
        try {
          // We always upload from the DC we are in
          let isDone = false;
          if (shouldDebugExportedSenders) {
            setTimeout(() => {
              if (isDone) return;
              logWithSenderIndex(`❗️️ getSender took too long j=${jMemo}`);
            }, 8000);
          }
          sender = await client.getSender(client.session.dcId, senderIndex, isPremium);
          isDone = true;
          let isDone2 = false;
          const partBytes = await blobSliceMemo.arrayBuffer();
          if (shouldDebugExportedSenders) {
            setTimeout(() => {
              if (isDone2) return;
              logWithSenderIndex(`❗️️ sender.send took too long j=${jMemo}`);
            }, 6000);
          }
          await sender.send(isLarge ? new _tl_api__WEBPACK_IMPORTED_MODULE_2__["default"].upload.SaveBigFilePart({
            fileId,
            filePart: jMemo,
            fileTotalParts: partCount,
            bytes: Buffer.from(partBytes)
          }) : new _tl_api__WEBPACK_IMPORTED_MODULE_2__["default"].upload.SaveFilePart({
            fileId,
            filePart: jMemo,
            bytes: Buffer.from(partBytes)
          }));
          client.releaseExportedSender(sender);
          isDone2 = true;
        } catch (err) {
          logWithSenderIndex(`❗️️️Upload part failed ${err?.toString()} j=${jMemo}`);
          if (sender && !sender.isConnected()) {
            await (0,_Helpers__WEBPACK_IMPORTED_MODULE_4__.sleep)(DISCONNECT_SLEEP);
            continue;
          } else if (err instanceof _errors__WEBPACK_IMPORTED_MODULE_1__.FloodWaitError) {
            if (err instanceof _errors__WEBPACK_IMPORTED_MODULE_1__.FloodPremiumWaitError && !isPremiumFloodWaitSent) {
              sender?._updateCallback(new _api_gramjs_updates_UpdatePremiumFloodWait__WEBPACK_IMPORTED_MODULE_3__["default"](true));
              isPremiumFloodWaitSent = true;
            }
            await (0,_Helpers__WEBPACK_IMPORTED_MODULE_4__.sleep)(err.seconds * 1000);
            continue;
          }
          foremans[senderIndex].releaseWorker();
          if (sender) client.releaseExportedSender(sender);
          throw err;
        }
        foremans[senderIndex].releaseWorker();
        if (onProgress) {
          if (onProgress.isCanceled) {
            throw new Error('USER_CANCELED');
          }
          progress += 1 / partCount;
          logWithSenderIndex(`${progress * 100}%`);
          onProgress(progress);
        }
        break;
      }
    })(i, blobSlice));
    currentForemanIndex++;
  }
  await Promise.all(promises);
  return isLarge ? new _tl_api__WEBPACK_IMPORTED_MODULE_2__["default"].InputFileBig({
    id: fileId,
    parts: partCount,
    name
  }) : new _tl_api__WEBPACK_IMPORTED_MODULE_2__["default"].InputFile({
    id: fileId,
    parts: partCount,
    name,
    md5Checksum: '' // This is not a "flag", so not sure if we can make it optional.
  });
}

/***/ }),

/***/ "./src/lib/gramjs/crypto/AuthKey.ts":
/*!******************************************!*\
  !*** ./src/lib/gramjs/crypto/AuthKey.ts ***!
  \******************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AuthKey: () => (/* binding */ AuthKey)
/* harmony export */ });
/* harmony import */ var _extensions__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../extensions */ "./src/lib/gramjs/extensions/index.ts");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];


class AuthKey {
  constructor(value, hash) {
    if (!hash || !value) {
      return;
    }
    this._key = value;
    this._hash = hash;
    const reader = new _extensions__WEBPACK_IMPORTED_MODULE_0__.BinaryReader(hash);
    this.auxHash = reader.readLong(false);
    reader.read(4);
    this.keyId = reader.readLong(false);
  }
  async setKey(value) {
    if (!value) {
      this._key = undefined;
      this.auxHash = undefined;
      this.keyId = undefined;
      this._hash = undefined;
      return;
    }
    if (value instanceof AuthKey) {
      this._key = value._key;
      this.auxHash = value.auxHash;
      this.keyId = value.keyId;
      this._hash = value._hash;
      return;
    }
    this._key = value;
    this._hash = await (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.sha1)(this._key);
    const reader = new _extensions__WEBPACK_IMPORTED_MODULE_0__.BinaryReader(this._hash);
    this.auxHash = reader.readLong(false);
    reader.read(4);
    this.keyId = reader.readLong(false);
  }
  async waitForKey() {
    while (!this.keyId) {
      await (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.sleep)(20);
    }
  }
  getKey() {
    return this._key;
  }

  // TODO : This doesn't really fit here, it's only used in authentication

  /**
     * Calculates the new nonce hash based on the current class fields' values
     * @param newNonce
     * @param number
     * @returns {BigInt.BigInteger}
     */
  async calcNewNonceHash(newNonce, number) {
    if (!this.auxHash) {
      throw new Error('Auth key not set');
    }
    const nonce = (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.toSignedLittleBuffer)(newNonce, 32);
    const n = Buffer.alloc(1);
    n.writeUInt8(number, 0);
    const data = Buffer.concat([nonce, Buffer.concat([n, (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.readBufferFromBigInt)(this.auxHash, 8, true)])]);

    // Calculates the message key from the given data
    const shaData = (await (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.sha1)(data)).slice(4, 20);
    return (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.readBigIntFromBuffer)(shaData, true, true);
  }
  equals(other) {
    return other instanceof this.constructor && this._key && Buffer.isBuffer(other.getKey()) && other.getKey()?.equals(this._key);
  }
}

/***/ }),

/***/ "./src/lib/gramjs/crypto/CTR.ts":
/*!**************************************!*\
  !*** ./src/lib/gramjs/crypto/CTR.ts ***!
  \**************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   CTR: () => (/* binding */ CTR)
/* harmony export */ });
/* harmony import */ var _crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./crypto */ "./src/lib/gramjs/crypto/crypto.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];

class CTR {
  constructor(key, iv) {
    if (!Buffer.isBuffer(key) || !Buffer.isBuffer(iv) || iv.length !== 16) {
      throw new Error('Key and iv need to be a buffer');
    }
    this.cipher = (0,_crypto__WEBPACK_IMPORTED_MODULE_0__.createCipheriv)('AES-256-CTR', key, iv);
    this.decipher = (0,_crypto__WEBPACK_IMPORTED_MODULE_0__.createDecipheriv)('AES-256-CTR', key, iv);
  }
  encrypt(data) {
    return Buffer.from(this.cipher.update(data));
  }
  decrypt(data) {
    return Buffer.from(this.decipher.update(data));
  }
}

/***/ }),

/***/ "./src/lib/gramjs/crypto/Factorizator.ts":
/*!***********************************************!*\
  !*** ./src/lib/gramjs/crypto/Factorizator.ts ***!
  \***********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Factorizator: () => (/* binding */ Factorizator)
/* harmony export */ });
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! big-integer */ "./node_modules/big-integer/BigInteger.js");
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(big_integer__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");


class Factorizator {
  /**
     * Calculates the greatest common divisor
     * @param a {BigInteger}
     * @param b {BigInteger}
     * @returns {BigInteger}
     */
  static gcd(a, b) {
    while (b.neq((big_integer__WEBPACK_IMPORTED_MODULE_0___default().zero))) {
      const temp = b;
      b = a.remainder(b);
      a = temp;
    }
    return a;
  }

  /**
     * Factorizes the given number and returns both the divisor and the number divided by the divisor
     * @param pq {BigInteger}
     * @returns {{p: *, q: *}}
     */
  static factorize(pq) {
    if (pq.remainder(2).equals((big_integer__WEBPACK_IMPORTED_MODULE_0___default().zero))) {
      return {
        p: big_integer__WEBPACK_IMPORTED_MODULE_0___default()(2),
        q: pq.divide(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(2))
      };
    }
    let y = big_integer__WEBPACK_IMPORTED_MODULE_0___default().randBetween(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(1), pq.minus(1));
    const c = big_integer__WEBPACK_IMPORTED_MODULE_0___default().randBetween(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(1), pq.minus(1));
    const m = big_integer__WEBPACK_IMPORTED_MODULE_0___default().randBetween(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(1), pq.minus(1));
    let g = (big_integer__WEBPACK_IMPORTED_MODULE_0___default().one);
    let r = (big_integer__WEBPACK_IMPORTED_MODULE_0___default().one);
    let q = (big_integer__WEBPACK_IMPORTED_MODULE_0___default().one);
    let x = (big_integer__WEBPACK_IMPORTED_MODULE_0___default().zero);
    let ys = (big_integer__WEBPACK_IMPORTED_MODULE_0___default().zero);
    let k;
    while (g.eq((big_integer__WEBPACK_IMPORTED_MODULE_0___default().one))) {
      x = y;
      for (let i = 0; big_integer__WEBPACK_IMPORTED_MODULE_0___default()(i).lesser(r); i++) {
        y = (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.modExp)(y, big_integer__WEBPACK_IMPORTED_MODULE_0___default()(2), pq).add(c).remainder(pq);
      }
      k = (big_integer__WEBPACK_IMPORTED_MODULE_0___default().zero);
      while (k.lesser(r) && g.eq((big_integer__WEBPACK_IMPORTED_MODULE_0___default().one))) {
        ys = y;
        const condition = big_integer__WEBPACK_IMPORTED_MODULE_0___default().min(m, r.minus(k));
        for (let i = 0; big_integer__WEBPACK_IMPORTED_MODULE_0___default()(i).lesser(condition); i++) {
          y = (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.modExp)(y, big_integer__WEBPACK_IMPORTED_MODULE_0___default()(2), pq).add(c).remainder(pq);
          q = q.multiply(x.minus(y).abs()).remainder(pq);
        }
        g = Factorizator.gcd(q, pq);
        k = k.add(m);
      }
      r = r.multiply(2);
    }
    if (g.eq(pq)) {
      while (true) {
        ys = (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.modExp)(ys, big_integer__WEBPACK_IMPORTED_MODULE_0___default()(2), pq).add(c).remainder(pq);
        g = Factorizator.gcd(x.minus(ys).abs(), pq);
        if (g.greater(1)) {
          break;
        }
      }
    }
    const p = g;
    q = pq.divide(g);
    return p < q ? {
      p,
      q
    } : {
      p: q,
      q: p
    };
  }
}

/***/ }),

/***/ "./src/lib/gramjs/crypto/IGE.ts":
/*!**************************************!*\
  !*** ./src/lib/gramjs/crypto/IGE.ts ***!
  \**************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   IGE: () => (/* binding */ IGENEW)
/* harmony export */ });
/* harmony import */ var _cryptography_aes__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @cryptography/aes */ "./node_modules/@cryptography/aes/dist/es/aes.js");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];


class IGENEW {
  constructor(key, iv) {
    this.ige = new _cryptography_aes__WEBPACK_IMPORTED_MODULE_0__.IGE(key, iv);
  }

  /**
     * Decrypts the given text in 16-bytes blocks by using the given key and 32-bytes initialization vector
     * @param cipherText {Buffer}
     * @returns {Buffer}
     */
  decryptIge(cipherText) {
    return (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.convertToLittle)(this.ige.decrypt(cipherText));
  }

  /**
     * Encrypts the given text in 16-bytes blocks by using the given key and 32-bytes initialization vector
     * @param plainText {Buffer}
     * @returns {Buffer}
     */
  encryptIge(plainText) {
    const padding = plainText.length % 16;
    if (padding) {
      plainText = Buffer.concat([plainText, (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.generateRandomBytes)(16 - padding)]);
    }
    return (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.convertToLittle)(this.ige.encrypt(plainText));
  }
}


/***/ }),

/***/ "./src/lib/gramjs/crypto/RSA.ts":
/*!**************************************!*\
  !*** ./src/lib/gramjs/crypto/RSA.ts ***!
  \**************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   SERVER_KEYS: () => (/* binding */ SERVER_KEYS),
/* harmony export */   encrypt: () => (/* binding */ encrypt)
/* harmony export */ });
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! big-integer */ "./node_modules/big-integer/BigInteger.js");
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(big_integer__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];


const SERVER_KEYS = [{
  fingerprint: big_integer__WEBPACK_IMPORTED_MODULE_0___default()('-3414540481677951611'),
  n: big_integer__WEBPACK_IMPORTED_MODULE_0___default()('2937959817066933702298617714945612856538843112005886376816255642404751219133084745514657634448776440866' + '1701890505066208632169112269581063774293102577308490531282748465986139880977280302242772832972539403531' + '3160108704012876427630091361567343395380424193887227773571344877461690935390938502512438971889287359033' + '8945177273024525306296338410881284207988753897636046529094613963869149149606209957083647645485599631919' + '2747663615955633778034897140982517446405334423701359108810182097749467210509584293428076654573384828809' + '574217079944388301239431309115013843331317877374435868468779972014486325557807783825502498215169806323'),
  e: 65537
}, {
  fingerprint: big_integer__WEBPACK_IMPORTED_MODULE_0___default()('-5595554452916591101'),
  n: big_integer__WEBPACK_IMPORTED_MODULE_0___default()('2534288944884041556497168959071347320689884775908477905258202659454602246385394058588521595116849196570' + '8222649399180603818074200620463776135424884632162512403163793083921641631564740959529419359595852941166' + '8489405859523376133330223960965841179548922160312292373029437018775884567383353986024616752250817918203' + '9315375750495263623495132323782003654358104782690612092797248736680529211579223142368426126233039432475' + '0785450942589751755390156647751460719351439969059949569615302809050721500330239005077889855323917509948' + '255722081644689442127297605422579707142646660768825302832201908302295573257427896031830742328565032949'),
  e: 65537
}].reduce((acc, {
  fingerprint,
  ...keyInfo
}) => {
  acc.set(fingerprint.toString(), keyInfo);
  return acc;
}, new Map());

/**
 * Encrypts the given data known the fingerprint to be used
 * in the way Telegram requires us to do so (sha1(data) + data + padding)

 * @param fingerprint the fingerprint of the RSA key.
 * @param data the data to be encrypted.
 * @returns {Buffer|*|undefined} the cipher text, or undefined if no key matching this fingerprint is found.
 */
async function encrypt(fingerprint, data) {
  const key = SERVER_KEYS.get(fingerprint.toString());
  if (!key) {
    return undefined;
  }

  // len(sha1.digest) is always 20, so we're left with 255 - 20 - x padding
  const rand = (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.generateRandomBytes)(235 - data.length);
  const toEncrypt = Buffer.concat([await (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.sha1)(data), data, rand]);

  // rsa module rsa.encrypt adds 11 bits for padding which we don't want
  // rsa module uses rsa.transform.bytes2int(to_encrypt), easier way:
  const payload = (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.readBigIntFromBuffer)(toEncrypt, false);
  const encrypted = (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.modExp)(payload, big_integer__WEBPACK_IMPORTED_MODULE_0___default()(key.e), key.n);
  // rsa module uses transform.int2bytes(encrypted, keylength), easier:
  return (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.readBufferFromBigInt)(encrypted, 256, false);
}

/***/ }),

/***/ "./src/lib/gramjs/crypto/converters.ts":
/*!*********************************************!*\
  !*** ./src/lib/gramjs/crypto/converters.ts ***!
  \*********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ab2i: () => (/* binding */ ab2i),
/* harmony export */   ab2iBig: () => (/* binding */ ab2iBig),
/* harmony export */   ab2iLow: () => (/* binding */ ab2iLow),
/* harmony export */   i2ab: () => (/* binding */ i2ab),
/* harmony export */   i2abBig: () => (/* binding */ i2abBig),
/* harmony export */   i2abLow: () => (/* binding */ i2abLow),
/* harmony export */   isBigEndian: () => (/* binding */ isBigEndian)
/* harmony export */ });
/**
 * Uint32Array -> ArrayBuffer (low-endian os)
 */
function i2abLow(buf) {
  const uint8 = new Uint8Array(buf.length * 4);
  let i = 0;
  for (let j = 0; j < buf.length; j++) {
    const int = buf[j];
    uint8[i++] = int >>> 24;
    uint8[i++] = int >> 16 & 0xFF;
    uint8[i++] = int >> 8 & 0xFF;
    uint8[i++] = int & 0xFF;
  }
  return uint8.buffer;
}

/**
 * Uint32Array -> ArrayBuffer (big-endian os)
 */
function i2abBig(buf) {
  return buf.buffer;
}

/**
 * ArrayBuffer -> Uint32Array (low-endian os)
 */
function ab2iLow(ab) {
  const uint8 = new Uint8Array(ab);
  const buf = new Uint32Array(uint8.length / 4);
  for (let i = 0; i < uint8.length; i += 4) {
    buf[i / 4] = uint8[i] << 24 ^ uint8[i + 1] << 16 ^ uint8[i + 2] << 8 ^ uint8[i + 3];
  }
  return buf;
}

/**
 * ArrayBuffer -> Uint32Array (big-endian os)
 */
function ab2iBig(ab) {
  return new Uint32Array(ab);
}
const isBigEndian = new Uint8Array(new Uint32Array([0x01020304]))[0] === 0x01;
const i2ab = isBigEndian ? i2abBig : i2abLow;
const ab2i = isBigEndian ? ab2iBig : ab2iLow;

/***/ }),

/***/ "./src/lib/gramjs/crypto/crypto.ts":
/*!*****************************************!*\
  !*** ./src/lib/gramjs/crypto/crypto.ts ***!
  \*****************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   createCipheriv: () => (/* binding */ createCipheriv),
/* harmony export */   createDecipheriv: () => (/* binding */ createDecipheriv),
/* harmony export */   createHash: () => (/* binding */ createHash),
/* harmony export */   pbkdf2: () => (/* binding */ pbkdf2),
/* harmony export */   randomBytes: () => (/* binding */ randomBytes)
/* harmony export */ });
/* harmony import */ var _cryptography_aes__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @cryptography/aes */ "./node_modules/@cryptography/aes/dist/es/aes.js");
/* harmony import */ var _converters__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./converters */ "./src/lib/gramjs/crypto/converters.ts");
/* harmony import */ var _words__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./words */ "./src/lib/gramjs/crypto/words.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];



class Counter {
  constructor(initialValue) {
    this._counter = Buffer.from(initialValue);
  }
  increment() {
    for (let i = 15; i >= 0; i--) {
      if (this._counter[i] === 255) {
        this._counter[i] = 0;
      } else {
        this._counter[i]++;
        break;
      }
    }
  }
}
class CTR {
  constructor(key, counter) {
    if (!(counter instanceof Counter)) {
      counter = new Counter(counter);
    }
    this._counter = counter;
    this._remainingCounter = undefined;
    this._remainingCounterIndex = 16;
    this._aes = new _cryptography_aes__WEBPACK_IMPORTED_MODULE_0__["default"]((0,_words__WEBPACK_IMPORTED_MODULE_2__.getWords)(key));
  }
  update(plainText) {
    return this.encrypt(plainText);
  }
  encrypt(plainText) {
    const encrypted = Buffer.from(plainText);
    for (let i = 0; i < encrypted.length; i++) {
      if (this._remainingCounterIndex === 16) {
        this._remainingCounter = Buffer.from((0,_converters__WEBPACK_IMPORTED_MODULE_1__.i2ab)(this._aes.encrypt((0,_converters__WEBPACK_IMPORTED_MODULE_1__.ab2i)(this._counter._counter))));
        this._remainingCounterIndex = 0;
        this._counter.increment();
      }
      if (this._remainingCounter) {
        encrypted[i] ^= this._remainingCounter[this._remainingCounterIndex++];
      }
    }
    return encrypted;
  }
}
// endregion
function createDecipheriv(algorithm, key, iv) {
  if (algorithm.includes('ECB')) {
    throw new Error('Not supported');
  } else {
    return new CTR(key, iv);
  }
}
function createCipheriv(algorithm, key, iv) {
  if (algorithm.includes('ECB')) {
    throw new Error('Not supported');
  } else {
    return new CTR(key, iv);
  }
}
function randomBytes(count) {
  const bytes = new Uint8Array(count);
  crypto.getRandomValues(bytes);
  return bytes;
}
class Hash {
  data = new Uint8Array(0);
  constructor(algorithm) {
    this.algorithm = algorithm;
  }
  update(data) {
    // We shouldn't be needing new Uint8Array but it doesn't
    // work without it
    this.data = new Uint8Array(data);
  }
  async digest() {
    if (this.algorithm === 'sha1') {
      return Buffer.from(await self.crypto.subtle.digest('SHA-1', this.data));
    } else {
      return Buffer.from(await self.crypto.subtle.digest('SHA-256', this.data));
    }
  }
}
async function pbkdf2(password, salt, iterations) {
  const passwordKey = await crypto.subtle.importKey('raw', password, {
    name: 'PBKDF2'
  }, false, ['deriveBits']);
  return Buffer.from(await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    hash: 'SHA-512',
    salt,
    iterations
  }, passwordKey, 512));
}
function createHash(algorithm) {
  return new Hash(algorithm);
}

/***/ }),

/***/ "./src/lib/gramjs/crypto/words.ts":
/*!****************************************!*\
  !*** ./src/lib/gramjs/crypto/words.ts ***!
  \****************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getWords: () => (/* binding */ getWords),
/* harmony export */   s2i: () => (/* binding */ s2i),
/* harmony export */   xor: () => (/* binding */ xor)
/* harmony export */ });
/*
 * Imported from https://github.com/spalt08/cryptography/blob/master/packages/aes/src/utils/words.ts
 */

function s2i(str, pos) {
  return str.charCodeAt(pos) << 24 ^ str.charCodeAt(pos + 1) << 16 ^ str.charCodeAt(pos + 2) << 8 ^ str.charCodeAt(pos + 3);
}

/**
 * Helper function for transforming string key to Uint32Array
 */
function getWords(key) {
  if (key instanceof Uint32Array) {
    return key;
  }
  if (typeof key === 'string') {
    if (key.length % 4 !== 0) for (let i = key.length % 4; i <= 4; i++) key += '\0x00';
    const buf = new Uint32Array(key.length / 4);
    for (let i = 0; i < key.length; i += 4) buf[i / 4] = s2i(key, i);
    return buf;
  }
  if (key instanceof Uint8Array) {
    const buf = new Uint32Array(key.length / 4);
    for (let i = 0; i < key.length; i += 4) {
      buf[i / 4] = key[i] << 24 ^ key[i + 1] << 16 ^ key[i + 2] << 8 ^ key[i + 3];
    }
    return buf;
  }
  throw new Error('Unable to create 32-bit words');
}
function xor(left, right, to = left) {
  for (let i = 0; i < left.length; i++) to[i] = left[i] ^ right[i];
}

/***/ }),

/***/ "./src/lib/gramjs/errors/Common.ts":
/*!*****************************************!*\
  !*** ./src/lib/gramjs/errors/Common.ts ***!
  \*****************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   BadMessageError: () => (/* binding */ BadMessageError),
/* harmony export */   CdnFileTamperedError: () => (/* binding */ CdnFileTamperedError),
/* harmony export */   InvalidBufferError: () => (/* binding */ InvalidBufferError),
/* harmony export */   InvalidChecksumError: () => (/* binding */ InvalidChecksumError),
/* harmony export */   ReadCancelledError: () => (/* binding */ ReadCancelledError),
/* harmony export */   SecurityError: () => (/* binding */ SecurityError),
/* harmony export */   TypeNotFoundError: () => (/* binding */ TypeNotFoundError)
/* harmony export */ });
/**
 * Errors not related to the Telegram API itself
 */

/**
 * Occurs when a read operation was cancelled.
 */
class ReadCancelledError extends Error {
  constructor() {
    super('The read operation was cancelled.');
  }
}

/**
 * Occurs when a type is not found, for example,
 * when trying to read a TLObject with an invalid constructor code.
 */
class TypeNotFoundError extends Error {
  constructor(invalidConstructorId, remaining) {
    super(`Could not find a matching Constructor ID for the TLObject that was supposed to be
        read with ID ${invalidConstructorId}. Most likely, a TLObject was trying to be read when
         it should not be read. Remaining bytes: ${remaining.length}`);
    if (typeof alert !== 'undefined') {
      alert(`Missing MTProto Entity: Please, make sure to add TL definition for ID ${invalidConstructorId}`);
    }
    this.invalidConstructorId = invalidConstructorId;
    this.remaining = remaining;
  }
}

/**
 * Occurs when using the TCP full mode and the checksum of a received
 * packet doesn't match the expected checksum.
 */
class InvalidChecksumError extends Error {
  constructor(checksum, validChecksum) {
    super(`Invalid checksum (${checksum} when ${validChecksum} was expected). This packet should be skipped.`);
    this.checksum = checksum;
    this.validChecksum = validChecksum;
  }
}

/**
 * Occurs when the buffer is invalid, and may contain an HTTP error code.
 * For instance, 404 means "forgotten/broken authorization key", while
 */
class InvalidBufferError extends Error {
  constructor(payload) {
    let code;
    if (payload.length === 4) {
      code = -payload.readInt32LE(0);
      super(`Invalid response buffer (HTTP code ${code})`);
    } else {
      super(`Invalid response buffer (too short ${payload.toString()})`);
    }
    this.code = code;
    this.payload = payload;
  }
}

/**
 * Generic security error, mostly used when generating a new AuthKey.
 */
class SecurityError extends Error {
  constructor(...args) {
    if (!args.length) {
      args = ['A security check failed.'];
    }
    super(...args);
  }
}

/**
 * Occurs when there's a hash mismatch between the decrypted CDN file
 * and its expected hash.
 */
class CdnFileTamperedError extends SecurityError {
  constructor() {
    super('The CDN file has been altered and its download cancelled.');
  }
}

/**
 * Occurs when handling a badMessageNotification
 */
class BadMessageError extends Error {
  static ErrorMessages = {
    16: 'msg_id too low (most likely, client time is wrong it would be worthwhile to ' + 'synchronize it using msg_id notifications and re-send the original message ' + 'with the “correct” msg_id or wrap it in a container with a new msg_id if the ' + 'original message had waited too long on the client to be transmitted).',
    17: 'msg_id too high (similar to the previous case, the client time has to be ' + 'synchronized, and the message re-sent with the correct msg_id).',
    18: 'Incorrect two lower order msg_id bits (the server expects client message msg_id ' + 'to be divisible by 4).',
    19: 'Container msg_id is the same as msg_id of a previously received message (this must never happen).',
    20: 'Message too old, and it cannot be verified whether the server has received a ' + 'message with this msg_id or not.',
    32: 'msg_seqno too low (the server has already received a message with a lower ' + 'msg_id but with either a higher or an equal and odd seqno).',
    33: 'msg_seqno too high (similarly, there is a message with a higher msg_id but with ' + 'either a lower or an equal and odd seqno).',
    34: 'An even msg_seqno expected (irrelevant message), but odd received.',
    35: 'Odd msg_seqno expected (relevant message), but even received.',
    48: 'Incorrect server salt (in this case, the bad_server_salt response is received with ' + 'the correct salt, and the message is to be re-sent with it).',
    64: 'Invalid container.'
  };
  constructor(request, code) {
    let errorMessage = BadMessageError.ErrorMessages[code] || `Unknown error code (this should not happen): ${code}.`;
    errorMessage += `  Caused by ${request.className}`;
    super(errorMessage);
    this.errorMessage = errorMessage;
    this.code = code;
  }
}

// TODO : Support multi errors.

/***/ }),

/***/ "./src/lib/gramjs/errors/RPCBaseErrors.ts":
/*!************************************************!*\
  !*** ./src/lib/gramjs/errors/RPCBaseErrors.ts ***!
  \************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AuthKeyError: () => (/* binding */ AuthKeyError),
/* harmony export */   BadRequestError: () => (/* binding */ BadRequestError),
/* harmony export */   FloodError: () => (/* binding */ FloodError),
/* harmony export */   ForbiddenError: () => (/* binding */ ForbiddenError),
/* harmony export */   InvalidDCError: () => (/* binding */ InvalidDCError),
/* harmony export */   NotFoundError: () => (/* binding */ NotFoundError),
/* harmony export */   RPCError: () => (/* binding */ RPCError),
/* harmony export */   ServerError: () => (/* binding */ ServerError),
/* harmony export */   TimedOutError: () => (/* binding */ TimedOutError),
/* harmony export */   UnauthorizedError: () => (/* binding */ UnauthorizedError)
/* harmony export */ });
/**
 * Base class for all Remote Procedure Call errors.
 */
class RPCError extends Error {
  constructor(message, request, code) {
    super('RPCError {0}: {1}{2}'.replace('{0}', code?.toString() || '').replace('{1}', message).replace('{2}', RPCError._fmtRequest(request)));
    this.code = code;
    this.errorMessage = message;
  }
  static _fmtRequest(request) {
    // TODO fix this
    if (request) {
      return ` (caused by ${request.className})`;
    } else {
      return '';
    }
  }
}

/**
 * The request must be repeated, but directed to a different data center.
 */
class InvalidDCError extends RPCError {
  constructor(message, request, code) {
    super(message, request, code);
    this.code = code || 303;
    this.errorMessage = message || 'ERROR_SEE_OTHER';
  }
}

/**
 * The query contains errors. In the event that a request was created
 * using a form and contains user generated data, the user should be
 * notified that the data must be corrected before the query is repeated.
 */
class BadRequestError extends RPCError {
  code = 400;
  errorMessage = 'BAD_REQUEST';
}

/**
 * There was an unauthorized attempt to use functionality available only
 * to authorized users.
 */
class UnauthorizedError extends RPCError {
  code = 401;
  errorMessage = 'UNAUTHORIZED';
}

/**
 * Privacy violation. For example, an attempt to write a message to
 * someone who has blacklisted the current user.
 */
class ForbiddenError extends RPCError {
  code = 403;
  errorMessage = 'FORBIDDEN';
}

/**
 * An attempt to invoke a non-existent object, such as a method.
 */
class NotFoundError extends RPCError {
  code = 404;
  errorMessage = 'NOT_FOUND';
}

/**
 * Errors related to invalid authorization key, like
 * AUTH_KEY_DUPLICATED which can cause the connection to fail.
 */
class AuthKeyError extends RPCError {
  code = 406;
  errorMessage = 'AUTH_KEY';
}

/**
 * The maximum allowed number of attempts to invoke the given method
 * with the given input parameters has been exceeded. For example, in an
 * attempt to request a large number of text messages (SMS) for the same
 * phone number.
 */
class FloodError extends RPCError {
  code = 420;
  errorMessage = 'FLOOD';
}

/**
 * An internal server error occurred while a request was being processed
 * for example, there was a disruption while accessing a database or file
 * storage
 */
class ServerError extends RPCError {
  code = 500; // Also witnessed as -500

  errorMessage = 'INTERNAL';
}

/**
 * Clicking the inline buttons of bots that never (or take to long to)
 * call ``answerCallbackQuery`` will result in this "special" RPCError.
 */
class TimedOutError extends RPCError {
  code = 503; // Only witnessed as -503

  errorMessage = 'Timeout';
}

/***/ }),

/***/ "./src/lib/gramjs/errors/RPCErrorList.ts":
/*!***********************************************!*\
  !*** ./src/lib/gramjs/errors/RPCErrorList.ts ***!
  \***********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   EmailUnconfirmedError: () => (/* binding */ EmailUnconfirmedError),
/* harmony export */   FileMigrateError: () => (/* binding */ FileMigrateError),
/* harmony export */   FloodPremiumWaitError: () => (/* binding */ FloodPremiumWaitError),
/* harmony export */   FloodTestPhoneWaitError: () => (/* binding */ FloodTestPhoneWaitError),
/* harmony export */   FloodWaitError: () => (/* binding */ FloodWaitError),
/* harmony export */   MsgWaitError: () => (/* binding */ MsgWaitError),
/* harmony export */   NetworkMigrateError: () => (/* binding */ NetworkMigrateError),
/* harmony export */   PasswordFreshError: () => (/* binding */ PasswordFreshError),
/* harmony export */   PhoneMigrateError: () => (/* binding */ PhoneMigrateError),
/* harmony export */   SlowModeWaitError: () => (/* binding */ SlowModeWaitError),
/* harmony export */   UserMigrateError: () => (/* binding */ UserMigrateError),
/* harmony export */   rpcErrorRe: () => (/* binding */ rpcErrorRe)
/* harmony export */ });
/* harmony import */ var _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./RPCBaseErrors */ "./src/lib/gramjs/errors/RPCBaseErrors.ts");
/* eslint-disable @stylistic/max-len */

class UserMigrateError extends _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.InvalidDCError {
  constructor(args) {
    const newDc = Number(args.capture || 0);
    super(`The user whose identity is being used to execute queries is associated with DC ${newDc}${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`, args.request);
    this.message = `The user whose identity is being used to execute queries is associated with DC ${newDc}${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`;
    this.newDc = newDc;
  }
}
class PhoneMigrateError extends _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.InvalidDCError {
  constructor(args) {
    const newDc = Number(args.capture || 0);
    super(`The phone number a user is trying to use for authorization is associated with DC ${newDc}${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`, args.request);
    this.message = `The phone number a user is trying to use for authorization is associated with DC ${newDc}${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`;
    this.newDc = newDc;
  }
}
class SlowModeWaitError extends _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.FloodError {
  constructor(args) {
    const seconds = Number(args.capture || 0);
    super(`A wait of ${seconds} seconds is required before sending another message in this chat ${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`, args.request);
    this.message = `A wait of ${seconds} seconds is required before sending another message in this chat${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`;
    this.seconds = seconds;
  }
}
class FloodWaitError extends _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.FloodError {
  constructor(args) {
    const seconds = Number(args.capture || 0);
    super(`A wait of ${seconds} seconds is required${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`, args.request);
    this.message = `A wait of ${seconds} seconds is required${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`;
    this.seconds = seconds;
  }
}
class FloodPremiumWaitError extends FloodWaitError {
  constructor(args) {
    const seconds = Number(args.capture || 0);
    super(`A wait of ${seconds} seconds is required${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`);
    this.message = `A wait of ${seconds} seconds is required${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`;
    this.seconds = seconds;
  }
}
class MsgWaitError extends _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.FloodError {
  constructor(args) {
    super(`Message failed to be sent.${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`, args.request);
    this.message = `Message failed to be sent.${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`;
  }
}
class FloodTestPhoneWaitError extends _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.FloodError {
  constructor(args) {
    const seconds = Number(args.capture || 0);
    super(`A wait of ${seconds} seconds is required in the test servers${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`, args.request);
    this.message = `A wait of ${seconds} seconds is required in the test servers${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`;
    this.seconds = seconds;
  }
}
class FileMigrateError extends _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.InvalidDCError {
  constructor(args) {
    const newDc = Number(args.capture || 0);
    super(`The file to be accessed is currently stored in DC ${newDc}${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`, args.request);
    this.message = `The file to be accessed is currently stored in DC ${newDc}${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`;
    this.newDc = newDc;
  }
}
class NetworkMigrateError extends _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.InvalidDCError {
  constructor(args) {
    const newDc = Number(args.capture || 0);
    super(`The source IP address is associated with DC ${newDc}${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`, args.request);
    this.message = `The source IP address is associated with DC ${newDc}${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`;
    this.newDc = newDc;
  }
}
class EmailUnconfirmedError extends _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.BadRequestError {
  constructor(args) {
    const codeLength = Number(args.capture || 0);
    super(`Email unconfirmed, the length of the code must be ${codeLength}${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`, args.request, 400);
    this.message = `Email unconfirmed, the length of the code must be ${codeLength}${_RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError._fmtRequest(args.request)}`;
    this.codeLength = codeLength;
  }
}
class PasswordFreshError extends _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.BadRequestError {
  constructor(args) {
    const seconds = Number(args.capture || 0);
    super(`The password was modified less than 24 hours ago, try again in ${seconds} seconds.`, args.request);
    this.message = `The password was modified less than 24 hours ago, try again in ${seconds} seconds.`;
    this.seconds = seconds;
  }
}
const rpcErrorRe = new Map([[/FILE_MIGRATE_(\d+)/, FileMigrateError], [/FLOOD_TEST_PHONE_WAIT_(\d+)/, FloodTestPhoneWaitError], [/FLOOD_WAIT_(\d+)/, FloodWaitError], [/FLOOD_PREMIUM_WAIT_(\d+)/, FloodPremiumWaitError], [/MSG_WAIT_(.*)/, MsgWaitError], [/PHONE_MIGRATE_(\d+)/, PhoneMigrateError], [/SLOWMODE_WAIT_(\d+)/, SlowModeWaitError], [/USER_MIGRATE_(\d+)/, UserMigrateError], [/NETWORK_MIGRATE_(\d+)/, NetworkMigrateError], [/EMAIL_UNCONFIRMED_(\d+)/, EmailUnconfirmedError], [/PASSWORD_TOO_FRESH_(\d+)/, PasswordFreshError], [/^Timeout$/, _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.TimedOutError]]);

/***/ }),

/***/ "./src/lib/gramjs/errors/index.ts":
/*!****************************************!*\
  !*** ./src/lib/gramjs/errors/index.ts ***!
  \****************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AuthKeyError: () => (/* reexport safe */ _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.AuthKeyError),
/* harmony export */   BadMessageError: () => (/* reexport safe */ _Common__WEBPACK_IMPORTED_MODULE_2__.BadMessageError),
/* harmony export */   BadRequestError: () => (/* reexport safe */ _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.BadRequestError),
/* harmony export */   CdnFileTamperedError: () => (/* reexport safe */ _Common__WEBPACK_IMPORTED_MODULE_2__.CdnFileTamperedError),
/* harmony export */   EmailUnconfirmedError: () => (/* reexport safe */ _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__.EmailUnconfirmedError),
/* harmony export */   FileMigrateError: () => (/* reexport safe */ _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__.FileMigrateError),
/* harmony export */   FloodError: () => (/* reexport safe */ _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.FloodError),
/* harmony export */   FloodPremiumWaitError: () => (/* reexport safe */ _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__.FloodPremiumWaitError),
/* harmony export */   FloodTestPhoneWaitError: () => (/* reexport safe */ _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__.FloodTestPhoneWaitError),
/* harmony export */   FloodWaitError: () => (/* reexport safe */ _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__.FloodWaitError),
/* harmony export */   ForbiddenError: () => (/* reexport safe */ _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.ForbiddenError),
/* harmony export */   InvalidBufferError: () => (/* reexport safe */ _Common__WEBPACK_IMPORTED_MODULE_2__.InvalidBufferError),
/* harmony export */   InvalidChecksumError: () => (/* reexport safe */ _Common__WEBPACK_IMPORTED_MODULE_2__.InvalidChecksumError),
/* harmony export */   InvalidDCError: () => (/* reexport safe */ _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.InvalidDCError),
/* harmony export */   MsgWaitError: () => (/* reexport safe */ _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__.MsgWaitError),
/* harmony export */   NetworkMigrateError: () => (/* reexport safe */ _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__.NetworkMigrateError),
/* harmony export */   NotFoundError: () => (/* reexport safe */ _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.NotFoundError),
/* harmony export */   PasswordFreshError: () => (/* reexport safe */ _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__.PasswordFreshError),
/* harmony export */   PhoneMigrateError: () => (/* reexport safe */ _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__.PhoneMigrateError),
/* harmony export */   RPCError: () => (/* reexport safe */ _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError),
/* harmony export */   RPCMessageToError: () => (/* binding */ RPCMessageToError),
/* harmony export */   ReadCancelledError: () => (/* reexport safe */ _Common__WEBPACK_IMPORTED_MODULE_2__.ReadCancelledError),
/* harmony export */   SecurityError: () => (/* reexport safe */ _Common__WEBPACK_IMPORTED_MODULE_2__.SecurityError),
/* harmony export */   ServerError: () => (/* reexport safe */ _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.ServerError),
/* harmony export */   SlowModeWaitError: () => (/* reexport safe */ _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__.SlowModeWaitError),
/* harmony export */   TimedOutError: () => (/* reexport safe */ _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.TimedOutError),
/* harmony export */   TypeNotFoundError: () => (/* reexport safe */ _Common__WEBPACK_IMPORTED_MODULE_2__.TypeNotFoundError),
/* harmony export */   UnauthorizedError: () => (/* reexport safe */ _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.UnauthorizedError),
/* harmony export */   UserMigrateError: () => (/* reexport safe */ _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__.UserMigrateError),
/* harmony export */   rpcErrorRe: () => (/* reexport safe */ _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__.rpcErrorRe)
/* harmony export */ });
/* harmony import */ var _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./RPCBaseErrors */ "./src/lib/gramjs/errors/RPCBaseErrors.ts");
/* harmony import */ var _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./RPCErrorList */ "./src/lib/gramjs/errors/RPCErrorList.ts");
/* harmony import */ var _Common__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./Common */ "./src/lib/gramjs/errors/Common.ts");
/**
 * Converts a Telegram's RPC Error to a Python error.
 * @param rpcError the RPCError instance
 * @param request the request that caused this error
 * @constructor the RPCError as a Python exception that represents this error
 */



function RPCMessageToError(rpcError, request) {
  for (const [msgRegex, Cls] of _RPCErrorList__WEBPACK_IMPORTED_MODULE_1__.rpcErrorRe) {
    const m = rpcError.errorMessage.match(msgRegex);
    if (m) {
      const capture = m.length === 2 ? parseInt(m[1], 10) : undefined;
      return new Cls({
        request,
        capture
      });
    }
  }
  return new _RPCBaseErrors__WEBPACK_IMPORTED_MODULE_0__.RPCError(rpcError.errorMessage, request, rpcError.errorCode);
}




/***/ }),

/***/ "./src/lib/gramjs/extensions/AsyncQueue.ts":
/*!*************************************************!*\
  !*** ./src/lib/gramjs/extensions/AsyncQueue.ts ***!
  \*************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ AsyncQueue)
/* harmony export */ });
class AsyncQueue {
  constructor() {
    this._queue = [];
    this.resolvePush = () => {};
    this.resolveGet = () => {};
    this.canGet = new Promise(resolve => {
      this.resolveGet = resolve;
    });
    this.canPush = true;
  }
  async push(value) {
    await this.canPush;
    this._queue.push(value);
    this.resolveGet(true);
    this.canPush = new Promise(resolve => {
      this.resolvePush = resolve;
    });
  }
  async pop() {
    await this.canGet;
    const returned = this._queue.pop();
    this.resolvePush(true);
    this.canGet = new Promise(resolve => {
      this.resolveGet = resolve;
    });
    return returned;
  }
}

/***/ }),

/***/ "./src/lib/gramjs/extensions/BinaryReader.ts":
/*!***************************************************!*\
  !*** ./src/lib/gramjs/extensions/BinaryReader.ts ***!
  \***************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ BinaryReader)
/* harmony export */ });
/* harmony import */ var _errors__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../errors */ "./src/lib/gramjs/errors/index.ts");
/* harmony import */ var _tl_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../tl/core */ "./src/lib/gramjs/tl/core/index.ts");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* harmony import */ var _tl_AllTLObjects__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../tl/AllTLObjects */ "./src/lib/gramjs/tl/AllTLObjects.ts");




class BinaryReader {
  /**
     * Small utility class to read binary data.
     * @param data {Buffer}
     */
  constructor(data) {
    this.stream = data;
    this._last = undefined;
    this.offset = 0;
  }

  // region Reading

  // "All numbers are written as little endian."
  // https://core.telegram.org/mtproto
  /**
     * Reads a single byte value.
     */
  readByte() {
    return this.read(1)[0];
  }

  /**
     * Reads an integer (4 bytes or 32 bits) value.
     * @param signed {Boolean}
     */
  readInt(signed = true) {
    let res;
    if (signed) {
      res = this.stream.readInt32LE(this.offset);
    } else {
      res = this.stream.readUInt32LE(this.offset);
    }
    this.offset += 4;
    return res;
  }

  /**
     * Reads a long integer (8 bytes or 64 bits) value.
     * @param signed
     * @returns {BigInteger}
     */
  readLong(signed = true) {
    return this.readLargeInt(64, signed);
  }

  /**
     * Reads a real floating point (4 bytes) value.
     * @returns {number}
     */
  readFloat() {
    return this.read(4).readFloatLE(0);
  }

  /**
     * Reads a real floating point (8 bytes) value.
     * @returns {BigInteger}
     */
  readDouble() {
    // was this a bug ? it should have been <d
    return this.read(8).readDoubleLE(0);
  }

  /**
     * Reads a n-bits long integer value.
     * @param bits
     * @param signed {Boolean}
     */
  readLargeInt(bits, signed = true) {
    const buffer = this.read(Math.floor(bits / 8));
    return (0,_Helpers__WEBPACK_IMPORTED_MODULE_2__.readBigIntFromBuffer)(buffer, true, signed);
  }

  /**
     * Read the given amount of bytes, or -1 to read all remaining.
     * @param length {number}
     * @param checkLength {boolean} whether to check if the length overflows or not.
     */
  read(length = -1) {
    if (length === -1) {
      length = this.stream.length - this.offset;
    }
    const result = this.stream.slice(this.offset, this.offset + length);
    this.offset += length;
    if (result.length !== length) {
      throw Error(
      // eslint-disable-next-line @stylistic/max-len
      `No more data left to read (need ${length}, got ${result.length}: ${result.toString()}); last read ${this._last?.toString()}`);
    }
    this._last = result;
    return result;
  }

  /**
     * Gets the byte array representing the current buffer as a whole.
     * @returns {Buffer}
     */
  getBuffer() {
    return this.stream;
  }

  // endregion

  // region Telegram custom reading
  /**
     * Reads a Telegram-encoded byte array, without the need of
     * specifying its length.
     * @returns {Buffer}
     */
  tgReadBytes() {
    const firstByte = this.readByte();
    let padding;
    let length;
    if (firstByte === 254) {
      length = this.readByte() | this.readByte() << 8 | this.readByte() << 16;
      padding = length % 4;
    } else {
      length = firstByte;
      padding = (length + 1) % 4;
    }
    const data = this.read(length);
    if (padding > 0) {
      padding = 4 - padding;
      this.read(padding);
    }
    return data;
  }

  /**
     * Reads a Telegram-encoded string.
     * @returns {string}
     */
  tgReadString() {
    return this.tgReadBytes().toString('utf-8');
  }

  /**
     * Reads a Telegram boolean value.
     * @returns {boolean}
     */
  tgReadBool() {
    const value = this.readInt(false);
    if (value === 0x997275b5) {
      // boolTrue
      return true;
    } else if (value === 0xbc799737) {
      // boolFalse
      return false;
    } else {
      throw new Error(`Invalid boolean code ${value.toString(16)}`);
    }
  }

  /**
     * Reads and converts Unix time (used by Telegram)
     * into a Javascript {Date} object.
     * @returns {Date}
     */
  tgReadDate() {
    const value = this.readInt();
    return new Date(value * 1000);
  }

  /**
     * Reads a Telegram object.
     */
  tgReadObject() {
    const constructorId = this.readInt(false);
    let clazz = _tl_AllTLObjects__WEBPACK_IMPORTED_MODULE_3__.tlobjects[constructorId];
    if (clazz === undefined) {
      /**
             * The class was undefined, but there's still a
             * chance of it being a manually parsed value like bool!
             */
      const value = constructorId;
      if (value === 0x997275b5) {
        // boolTrue
        return true;
      } else if (value === 0xbc799737) {
        // boolFalse
        return false;
      } else if (value === 0x1cb5c415) {
        // Vector
        const temp = [];
        const length = this.readInt();
        for (let i = 0; i < length; i++) {
          temp.push(this.tgReadObject());
        }
        return temp;
      }
      clazz = _tl_core__WEBPACK_IMPORTED_MODULE_1__.coreObjects.get(constructorId);
      if (clazz === undefined) {
        // If there was still no luck, give up
        this.seek(-4); // Go back
        const pos = this.tellPosition();
        const error = new _errors__WEBPACK_IMPORTED_MODULE_0__.TypeNotFoundError(constructorId, this.read());
        this.setPosition(pos);
        throw error;
      }
    }
    return clazz.fromReader(this);
  }

  /**
     * Reads a vector (a list) of Telegram objects.
     * @returns {[Buffer]}
     */
  tgReadVector() {
    if (this.readInt(false) !== 0x1cb5c415) {
      throw new Error('Invalid constructor code, vector was expected');
    }
    const count = this.readInt();
    const temp = [];
    for (let i = 0; i < count; i++) {
      temp.push(this.tgReadObject());
    }
    return temp;
  }

  // endregion

  // region Position related

  /**
     * Tells the current position on the stream.
     * @returns {number}
     */
  tellPosition() {
    return this.offset;
  }

  /**
     * Sets the current position on the stream.
     * @param position
     */
  setPosition(position) {
    this.offset = position;
  }

  /**
     * Seeks the stream position given an offset from the current position.
     * The offset may be negative.
     * @param offset
     */
  seek(offset) {
    this.offset += offset;
  }

  // endregion
}

/***/ }),

/***/ "./src/lib/gramjs/extensions/BinaryWriter.ts":
/*!***************************************************!*\
  !*** ./src/lib/gramjs/extensions/BinaryWriter.ts ***!
  \***************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ BinaryWriter)
/* harmony export */ });
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];
class BinaryWriter {
  constructor(stream) {
    this._buffers = [stream];
  }
  write(buffer) {
    this._buffers.push(buffer);
  }
  getValue() {
    return Buffer.concat(this._buffers);
  }
}

/***/ }),

/***/ "./src/lib/gramjs/extensions/HttpStream.ts":
/*!*************************************************!*\
  !*** ./src/lib/gramjs/extensions/HttpStream.ts ***!
  \*************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ HttpStream)
/* harmony export */ });
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];
const closeError = new Error('HttpStream was closed');
const REQUEST_TIMEOUT = 10000;
AbortSignal.timeout ??= function timeout(ms) {
  const ctrl = new AbortController();
  setTimeout(() => ctrl.abort(), ms);
  return ctrl.signal;
};
class HttpStream {
  stream = [];
  canRead = Promise.resolve();
  constructor(disconnectedCallback) {
    this.isClosed = true;
    this.disconnectedCallback = disconnectedCallback;
  }
  async readExactly(number) {
    let readData = Buffer.alloc(0);
    while (true) {
      const thisTime = await this.read();
      readData = Buffer.concat([readData, thisTime]);
      number -= thisTime.length;
      if (number <= 0) {
        return readData;
      }
    }
  }
  async read() {
    await this.canRead;
    const data = this.stream.shift();
    if (this.stream.length === 0) {
      this.canRead = new Promise((resolve, reject) => {
        this.resolveRead = resolve;
        this.rejectRead = reject;
      });
    }
    return data;
  }
  static getURL(ip, port, isTestServer, isPremium) {
    if (port === 443) {
      return `https://${ip}:${port}/apiw1${isTestServer ? '_test' : ''}${isPremium ? '_premium' : ''}`;
    } else {
      return `http://${ip}:${port}/apiw1${isTestServer ? '_test' : ''}${isPremium ? '_premium' : ''}`;
    }
  }
  async connect(port, ip, isTestServer = false, isPremium = false) {
    this.stream = [];
    this.canRead = new Promise((resolve, reject) => {
      this.resolveRead = resolve;
      this.rejectRead = reject;
    });
    this.url = HttpStream.getURL(ip, port, isTestServer, isPremium);
    await fetch(this.url, {
      method: 'POST',
      body: Buffer.from([]),
      mode: 'cors',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT)
    });
    this.isClosed = false;
  }
  write(data) {
    if (this.isClosed || !this.url) {
      this.handleDisconnect();
      throw closeError;
    }
    return fetch(this.url, {
      method: 'POST',
      body: data,
      mode: 'cors',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT)
    }).then(async response => {
      if (this.isClosed) {
        this.handleDisconnect();
        return;
      }
      if (response.status !== 200) {
        throw closeError;
      }
      const arrayBuffer = await response.arrayBuffer();
      this.stream = this.stream.concat(Buffer.from(arrayBuffer));
      if (this.resolveRead && !this.isClosed) this.resolveRead();
    }).catch(err => {
      this.handleDisconnect();
      throw err;
    });
  }
  handleDisconnect() {
    this.disconnectedCallback?.();
    if (this.rejectRead) this.rejectRead();
  }
  close() {
    this.isClosed = true;
    this.handleDisconnect();
    this.disconnectedCallback = undefined;
  }
}

/***/ }),

/***/ "./src/lib/gramjs/extensions/Logger.ts":
/*!*********************************************!*\
  !*** ./src/lib/gramjs/extensions/Logger.ts ***!
  \*********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ Logger)
/* harmony export */ });
let _level;
class Logger {
  static LEVEL_MAP = new Map([['error', new Set(['error'])], ['warn', new Set(['error', 'warn'])], ['info', new Set(['error', 'warn', 'info'])], ['debug', new Set(['error', 'warn', 'info', 'debug'])]]);
  constructor(level) {
    if (!_level) {
      _level = level || 'debug';
    }
    this.colors = {
      start: '%c',
      warn: 'color : #ff00ff',
      info: 'color : #ffff00',
      debug: 'color : #00ffff',
      error: 'color : #ff0000',
      end: ''
    };
    this.messageFormat = '[%t] [%l] - [%m]';
  }
  static setLevel(level) {
    _level = level;
  }
  canSend(level) {
    if (!_level) return false;
    return Logger.LEVEL_MAP.get(_level).has(level);
  }
  warn(message) {
    this._log('warn', message, this.colors.warn);
  }
  info(message) {
    this._log('info', message, this.colors.info);
  }
  debug(message) {
    this._log('debug', message, this.colors.debug);
  }
  error(message) {
    this._log('error', message, this.colors.error);
  }
  format(message, level) {
    return this.messageFormat.replace('%t', new Date().toISOString()).replace('%l', level.toUpperCase()).replace('%m', message);
  }
  _log(level, message, color) {
    if (!_level) {
      return;
    }
    if (this.canSend(level)) {
      // eslint-disable-next-line no-console
      console.log(this.colors.start + this.format(message, level), color);
    }
  }
}

/***/ }),

/***/ "./src/lib/gramjs/extensions/MessagePacker.ts":
/*!****************************************************!*\
  !*** ./src/lib/gramjs/extensions/MessagePacker.ts ***!
  \****************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ MessagePacker)
/* harmony export */ });
/* harmony import */ var _tl_core_TLMessage__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../tl/core/TLMessage */ "./src/lib/gramjs/tl/core/TLMessage.ts");
/* harmony import */ var _tl_core_MessageContainer__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../tl/core/MessageContainer */ "./src/lib/gramjs/tl/core/MessageContainer.ts");
/* harmony import */ var _BinaryWriter__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./BinaryWriter */ "./src/lib/gramjs/extensions/BinaryWriter.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];



const USE_INVOKE_AFTER_WITH = new Set(['messages.SendMessage', 'messages.SendMedia', 'messages.SendMultiMedia', 'messages.ForwardMessages', 'messages.SendInlineBotResult']);
class MessagePacker {
  constructor(state, logger) {
    this._state = state;
    this._queue = [];
    this._pendingStates = [];
    this._ready = new Promise(resolve => {
      this.setReady = resolve;
    });
    this._log = logger;
  }
  values() {
    return this._queue;
  }
  clear() {
    this._queue = [];
    this.append(undefined);
  }
  append(state, setReady = true, atStart = false) {
    // We need to check if there is already a `USE_INVOKE_AFTER_WITH` request
    if (state && USE_INVOKE_AFTER_WITH.has(state.request.className)) {
      if (atStart) {
        // Assign `after` for the previously first `USE_INVOKE_AFTER_WITH` request
        for (let i = 0; i < this._queue.length; i++) {
          if (USE_INVOKE_AFTER_WITH.has(this._queue[i]?.request.className)) {
            this._queue[i].after = state;
            break;
          }
        }
      } else {
        // Assign after for the previous `USE_INVOKE_AFTER_WITH` request
        for (let i = this._queue.length - 1; i >= 0; i--) {
          if (USE_INVOKE_AFTER_WITH.has(this._queue[i]?.request.className)) {
            state.after = this._queue[i];
            break;
          }
        }
      }
    }
    if (atStart) {
      this._queue.unshift(state);
    } else {
      this._queue.push(state);
    }
    if (setReady) {
      this.setReady?.(true);
    }

    // 1658238041=MsgsAck, we don't care about MsgsAck here because they never resolve anyway.
    if (state && state.request.CONSTRUCTOR_ID !== 1658238041) {
      this._pendingStates.push(state);
      state.promise
      // Using finally causes triggering `unhandledrejection` event
      ?.catch(() => {}).finally(() => {
        this._pendingStates = this._pendingStates.filter(s => s !== state);
      });
    }
  }
  prepend(states) {
    states.reverse().forEach(state => {
      this.append(state, false, true);
    });
    this.setReady?.(true);
  }
  extend(states) {
    states.forEach(state => {
      this.append(state, false);
    });
    this.setReady?.(true);
  }
  async getBeacon(state) {
    const buffer = new _BinaryWriter__WEBPACK_IMPORTED_MODULE_2__["default"](Buffer.alloc(0));
    const size = state.data.length + _tl_core_TLMessage__WEBPACK_IMPORTED_MODULE_0__["default"].SIZE_OVERHEAD;
    if (size <= _tl_core_MessageContainer__WEBPACK_IMPORTED_MODULE_1__["default"].MAXIMUM_SIZE) {
      let afterId;
      if (state.after) {
        afterId = state.after.msgId;
      }
      state.msgId = await this._state.writeDataAsMessage(buffer, state.data, state.request.classType === 'request', afterId);
      this._log.debug(`Assigned msgId = ${state.msgId.toString()} to ${state.request.className || state.request.constructor.name}`);
      return buffer.getValue();
    }
    this._log.warn(`Message payload for ${state.request.className || state.request.constructor.name} is too long ${state.data.length} and cannot be sent`);
    state.reject?.(new Error('Request Payload is too big'));
    return undefined;
  }
  async wait() {
    if (!this._queue.length) {
      this._ready = new Promise(resolve => {
        this.setReady = resolve;
      });
      await this._ready;
    }
  }
  async get() {
    if (!this._queue[this._queue.length - 1]) {
      this._queue = this._queue.filter(Boolean);
      return undefined;
    }
    let data;
    let buffer = new _BinaryWriter__WEBPACK_IMPORTED_MODULE_2__["default"](Buffer.alloc(0));
    const batch = [];
    let size = 0;
    while (this._queue.length && batch.length <= _tl_core_MessageContainer__WEBPACK_IMPORTED_MODULE_1__["default"].MAXIMUM_LENGTH) {
      const state = this._queue.shift();
      if (!state) {
        continue;
      }
      if (state.abortSignal?.aborted) {
        state.reject?.(new Error('Request aborted'));
        continue;
      }
      size += state.data.length + _tl_core_TLMessage__WEBPACK_IMPORTED_MODULE_0__["default"].SIZE_OVERHEAD;
      if (size <= _tl_core_MessageContainer__WEBPACK_IMPORTED_MODULE_1__["default"].MAXIMUM_SIZE) {
        let afterId;
        if (state.after) {
          afterId = state.after.msgId;
        }
        state.msgId = await this._state.writeDataAsMessage(buffer, state.data, state.request.classType === 'request', afterId);
        this._log.debug(`Assigned msgId = ${state.msgId.toString()} to ${state.request.className || state.request.constructor.name}`);
        batch.push(state);
        continue;
      }
      if (batch.length) {
        this._queue.unshift(state);
        break;
      }
      this._log.warn(`Message payload for ${state.request.className || state.request.constructor.name} is too long ${state.data.length} and cannot be sent`);
      state.reject?.(new Error('Request Payload is too big'));
      size = 0;
    }
    if (!batch.length) {
      return undefined;
    }
    if (batch.length > 1) {
      const b = Buffer.alloc(8);
      b.writeUInt32LE(_tl_core_MessageContainer__WEBPACK_IMPORTED_MODULE_1__["default"].CONSTRUCTOR_ID, 0);
      b.writeInt32LE(batch.length, 4);
      data = Buffer.concat([b, buffer.getValue()]);
      buffer = new _BinaryWriter__WEBPACK_IMPORTED_MODULE_2__["default"](Buffer.alloc(0));
      const containerId = await this._state.writeDataAsMessage(buffer, data, false);
      for (const s of batch) {
        s.containerId = containerId;
      }
    }
    data = buffer.getValue();
    return {
      batch,
      data
    };
  }
}

/***/ }),

/***/ "./src/lib/gramjs/extensions/PendingState.ts":
/*!***************************************************!*\
  !*** ./src/lib/gramjs/extensions/PendingState.ts ***!
  \***************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ PendingState)
/* harmony export */ });
class PendingState {
  constructor() {
    this._pending = new Map();
  }
  set(msgId, state) {
    this._pending.set(msgId.toString(), state);
  }
  get(msgId) {
    return this._pending.get(msgId.toString());
  }
  getAndDelete(msgId) {
    const state = this.get(msgId);
    this.delete(msgId);
    return state;
  }
  values() {
    return Array.from(this._pending.values());
  }
  delete(msgId) {
    this._pending.delete(msgId.toString());
  }
  clear() {
    this._pending.clear();
  }
}

/***/ }),

/***/ "./src/lib/gramjs/extensions/PromisedWebSockets.ts":
/*!*********************************************************!*\
  !*** ./src/lib/gramjs/extensions/PromisedWebSockets.ts ***!
  \*********************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ PromisedWebSockets)
/* harmony export */ });
/* harmony import */ var async_mutex__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! async-mutex */ "./node_modules/async-mutex/index.mjs");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];

const mutex = new async_mutex__WEBPACK_IMPORTED_MODULE_0__.Mutex();
const closeError = new Error('WebSocket was closed');
const CONNECTION_TIMEOUT = 3000;
const MAX_TIMEOUT = 30000;
class PromisedWebSockets {
  constructor(disconnectedCallback) {
    this.client = undefined;
    this.closed = true;
    this.stream = Buffer.alloc(0);
    this.disconnectedCallback = disconnectedCallback;
    this.timeout = CONNECTION_TIMEOUT;
  }
  async readExactly(number) {
    let readData = Buffer.alloc(0);
    while (true) {
      const thisTime = await this.read(number);
      readData = Buffer.concat([readData, thisTime]);
      number -= thisTime.length;
      if (!number) {
        return readData;
      }
    }
  }
  async read(number) {
    if (this.closed) {
      throw closeError;
    }
    await this.canRead;
    if (this.closed) {
      throw closeError;
    }
    const toReturn = this.stream.slice(0, number);
    this.stream = this.stream.slice(number);
    if (this.stream.length === 0) {
      this.canRead = new Promise(resolve => {
        this.resolveRead = resolve;
      });
    }
    return toReturn;
  }
  async readAll() {
    if (this.closed || !(await this.canRead)) {
      throw closeError;
    }
    const toReturn = this.stream;
    this.stream = Buffer.alloc(0);
    this.canRead = new Promise(resolve => {
      this.resolveRead = resolve;
    });
    return toReturn;
  }
  getWebSocketLink(ip, port, isTestServer, isPremium) {
    if (port === 443) {
      return `wss://${ip}:${port}/apiws${isTestServer ? '_test' : ''}${isPremium ? '_premium' : ''}`;
    } else {
      return `ws://${ip}:${port}/apiws${isTestServer ? '_test' : ''}${isPremium ? '_premium' : ''}`;
    }
  }
  connect(port, ip, isTestServer = false, isPremium = false) {
    this.stream = Buffer.alloc(0);
    this.canRead = new Promise(resolve => {
      this.resolveRead = resolve;
    });
    this.closed = false;
    this.website = this.getWebSocketLink(ip, port, isTestServer, isPremium);
    this.client = new WebSocket(this.website, 'binary');
    return new Promise((resolve, reject) => {
      if (!this.client) return;
      let hasResolved = false;
      let timeout;
      this.client.onopen = () => {
        this.receive();
        resolve(this);
        hasResolved = true;
        if (timeout) clearTimeout(timeout);
      };
      this.client.onerror = error => {
        // eslint-disable-next-line no-console
        console.error('WebSocket error', error);
        reject(error);
        hasResolved = true;
        if (timeout) clearTimeout(timeout);
      };
      this.client.onclose = event => {
        const {
          code,
          reason,
          wasClean
        } = event;
        if (code !== 1000) {
          // eslint-disable-next-line no-console
          console.error(`Socket ${ip} closed. Code: ${code}, reason: ${reason}, was clean: ${wasClean}`);
        }
        this.resolveRead?.(false);
        this.closed = true;
        if (this.disconnectedCallback) {
          this.disconnectedCallback();
        }
        hasResolved = true;
        if (timeout) clearTimeout(timeout);
      };
      timeout = setTimeout(() => {
        if (hasResolved) return;
        reject(new Error('WebSocket connection timeout'));
        this.resolveRead?.(false);
        this.closed = true;
        if (this.disconnectedCallback) {
          this.disconnectedCallback();
        }
        this.client?.close();
        this.timeout *= 2;
        this.timeout = Math.min(this.timeout, MAX_TIMEOUT);
        timeout = undefined;
      }, this.timeout);

      // CONTEST
      // Seems to not be working, at least in a web worker

      self.addEventListener('offline', () => {
        this.close();
        this.resolveRead?.(false);
      });
    });
  }
  write(data) {
    if (this.closed) {
      throw closeError;
    }
    this.client?.send(data);
  }
  close() {
    this.client?.close();
    this.closed = true;
  }
  receive() {
    if (!this.client) return;
    this.client.onmessage = async message => {
      await mutex.runExclusive(async () => {
        const data = message.data instanceof ArrayBuffer ? Buffer.from(message.data) : Buffer.from(await new Response(message.data).arrayBuffer());
        this.stream = Buffer.concat([this.stream, data]);
        this.resolveRead?.(true);
      });
    };
  }
}

/***/ }),

/***/ "./src/lib/gramjs/extensions/index.ts":
/*!********************************************!*\
  !*** ./src/lib/gramjs/extensions/index.ts ***!
  \********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AsyncQueue: () => (/* reexport safe */ _AsyncQueue__WEBPACK_IMPORTED_MODULE_0__["default"]),
/* harmony export */   BinaryReader: () => (/* reexport safe */ _BinaryReader__WEBPACK_IMPORTED_MODULE_1__["default"]),
/* harmony export */   BinaryWriter: () => (/* reexport safe */ _BinaryWriter__WEBPACK_IMPORTED_MODULE_2__["default"]),
/* harmony export */   HttpStream: () => (/* reexport safe */ _HttpStream__WEBPACK_IMPORTED_MODULE_3__["default"]),
/* harmony export */   Logger: () => (/* reexport safe */ _Logger__WEBPACK_IMPORTED_MODULE_4__["default"]),
/* harmony export */   MessagePacker: () => (/* reexport safe */ _MessagePacker__WEBPACK_IMPORTED_MODULE_5__["default"]),
/* harmony export */   PendingState: () => (/* reexport safe */ _PendingState__WEBPACK_IMPORTED_MODULE_6__["default"]),
/* harmony export */   PromisedWebSockets: () => (/* reexport safe */ _PromisedWebSockets__WEBPACK_IMPORTED_MODULE_7__["default"])
/* harmony export */ });
/* harmony import */ var _AsyncQueue__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./AsyncQueue */ "./src/lib/gramjs/extensions/AsyncQueue.ts");
/* harmony import */ var _BinaryReader__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./BinaryReader */ "./src/lib/gramjs/extensions/BinaryReader.ts");
/* harmony import */ var _BinaryWriter__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./BinaryWriter */ "./src/lib/gramjs/extensions/BinaryWriter.ts");
/* harmony import */ var _HttpStream__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./HttpStream */ "./src/lib/gramjs/extensions/HttpStream.ts");
/* harmony import */ var _Logger__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./Logger */ "./src/lib/gramjs/extensions/Logger.ts");
/* harmony import */ var _MessagePacker__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./MessagePacker */ "./src/lib/gramjs/extensions/MessagePacker.ts");
/* harmony import */ var _PendingState__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./PendingState */ "./src/lib/gramjs/extensions/PendingState.ts");
/* harmony import */ var _PromisedWebSockets__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./PromisedWebSockets */ "./src/lib/gramjs/extensions/PromisedWebSockets.ts");










/***/ }),

/***/ "./src/lib/gramjs/index.ts":
/*!*********************************!*\
  !*** ./src/lib/gramjs/index.ts ***!
  \*********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Api: () => (/* reexport safe */ _tl__WEBPACK_IMPORTED_MODULE_0__.Api),
/* harmony export */   TelegramClient: () => (/* reexport safe */ _client_TelegramClient__WEBPACK_IMPORTED_MODULE_5__["default"]),
/* harmony export */   connection: () => (/* reexport module object */ _network__WEBPACK_IMPORTED_MODULE_3__),
/* harmony export */   errors: () => (/* reexport module object */ _errors__WEBPACK_IMPORTED_MODULE_1__),
/* harmony export */   extensions: () => (/* reexport module object */ _extensions__WEBPACK_IMPORTED_MODULE_2__),
/* harmony export */   helpers: () => (/* reexport module object */ _Helpers__WEBPACK_IMPORTED_MODULE_6__),
/* harmony export */   sessions: () => (/* reexport module object */ _sessions__WEBPACK_IMPORTED_MODULE_4__),
/* harmony export */   tl: () => (/* reexport module object */ _tl__WEBPACK_IMPORTED_MODULE_0__),
/* harmony export */   utils: () => (/* reexport module object */ _Utils__WEBPACK_IMPORTED_MODULE_7__)
/* harmony export */ });
/* harmony import */ var _tl__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./tl */ "./src/lib/gramjs/tl/index.ts");
/* harmony import */ var _errors__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./errors */ "./src/lib/gramjs/errors/index.ts");
/* harmony import */ var _extensions__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./extensions */ "./src/lib/gramjs/extensions/index.ts");
/* harmony import */ var _network__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./network */ "./src/lib/gramjs/network/index.ts");
/* harmony import */ var _sessions__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./sessions */ "./src/lib/gramjs/sessions/index.ts");
/* harmony import */ var _client_TelegramClient__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./client/TelegramClient */ "./src/lib/gramjs/client/TelegramClient.ts");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./Helpers */ "./src/lib/gramjs/Helpers.ts");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./Utils */ "./src/lib/gramjs/Utils.ts");


















/***/ }),

/***/ "./src/lib/gramjs/network/Authenticator.ts":
/*!*************************************************!*\
  !*** ./src/lib/gramjs/network/Authenticator.ts ***!
  \*************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   doAuthentication: () => (/* binding */ doAuthentication)
/* harmony export */ });
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! big-integer */ "./node_modules/big-integer/BigInteger.js");
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(big_integer__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _crypto_IGE__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../crypto/IGE */ "./src/lib/gramjs/crypto/IGE.ts");
/* harmony import */ var _crypto_RSA__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../crypto/RSA */ "./src/lib/gramjs/crypto/RSA.ts");
/* harmony import */ var _errors__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../errors */ "./src/lib/gramjs/errors/index.ts");
/* harmony import */ var _extensions__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../extensions */ "./src/lib/gramjs/extensions/index.ts");
/* harmony import */ var _tl__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../tl */ "./src/lib/gramjs/tl/index.ts");
/* harmony import */ var _crypto_AuthKey__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../crypto/AuthKey */ "./src/lib/gramjs/crypto/AuthKey.ts");
/* harmony import */ var _crypto_Factorizator__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../crypto/Factorizator */ "./src/lib/gramjs/crypto/Factorizator.ts");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];
/**
 * Executes the authentication process with the Telegram servers.
 * @param sender a connected {MTProtoPlainSender}.
 * @param log
 * @returns {Promise<{authKey: *, timeOffset: *}>}
 */










const RETRIES = 20;
async function doAuthentication(sender, log) {
  // Step 1 sending: PQ Request, endianness doesn't matter since it's random
  let bytes = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.generateRandomBytes)(16);
  const nonce = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.readBigIntFromBuffer)(bytes, false, true);
  const resPQ = await sender.send(new _tl__WEBPACK_IMPORTED_MODULE_5__.Api.ReqPqMulti({
    nonce
  }));
  log.debug('Starting authKey generation step 1');
  if (!(resPQ instanceof _tl__WEBPACK_IMPORTED_MODULE_5__.Api.ResPQ)) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError(`Step 1 answer was ${resPQ}`);
  }
  if (resPQ.nonce.neq(nonce)) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 1 invalid nonce from server');
  }
  const pq = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.readBigIntFromBuffer)(resPQ.pq, false, true);
  log.debug('Finished authKey generation step 1');
  // Step 2 sending: DH Exchange
  const {
    p,
    q
  } = _crypto_Factorizator__WEBPACK_IMPORTED_MODULE_7__.Factorizator.factorize(pq);
  const pBuffer = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.getByteArray)(p);
  const qBuffer = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.getByteArray)(q);
  bytes = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.generateRandomBytes)(32);
  const newNonce = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.readBigIntFromBuffer)(bytes, true, true);
  const pqInnerData = new _tl__WEBPACK_IMPORTED_MODULE_5__.Api.PQInnerData({
    pq: (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.getByteArray)(pq),
    // unsigned
    p: pBuffer,
    q: qBuffer,
    nonce: resPQ.nonce,
    serverNonce: resPQ.serverNonce,
    newNonce
  }).getBytes();
  if (pqInnerData.length > 144) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 1 invalid nonce from server');
  }
  let targetFingerprint;
  let targetKey;
  for (const fingerprint of resPQ.serverPublicKeyFingerprints) {
    targetKey = _crypto_RSA__WEBPACK_IMPORTED_MODULE_2__.SERVER_KEYS.get(fingerprint.toString());
    if (targetKey !== undefined) {
      targetFingerprint = fingerprint;
      break;
    }
  }
  if (targetFingerprint === undefined || targetKey === undefined) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 2 could not find a valid key for fingerprints');
  }
  // Value should be padded to be made 192 exactly
  const padding = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.generateRandomBytes)(192 - pqInnerData.length);
  const dataWithPadding = Buffer.concat([pqInnerData, padding]);
  const dataPadReversed = Buffer.from(dataWithPadding).reverse();
  let encryptedData;
  for (let i = 0; i < RETRIES; i++) {
    const tempKey = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.generateRandomBytes)(32);
    const shaDigestKeyWithData = await (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.sha256)(Buffer.concat([tempKey, dataWithPadding]));
    const dataWithHash = Buffer.concat([dataPadReversed, shaDigestKeyWithData]);
    const ige = new _crypto_IGE__WEBPACK_IMPORTED_MODULE_1__.IGE(tempKey, Buffer.alloc(32));
    const aesEncrypted = ige.encryptIge(dataWithHash);
    const tempKeyXor = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.bufferXor)(tempKey, await (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.sha256)(aesEncrypted));
    const keyAesEncrypted = Buffer.concat([tempKeyXor, aesEncrypted]);
    const keyAesEncryptedInt = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.readBigIntFromBuffer)(keyAesEncrypted, false, false);
    if (keyAesEncryptedInt.greaterOrEquals(targetKey.n)) {
      log.debug('Aes key greater than RSA. retrying');
      continue;
    }
    const encryptedDataBuffer = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.modExp)(keyAesEncryptedInt, big_integer__WEBPACK_IMPORTED_MODULE_0___default()(targetKey.e), targetKey.n);
    encryptedData = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.readBufferFromBigInt)(encryptedDataBuffer, 256, false, false);
    break;
  }
  if (encryptedData === undefined) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 2 could create a secure encrypted key');
  }
  log.debug('Step 2 : Generated a secure aes encrypted data');
  const serverDhParams = await sender.send(new _tl__WEBPACK_IMPORTED_MODULE_5__.Api.ReqDHParams({
    nonce: resPQ.nonce,
    serverNonce: resPQ.serverNonce,
    p: pBuffer,
    q: qBuffer,
    publicKeyFingerprint: targetFingerprint,
    encryptedData
  }));
  if (!(serverDhParams instanceof _tl__WEBPACK_IMPORTED_MODULE_5__.Api.ServerDHParamsOk || serverDhParams instanceof _tl__WEBPACK_IMPORTED_MODULE_5__.Api.ServerDHParamsFail)) {
    throw new Error(`Step 2.1 answer was ${serverDhParams}`);
  }
  if (serverDhParams.nonce.neq(resPQ.nonce)) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 2 invalid nonce from server');
  }
  if (serverDhParams.serverNonce.neq(resPQ.serverNonce)) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 2 invalid server nonce from server');
  }
  if (serverDhParams instanceof _tl__WEBPACK_IMPORTED_MODULE_5__.Api.ServerDHParamsFail) {
    const sh = await (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.sha1)((0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.toSignedLittleBuffer)(newNonce, 32).slice(4, 20));
    const nnh = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.readBigIntFromBuffer)(sh, true, true);
    if (serverDhParams.newNonceHash.neq(nnh)) {
      throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 2 invalid DH fail nonce from server');
    }
  }
  if (!(serverDhParams instanceof _tl__WEBPACK_IMPORTED_MODULE_5__.Api.ServerDHParamsOk)) {
    throw new Error(`Step 2.2 answer was ${serverDhParams.className}`);
  }
  log.debug('Finished authKey generation step 2');
  log.debug('Starting authKey generation step 3');

  // Step 3 sending: Complete DH Exchange
  const {
    key,
    iv
  } = await (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.generateKeyDataFromNonce)(resPQ.serverNonce, newNonce);
  if (serverDhParams.encryptedAnswer.length % 16 !== 0) {
    // See PR#453
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 3 AES block size mismatch');
  }
  const ige = new _crypto_IGE__WEBPACK_IMPORTED_MODULE_1__.IGE(key, iv);
  const plainTextAnswer = ige.decryptIge(serverDhParams.encryptedAnswer);
  const reader = new _extensions__WEBPACK_IMPORTED_MODULE_4__.BinaryReader(plainTextAnswer);
  const hash = reader.read(20); // hash sum
  const serverDhInner = reader.tgReadObject();
  if (!(serverDhInner instanceof _tl__WEBPACK_IMPORTED_MODULE_5__.Api.ServerDHInnerData)) {
    throw new Error(`Step 3 answer was ${serverDhInner}`);
  }
  const sha1Answer = await (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.sha1)(serverDhInner.getBytes());
  if (!hash.equals(sha1Answer)) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 3 Invalid hash answer');
  }
  if (serverDhInner.nonce.neq(resPQ.nonce)) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 3 Invalid nonce in encrypted answer');
  }
  if (serverDhInner.serverNonce.neq(resPQ.serverNonce)) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 3 Invalid server nonce in encrypted answer');
  }
  if (serverDhInner.g !== 3 || serverDhInner.dhPrime.toString('hex') !== 'c71caeb9c6b1c9048e6c522f70f13' + 'f73980d40238e3e21c14934d037563d930f48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c3720fd5' + '1f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f642477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3' + 'c4f3a9060bee67cf9a4a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754fd17ed950d5965b4b9dd4' + '6582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce9298' + '51f0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b') {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 3 invalid dhPrime or g');
  }
  const dhPrime = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.readBigIntFromBuffer)(serverDhInner.dhPrime, false, false);
  const ga = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.readBigIntFromBuffer)(serverDhInner.gA, false, false);
  const timeOffset = serverDhInner.serverTime - Math.floor(Date.now() / 1000);
  const b = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.readBigIntFromBuffer)((0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.generateRandomBytes)(256), false, false);
  const gb = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.modExp)(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(serverDhInner.g), b, dhPrime);
  const gab = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.modExp)(ga, b, dhPrime);
  if (ga.lesserOrEquals(1)) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 3 failed ga > 1 check');
  }
  if (gb.lesserOrEquals(1)) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 3 failed gb > 1 check');
  }
  if (ga.greater(dhPrime.minus(1))) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 3 failed ga > dh_prime - 1 check');
  }
  const toCheckAgainst = big_integer__WEBPACK_IMPORTED_MODULE_0___default()(2).pow(2048 - 64);
  if (!(ga.greaterOrEquals(toCheckAgainst) && ga.lesserOrEquals(dhPrime.minus(toCheckAgainst)))) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 3 failed dh_prime - 2^{2048-64} < ga < 2^{2048-64} check');
  }
  if (!(gb.greaterOrEquals(toCheckAgainst) && gb.lesserOrEquals(dhPrime.minus(toCheckAgainst)))) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 3 failed dh_prime - 2^{2048-64} < gb < 2^{2048-64} check');
  }

  // Prepare client DH Inner Data
  const clientDhInner = new _tl__WEBPACK_IMPORTED_MODULE_5__.Api.ClientDHInnerData({
    nonce: resPQ.nonce,
    serverNonce: resPQ.serverNonce,
    retryId: (big_integer__WEBPACK_IMPORTED_MODULE_0___default().zero),
    // TODO Actual retry ID
    gB: (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.getByteArray)(gb, false)
  }).getBytes();
  const clientDdhInnerHashed = Buffer.concat([await (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.sha1)(clientDhInner), clientDhInner]);
  // Encryption

  const clientDhEncrypted = ige.encryptIge(clientDdhInnerHashed);
  const dhGen = await sender.send(new _tl__WEBPACK_IMPORTED_MODULE_5__.Api.SetClientDHParams({
    nonce: resPQ.nonce,
    serverNonce: resPQ.serverNonce,
    encryptedData: clientDhEncrypted
  }));
  const nonceTypes = [_tl__WEBPACK_IMPORTED_MODULE_5__.Api.DhGenOk, _tl__WEBPACK_IMPORTED_MODULE_5__.Api.DhGenRetry, _tl__WEBPACK_IMPORTED_MODULE_5__.Api.DhGenFail];
  // TS being weird again.
  const nonceTypesString = ['DhGenOk', 'DhGenRetry', 'DhGenFail'];
  if (!(dhGen instanceof nonceTypes[0] || dhGen instanceof nonceTypes[1] || dhGen instanceof nonceTypes[2])) {
    throw new Error(`Step 3.1 answer was ${dhGen}`);
  }
  const {
    name
  } = dhGen.constructor;
  if (dhGen.nonce.neq(resPQ.nonce)) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError(`Step 3 invalid ${name} nonce from server`);
  }
  if (dhGen.serverNonce.neq(resPQ.serverNonce)) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError(`Step 3 invalid ${name} server nonce from server`);
  }
  const authKey = new _crypto_AuthKey__WEBPACK_IMPORTED_MODULE_6__.AuthKey();
  await authKey.setKey((0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.getByteArray)(gab));
  const nonceNumber = 1 + nonceTypesString.indexOf(dhGen.className);
  const newNonceHash = await authKey.calcNewNonceHash(newNonce, nonceNumber);
  // @ts-ignore
  const dhHash = dhGen[`newNonceHash${nonceNumber}`];
  if (dhHash.neq(newNonceHash)) {
    throw new _errors__WEBPACK_IMPORTED_MODULE_3__.SecurityError('Step 3 invalid new nonce hash');
  }
  if (!(dhGen instanceof _tl__WEBPACK_IMPORTED_MODULE_5__.Api.DhGenOk)) {
    throw new Error(`Step 3.2 answer was ${dhGen.className}`);
  }
  log.debug('Finished authKey generation step 3');
  return {
    authKey,
    timeOffset
  };
}

/***/ }),

/***/ "./src/lib/gramjs/network/MTProtoPlainSender.ts":
/*!******************************************************!*\
  !*** ./src/lib/gramjs/network/MTProtoPlainSender.ts ***!
  \******************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ MTProtoPlainSender)
/* harmony export */ });
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! big-integer */ "./node_modules/big-integer/BigInteger.js");
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(big_integer__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _extensions__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../extensions */ "./src/lib/gramjs/extensions/index.ts");
/* harmony import */ var _errors_Common__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../errors/Common */ "./src/lib/gramjs/errors/Common.ts");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* harmony import */ var _MTProtoState__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./MTProtoState */ "./src/lib/gramjs/network/MTProtoState.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];
/**
 *  This module contains the class used to communicate with Telegram's servers
 *  in plain text, when no authorization key has been created yet.
 */






/**
 * MTProto Mobile Protocol plain sender (https://core.telegram.org/mtproto/description#unencrypted-messages)
 */

class MTProtoPlainSender {
  /**
     * Initializes the MTProto plain sender.
     * @param connection connection: the Connection to be used.
     * @param loggers
     */
  constructor(connection, loggers) {
    this._state = new _MTProtoState__WEBPACK_IMPORTED_MODULE_4__["default"](undefined, loggers);
    this._connection = connection;
  }

  /**
     * Sends and receives the result for the given request.
     * @param request
     */
  async send(request) {
    let body = request.getBytes();
    let msgId = this._state._getNewMsgId();
    const m = (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.toSignedLittleBuffer)(msgId, 8);
    const b = Buffer.alloc(4);
    b.writeInt32LE(body.length, 0);
    const res = Buffer.concat([Buffer.concat([Buffer.alloc(8), m, b]), body]);
    await this._connection.send(res);
    body = await this._connection.recv();
    if (body.length < 8) {
      throw new _errors_Common__WEBPACK_IMPORTED_MODULE_2__.InvalidBufferError(body);
    }
    const reader = new _extensions__WEBPACK_IMPORTED_MODULE_1__.BinaryReader(body);
    const authKeyId = reader.readLong();
    if (authKeyId.neq(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(0))) {
      throw new Error('Bad authKeyId');
    }
    msgId = reader.readLong();
    if (msgId.eq(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(0))) {
      throw new Error('Bad msgId');
    }
    /** ^ We should make sure that the read ``msg_id`` is greater
         * than our own ``msg_id``. However, under some circumstances
         * (bad system clock/working behind proxies) this seems to not
         * be the case, which would cause endless assertion errors.
         */

    const length = reader.readInt();
    if (length <= 0) {
      throw new Error('Bad length');
    }
    /**
         * We could read length bytes and use those in a new reader to read
         * the next TLObject without including the padding, but since the
         * reader isn't used for anything else after this, it's unnecessary.
         */
    return reader.tgReadObject();
  }
}

/***/ }),

/***/ "./src/lib/gramjs/network/MTProtoSender.ts":
/*!*************************************************!*\
  !*** ./src/lib/gramjs/network/MTProtoSender.ts ***!
  \*************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ MTProtoSender)
/* harmony export */ });
/* harmony import */ var _errors__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../errors */ "./src/lib/gramjs/errors/index.ts");
/* harmony import */ var _extensions__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../extensions */ "./src/lib/gramjs/extensions/index.ts");
/* harmony import */ var _tl__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../tl */ "./src/lib/gramjs/tl/index.ts");
/* harmony import */ var _tl_core_GZIPPacked__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../tl/core/GZIPPacked */ "./src/lib/gramjs/tl/core/GZIPPacked.ts");
/* harmony import */ var _tl_core_RPCResult__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../tl/core/RPCResult */ "./src/lib/gramjs/tl/core/RPCResult.ts");
/* harmony import */ var _connection__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./connection */ "./src/lib/gramjs/network/connection/index.ts");
/* harmony import */ var _updates__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./updates */ "./src/lib/gramjs/network/updates.ts");
/* harmony import */ var _crypto_AuthKey__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../crypto/AuthKey */ "./src/lib/gramjs/crypto/AuthKey.ts");
/* harmony import */ var _errors_Common__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../errors/Common */ "./src/lib/gramjs/errors/Common.ts");
/* harmony import */ var _extensions_PendingState__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../extensions/PendingState */ "./src/lib/gramjs/extensions/PendingState.ts");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* harmony import */ var _tl_core_MessageContainer__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ../tl/core/MessageContainer */ "./src/lib/gramjs/tl/core/MessageContainer.ts");
/* harmony import */ var _Authenticator__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! ./Authenticator */ "./src/lib/gramjs/network/Authenticator.ts");
/* harmony import */ var _MTProtoPlainSender__WEBPACK_IMPORTED_MODULE_13__ = __webpack_require__(/*! ./MTProtoPlainSender */ "./src/lib/gramjs/network/MTProtoPlainSender.ts");
/* harmony import */ var _MTProtoState__WEBPACK_IMPORTED_MODULE_14__ = __webpack_require__(/*! ./MTProtoState */ "./src/lib/gramjs/network/MTProtoState.ts");
/* harmony import */ var _RequestState__WEBPACK_IMPORTED_MODULE_15__ = __webpack_require__(/*! ./RequestState */ "./src/lib/gramjs/network/RequestState.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];
















const LONGPOLL_MAX_WAIT = 3000;
const LONGPOLL_MAX_DELAY = 500;
const LONGPOLL_WAIT_AFTER = 150;
/**
 * MTProto Mobile Protocol sender
 * (https://core.telegram.org/mtproto/description)
 * This class is responsible for wrapping requests into `TLMessage`'s,
 * sending them over the network and receiving them in a safe manner.
 *
 * Automatic reconnection due to temporary network issues is a concern
 * for this class as well, including retry of messages that could not
 * be sent successfully.
 *
 * A new authorization key will be generated on connection if no other
 * key exists yet.
 */
class MTProtoSender {
  static DEFAULT_OPTIONS = {
    logger: undefined,
    retries: Infinity,
    retriesToFallback: 1,
    delay: 2000,
    retryMainConnectionDelay: 10000,
    shouldForceHttpTransport: false,
    shouldAllowHttpTransport: false,
    autoReconnect: true,
    connectTimeout: undefined,
    authKeyCallback: undefined,
    updateCallback: undefined,
    autoReconnectCallback: undefined,
    isMainSender: undefined,
    onConnectionBreak: undefined,
    isExported: undefined,
    getShouldDebugExportedSenders: undefined
  };
  _isReconnectingToMain = false;
  isConnecting = false;
  _authenticated = false;

  /**
   * @param authKey
   * @param opts
   */
  constructor(authKey, opts) {
    const args = {
      ...MTProtoSender.DEFAULT_OPTIONS,
      ...opts
    };
    this._connection = undefined;
    this._fallbackConnection = undefined;
    this._shouldForceHttpTransport = args.shouldForceHttpTransport;
    this._shouldAllowHttpTransport = args.shouldAllowHttpTransport;
    this._log = args.logger;
    this._dcId = args.dcId;
    this._senderIndex = args.senderIndex || 0;
    this._retries = args.retries;
    this._retriesToFallback = args.retriesToFallback;
    this._delay = args.delay;
    this._retryMainConnectionDelay = args.retryMainConnectionDelay;
    this._authKeyCallback = args.authKeyCallback;
    this._updateCallback = args.updateCallback;
    this._autoReconnectCallback = args.autoReconnectCallback;
    this._isMainSender = Boolean(args.isMainSender);
    this._isExported = Boolean(args.isExported);
    this._onConnectionBreak = args.onConnectionBreak;
    this._isFallback = false;
    this._getShouldDebugExportedSenders = args.getShouldDebugExportedSenders;

    /**
     * whether we disconnected ourself or telegram did it.
     */
    this.userDisconnected = false;

    /**
     * Whether the user has explicitly connected or disconnected.
     *
     * If a disconnection happens for any other reason and it
     * was *not* user action then the pending messages won't
     * be cleared but on explicit user disconnection all the
     * pending futures should be cancelled.
     */
    this._userConnected = false;
    this.isReconnecting = false;
    this._disconnected = true;

    /**
     * We need to join the loops upon disconnection
     */
    this._sendLoopHandle = undefined;
    this._longPollLoopHandle = undefined;
    this._recvLoopHandle = undefined;

    /**
     * Preserving the references of the AuthKey and state is important
     */
    this.authKey = authKey || new _crypto_AuthKey__WEBPACK_IMPORTED_MODULE_7__.AuthKey();
    this._state = new _MTProtoState__WEBPACK_IMPORTED_MODULE_14__["default"](this.authKey, this._log);

    /**
     * Outgoing messages are put in a queue and sent in a batch.
     * Note that here we're also storing their ``_RequestState``.
     */
    this._sendQueue = new _extensions__WEBPACK_IMPORTED_MODULE_1__.MessagePacker(this._state, this._log);
    this._sendQueueLongPoll = new _extensions__WEBPACK_IMPORTED_MODULE_1__.MessagePacker(this._state, this._log);

    /**
     * Sent states are remembered until a response is received.
     */
    this._pendingState = new _extensions_PendingState__WEBPACK_IMPORTED_MODULE_9__["default"]();

    /**
     * Responses must be acknowledged, and we can also batch these.
     */
    this._pendingAck = new Set();

    /**
     * Similar to pending_messages but only for the last acknowledges.
     * These can't go in pending_messages because no acknowledge for them
     * is received, but we may still need to resend their state on bad salts.
     */
    this._lastAcks = [];

    /**
     * Jump table from response ID to method that handles it
     */

    this._handlers = {
      [_tl_core_RPCResult__WEBPACK_IMPORTED_MODULE_4__["default"].CONSTRUCTOR_ID]: this._handleRPCResult.bind(this),
      [_tl_core_MessageContainer__WEBPACK_IMPORTED_MODULE_11__["default"].CONSTRUCTOR_ID]: this._handleContainer.bind(this),
      [_tl_core_GZIPPacked__WEBPACK_IMPORTED_MODULE_3__["default"].CONSTRUCTOR_ID]: this._handleGzipPacked.bind(this),
      [_tl__WEBPACK_IMPORTED_MODULE_2__.Api.Pong.CONSTRUCTOR_ID]: this._handlePong.bind(this),
      [_tl__WEBPACK_IMPORTED_MODULE_2__.Api.BadServerSalt.CONSTRUCTOR_ID]: this._handleBadServerSalt.bind(this),
      [_tl__WEBPACK_IMPORTED_MODULE_2__.Api.BadMsgNotification.CONSTRUCTOR_ID]: this._handleBadNotification.bind(this),
      [_tl__WEBPACK_IMPORTED_MODULE_2__.Api.MsgDetailedInfo.CONSTRUCTOR_ID]: this._handleDetailedInfo.bind(this),
      [_tl__WEBPACK_IMPORTED_MODULE_2__.Api.MsgNewDetailedInfo.CONSTRUCTOR_ID]: this._handleNewDetailedInfo.bind(this),
      [_tl__WEBPACK_IMPORTED_MODULE_2__.Api.NewSessionCreated.CONSTRUCTOR_ID]: this._handleNewSessionCreated.bind(this),
      [_tl__WEBPACK_IMPORTED_MODULE_2__.Api.MsgsAck.CONSTRUCTOR_ID]: this._handleAck.bind(this),
      [_tl__WEBPACK_IMPORTED_MODULE_2__.Api.FutureSalts.CONSTRUCTOR_ID]: this._handleFutureSalts.bind(this),
      [_tl__WEBPACK_IMPORTED_MODULE_2__.Api.MsgsStateReq.CONSTRUCTOR_ID]: this._handleStateForgotten.bind(this),
      [_tl__WEBPACK_IMPORTED_MODULE_2__.Api.MsgResendReq.CONSTRUCTOR_ID]: this._handleStateForgotten.bind(this),
      [_tl__WEBPACK_IMPORTED_MODULE_2__.Api.MsgsAllInfo.CONSTRUCTOR_ID]: this._handleMsgAll.bind(this)
    };
  }

  // Public API

  logWithIndexCallback(level) {
    return (...args) => {
      if (!this._getShouldDebugExportedSenders || !this._getShouldDebugExportedSenders()) return;
      // eslint-disable-next-line no-console
      console[level](`[${this._isExported ? `idx=${this._senderIndex} ` : 'M '}dcId=${this._dcId}]`, ...args);
    };
  }
  logWithIndex = {
    debug: this.logWithIndexCallback('debug'),
    log: this.logWithIndexCallback('log'),
    warn: this.logWithIndexCallback('warn'),
    error: this.logWithIndexCallback('error')
  };
  getConnection() {
    return this._isFallback ? this._fallbackConnection : this._connection;
  }

  /**
   * Connects to the specified given connection using the given auth key.
   * @param connection
   * @param [force]
   * @param fallbackConnection
   * @returns {Promise<boolean>}
   */
  async connect(connection, force, fallbackConnection) {
    this.userDisconnected = false;
    if (this._userConnected && !force) {
      this._log.info('User is already connected!');
      return false;
    }
    this.isConnecting = true;
    this._isFallback = this._shouldForceHttpTransport && this._shouldAllowHttpTransport;
    this._connection = connection;
    this._fallbackConnection = fallbackConnection;
    for (let attempt = 0; attempt < this._retries + this._retriesToFallback; attempt++) {
      try {
        if (attempt >= this._retriesToFallback && this._shouldAllowHttpTransport) {
          this._isFallback = true;
          this.logWithIndex.warn('Using fallback connection');
          this._log.warn('Using fallback connection');
        }
        this.logWithIndex.warn('Connecting...');
        await this._connect(this.getConnection());
        this.logWithIndex.warn('Connected!');
        if (!this._isExported) {
          this._updateCallback?.(new _updates__WEBPACK_IMPORTED_MODULE_6__.UpdateConnectionState(_updates__WEBPACK_IMPORTED_MODULE_6__.UpdateConnectionState.connected));
        }
        break;
      } catch (err) {
        if (!this._isExported && attempt === 0) {
          this._updateCallback?.(new _updates__WEBPACK_IMPORTED_MODULE_6__.UpdateConnectionState(_updates__WEBPACK_IMPORTED_MODULE_6__.UpdateConnectionState.disconnected));
        }
        this._log.error(`${this._isFallback ? 'HTTP' : 'WebSocket'} connection failed attempt: ${attempt + 1}`);
        // eslint-disable-next-line no-console
        console.error(err);
        await (0,_Helpers__WEBPACK_IMPORTED_MODULE_10__.sleep)(this._delay);
      }
    }
    this.isConnecting = false;
    if (this._isFallback && !this._shouldForceHttpTransport) {
      void this.tryReconnectToMain();
    }
    return true;
  }
  async tryReconnectToMain() {
    if (!this.isConnecting && this._isFallback && !this._isReconnectingToMain && !this.isReconnecting && !this._shouldForceHttpTransport && !this._isExported) {
      this._log.debug('Trying to reconnect to main connection');
      this._isReconnectingToMain = true;
      try {
        await this._connection.connect();
        this._log.info('Reconnected to main connection');
        this.logWithIndex.warn('Reconnected to main connection');
        this.isReconnecting = true;
        if (this._fallbackConnection) this._disconnect(this._fallbackConnection);
        await this.connect(this._connection, true, this._fallbackConnection);
        this.isReconnecting = false;
        this._isReconnectingToMain = false;
      } catch (e) {
        this.isReconnecting = false;
        this._isReconnectingToMain = false;
        this._log.error(`Failed to reconnect to main connection, retrying in ${this._retryMainConnectionDelay}ms`);
        await (0,_Helpers__WEBPACK_IMPORTED_MODULE_10__.sleep)(this._retryMainConnectionDelay);
        void this.tryReconnectToMain();
      }
    } else {
      await (0,_Helpers__WEBPACK_IMPORTED_MODULE_10__.sleep)(this._retryMainConnectionDelay);
    }
  }
  isConnected() {
    return this._userConnected;
  }

  /**
   * Cleanly disconnects the instance from the network, cancels
   * all pending requests, and closes the send and receive loops.
   */
  disconnect() {
    this.userDisconnected = true;
    this.logWithIndex.warn('Disconnecting...');
    const connection = this.getConnection();
    if (!connection) return;
    this._disconnect(connection);
  }
  destroy() {
    this._sendQueue.clear();
  }

  /**
   *
   This method enqueues the given request to be sent. Its send
   state will be saved until a response arrives, and a ``Future``
   that will be resolved when the response arrives will be returned:
    .. code-block:: javascript
    async def method():
   # Sending (enqueued for the send loop)
   future = sender.send(request)
   # Receiving (waits for the receive loop to read the result)
   result = await future
    Designed like this because Telegram may send the response at
   any point, and it can send other items while one waits for it.
   Once the response for this future arrives, it is set with the
   received result, quite similar to how a ``receive()`` call
   would otherwise work.
    Since the receiving part is "built in" the future, it's
   impossible to await receive a result that was never sent.
   * @param request
   * @param abortSignal
   * @param isLongPoll
   * @returns {RequestState}
   */
  send(request, abortSignal, isLongPoll = false) {
    const state = new _RequestState__WEBPACK_IMPORTED_MODULE_15__["default"](request, abortSignal);
    if (!isLongPoll) {
      this.logWithIndex.debug(`Send ${request.className}`);
      this._sendQueue.append(state);
    } else {
      this._sendQueueLongPoll.append(state);
    }
    return state.promise;
  }
  addStateToQueue(state) {
    this._sendQueue.append(state);
  }
  async sendBeacon(request) {
    if (!this._userConnected || !(this._fallbackConnection instanceof _connection__WEBPACK_IMPORTED_MODULE_5__.HttpConnection)) {
      throw new Error('Cannot send requests while disconnected');
    }
    const state = new _RequestState__WEBPACK_IMPORTED_MODULE_15__["default"](request, undefined);
    const data = await this._sendQueue.getBeacon(state);
    if (!data) return;
    const encryptedData = await this._state.encryptMessageData(data);
    postMessage({
      type: 'sendBeacon',
      data: encryptedData,
      url: this._fallbackConnection.href
    });
  }

  /**
   * Performs the actual connection, retrying, generating the
   * authorization key if necessary, and starting the send and
   * receive loops.
   * @returns {Promise<void>}
   * @private
   */
  async _connect(connection) {
    if (!connection.isConnected()) {
      this._log.info('Connecting to {0}...'.replace('{0}', connection._ip));
      await connection.connect();
      this._log.debug('Connection success!');
    }
    if (!this.authKey.getKey()) {
      const plain = new _MTProtoPlainSender__WEBPACK_IMPORTED_MODULE_13__["default"](connection, this._log);
      this._log.debug('New auth_key attempt ...');
      const res = await (0,_Authenticator__WEBPACK_IMPORTED_MODULE_12__.doAuthentication)(plain, this._log);
      this._log.debug('Generated new auth_key successfully');
      await this.authKey.setKey(res.authKey);
      this._state.timeOffset = res.timeOffset;
      if (!this._isExported) {
        this._updateCallback?.(new _updates__WEBPACK_IMPORTED_MODULE_6__.UpdateServerTimeOffset(this._state.timeOffset));
      }

      /**
       * This is *EXTREMELY* important since we don't control
       * external references to the authorization key, we must
       * notify whenever we change it. This is crucial when we
       * switch to different data centers.
       */
      if (this._authKeyCallback) {
        await this._authKeyCallback(this.authKey, this._dcId);
      }
    } else {
      this._authenticated = true;
      this._log.debug('Already have an auth key ...');
    }
    this._userConnected = true;
    this.isReconnecting = false;
    if (!this._sendLoopHandle) {
      this._log.debug('Starting send loop');
      this._sendLoopHandle = this._sendLoop();
    }
    if (!this._recvLoopHandle) {
      this._log.debug('Starting receive loop');
      this._recvLoopHandle = this._recvLoop();
    }
    if (!this._longPollLoopHandle && connection.shouldLongPoll) {
      this._log.debug('Starting long-poll loop');
      this._longPollLoopHandle = this._longPollLoop();
    }

    // _disconnected only completes after manual disconnection
    // or errors after which the sender cannot continue such
    // as failing to reconnect or any unexpected error.

    this._log.info('Connection to %s complete!'.replace('%s', connection.toString()));
  }
  _disconnect(connection) {
    if (!this._isExported) {
      this._updateCallback?.(new _updates__WEBPACK_IMPORTED_MODULE_6__.UpdateConnectionState(_updates__WEBPACK_IMPORTED_MODULE_6__.UpdateConnectionState.disconnected));
    }
    if (connection === undefined) {
      this._log.info('Not disconnecting (already have no connection)');
      return;
    }
    this._log.info('Disconnecting from %s...'.replace('%s', connection.toString()));
    this._userConnected = false;
    this._log.debug('Closing current connection...');
    this.logWithIndex.warn('Disconnecting');
    connection.disconnect();
  }
  async _longPollLoop() {
    while (this._userConnected && !this.isReconnecting && this._isFallback && this.getConnection().shouldLongPoll) {
      await this._sendQueueLongPoll.wait();
      const res = await this._sendQueueLongPoll.get();
      if (this.isReconnecting || !this._isFallback) {
        this._longPollLoopHandle = undefined;
        return;
      }
      if (!res) {
        continue;
      }
      let {
        data
      } = res;
      const {
        batch
      } = res;
      this._log.debug(`Encrypting ${batch.length} message(s) in ${data.length} bytes for sending`);
      data = await this._state.encryptMessageData(data);
      try {
        await this._fallbackConnection?.send(data);
      } catch (e) {
        this._log.error(e);
        this._log.info('Connection closed while sending data');
        this._longPollLoopHandle = undefined;
        this.isSendingLongPoll = false;
        if (!this.userDisconnected) {
          this.reconnect();
        }
        return;
      }
      this.isSendingLongPoll = false;
      this.checkLongPoll();
    }
    this._longPollLoopHandle = undefined;
  }

  /**
   * This loop is responsible for popping items off the send
   * queue, encrypting them, and sending them over the network.
   * Besides `connect`, only this method ever sends data.
   * @returns {Promise<void>}
   * @private
   */
  async _sendLoop() {
    // Retry previous pending requests
    this._sendQueue.prepend(this._pendingState.values());
    this._pendingState.clear();
    while (this._userConnected && !this.isReconnecting) {
      const appendAcks = () => {
        if (this._pendingAck.size) {
          const ack = new _RequestState__WEBPACK_IMPORTED_MODULE_15__["default"](new _tl__WEBPACK_IMPORTED_MODULE_2__.Api.MsgsAck({
            msgIds: Array(...this._pendingAck)
          }));
          this._sendQueue.append(ack);
          this._lastAcks.push(ack);
          if (this._lastAcks.length >= 10) {
            this._lastAcks.shift();
          }
          this._pendingAck.clear();
        }
      };
      appendAcks();
      this.logWithIndex.debug(`Waiting for messages to send... ${this.isReconnecting}`);
      this._log.debug(`Waiting for messages to send... ${this.isReconnecting}`);
      // TODO Wait for the connection send queue to be empty?
      // This means that while it's not empty we can wait for
      // more messages to be added to the send queue.
      await this._sendQueue.wait();
      if (this._isFallback) {
        // We don't long-poll on main loop, instead we have a separate loop for that
        this.send(new _tl__WEBPACK_IMPORTED_MODULE_2__.Api.HttpWait({
          maxDelay: 0,
          waitAfter: 0,
          maxWait: 0
        }));
      }

      // If we've had new ACKs appended while waiting for messages to send, add them to queue
      appendAcks();
      const res = await this._sendQueue.get();
      this.logWithIndex.debug(`Got ${res?.batch.length} message(s) to send`);
      if (!res) {
        continue;
      }
      let {
        data
      } = res;
      const {
        batch
      } = res;
      for (const state of batch) {
        if (!Array.isArray(state)) {
          if (state.request.classType === 'request' && state.request.className !== 'HttpWait') {
            this._pendingState.set(state.msgId, state);
          }
        } else {
          for (const s of state) {
            if (s.request.classType === 'request' && s.request.className !== 'HttpWait') {
              this._pendingState.set(s.msgId, s);
            }
          }
        }
      }
      if (this.isReconnecting) {
        this.logWithIndex.debug('Reconnecting :(');
        this._sendLoopHandle = undefined;
        return;
      }
      this._log.debug(`Encrypting ${batch.length} message(s) in ${data.length} bytes for sending`);
      this.logWithIndex.debug('Sending', batch.map(m => m.request.className));
      data = await this._state.encryptMessageData(data);
      try {
        await this.getConnection().send(data);
      } catch (e) {
        this.logWithIndex.debug(`Connection closed while sending data ${e}`);
        this._log.error(e);
        this._log.info('Connection closed while sending data');
        this._sendLoopHandle = undefined;
        if (!this.userDisconnected) {
          this.reconnect();
        }
        return;
      } finally {
        for (const state of batch) {
          if (!Array.isArray(state)) {
            if (state.request.className === 'HttpWait') {
              state.resolve?.();
            }
          } else {
            for (const s of state) {
              if (s.request.className === 'HttpWait') {
                state.resolve?.();
              }
            }
          }
        }
        this.logWithIndex.debug('Encrypted messages put in a queue to be sent');
        this._log.debug('Encrypted messages put in a queue to be sent');
      }
    }
    this._sendLoopHandle = undefined;
  }
  async _recvLoop() {
    let body;
    let message;
    while (this._userConnected && !this.isReconnecting) {
      this._log.debug('Receiving items from the network...');
      this.logWithIndex.debug('Receiving items from the network...');
      try {
        body = await this.getConnection().recv();
      } catch (e) {
        // this._log.info('Connection closed while receiving data');
        /** when the server disconnects us we want to reconnect */
        if (!this.userDisconnected) {
          this._log.error(e);
          this._log.warn('Connection closed while receiving data');
          this.reconnect();
        }
        this._recvLoopHandle = undefined;
        return;
      }
      try {
        // TODO: Handle `DecryptedDataBlock` in calls like a regular `TLMessage` rather than `Buffer`
        message = await this._state.decryptMessageData(body);
      } catch (e) {
        this.logWithIndex.debug(`Error while receiving items from the network ${e.toString()}`);
        if (e instanceof _errors_Common__WEBPACK_IMPORTED_MODULE_8__.TypeNotFoundError) {
          // Received object which we don't know how to deserialize
          this._log.info(`Type ${e.invalidConstructorId} not found, remaining data ${e.remaining.length} bytes`);
          continue;
        } else if (e instanceof _errors_Common__WEBPACK_IMPORTED_MODULE_8__.SecurityError) {
          // A step while decoding had the incorrect data. This message
          // should not be considered safe and it should be ignored.
          this._log.warn(`Security error while unpacking a received message: ${e.message}`);
          continue;
        } else if (e instanceof _errors_Common__WEBPACK_IMPORTED_MODULE_8__.InvalidBufferError) {
          // 404 means that the server has "forgotten" our auth key and we need to create a new one.
          if (e.code === 404) {
            this._handleBadAuthKey();
          } else {
            // this happens sometimes when telegram is having some internal issues.
            // reconnecting should be enough usually
            // since the data we sent and received is probably wrong now.
            this._log.warn(`Invalid buffer ${e.code} for dc ${this._dcId}`);
            this.reconnect();
          }
          this._recvLoopHandle = undefined;
          return;
        } else {
          this._log.error('Unhandled error while receiving data');
          this._log.error(e);
          this.reconnect();
          this._recvLoopHandle = undefined;
          return;
        }
      }
      try {
        await this._processMessage(message);
      } catch (e) {
        // `RPCError` errors except for 'AUTH_KEY_UNREGISTERED' should be handled by the client
        if (e instanceof _errors__WEBPACK_IMPORTED_MODULE_0__.RPCError) {
          if (e.errorMessage === 'AUTH_KEY_UNREGISTERED' || e.errorMessage === 'SESSION_REVOKED' || e.errorMessage === 'USER_DEACTIVATED') {
            // 'AUTH_KEY_UNREGISTERED' for the main sender is thrown when unauthorized and should be ignored
            this._handleBadAuthKey(true);
          }
        } else {
          this._log.error('Unhandled error while receiving data');
          this._log.error(e);
        }
      }
      void this.checkLongPoll();
    }
    this._recvLoopHandle = undefined;
  }
  checkLongPoll() {
    if (this.isSendingLongPoll || !this._isFallback) return;
    this.isSendingLongPoll = true;
    this.send(new _tl__WEBPACK_IMPORTED_MODULE_2__.Api.HttpWait({
      maxDelay: LONGPOLL_MAX_DELAY,
      waitAfter: LONGPOLL_WAIT_AFTER,
      maxWait: LONGPOLL_MAX_WAIT
    }), undefined, true);
  }
  _handleBadAuthKey(shouldSkipForMain) {
    if (shouldSkipForMain && this._isMainSender) {
      return;
    }
    this._log.warn(`Broken authorization key for dc ${this._dcId}, resetting...`);
    if (this._isMainSender && !this._isExported) {
      this._updateCallback?.(new _updates__WEBPACK_IMPORTED_MODULE_6__.UpdateConnectionState(_updates__WEBPACK_IMPORTED_MODULE_6__.UpdateConnectionState.broken));
    } else if (!this._isMainSender && this._onConnectionBreak) {
      this._onConnectionBreak(this._dcId);
    }
  }

  // Response Handlers

  /**
   * Adds the given message to the list of messages that must be
   * acknowledged and dispatches control to different ``_handle_*``
   * method based on its type.
   * @param message
   * @returns {Promise<void>}
   * @private
   */
  async _processMessage(message) {
    if (message.obj.className === 'MsgsAck') return;
    this.logWithIndex.debug(`Process message ${message.obj.className}`);
    this._pendingAck.add(message.msgId);
    if (this.getConnection().shouldLongPoll) {
      this._sendQueue.setReady?.(true);
    }
    message.obj = await message.obj;
    let handler = this._handlers[message.obj.CONSTRUCTOR_ID];
    if (!handler) {
      handler = this._handleUpdate.bind(this);
    }
    handler(message);
  }

  /**
   * Pops the states known to match the given ID from pending messages.
   * This method should be used when the response isn't specific.
   * @param msgId
   * @returns {*[]}
   * @private
   */
  _popStates(msgId) {
    const state = this._pendingState.getAndDelete(msgId);
    if (state) {
      return [state];
    }
    const toPop = [];
    for (const pendingState of this._pendingState.values()) {
      if (pendingState.containerId?.equals(msgId)) {
        toPop.push(pendingState.msgId);
      }
    }
    if (toPop.length) {
      const temp = [];
      for (const x of toPop) {
        temp.push(this._pendingState.getAndDelete(x));
      }
      return temp;
    }
    for (const ack of this._lastAcks) {
      if (ack.msgId === msgId) {
        return [ack];
      }
    }
    return [];
  }

  /**
   * Handles the result for Remote Procedure Calls:
   * rpc_result#f35c6d01 req_msg_id:long result:bytes = RpcResult;
   * This is where the future results for sent requests are set.
   * @param message
   * @returns {Promise<void>}
   * @private
   */
  _handleRPCResult(message) {
    const result = message.obj;
    const state = this._pendingState.getAndDelete(result.reqMsgId);
    this._log.debug(`Handling RPC result for message ${result.reqMsgId}`);
    if (!state) {
      // TODO We should not get responses to things we never sent
      // However receiving a File() with empty bytes is "common".
      // See #658, #759 and #958. They seem to happen in a container
      // which contain the real response right after.
      try {
        const reader = new _extensions__WEBPACK_IMPORTED_MODULE_1__.BinaryReader(result.body);
        if (!(reader.tgReadObject() instanceof _tl__WEBPACK_IMPORTED_MODULE_2__.Api.upload.File)) {
          throw new _errors_Common__WEBPACK_IMPORTED_MODULE_8__.TypeNotFoundError(0, Buffer.alloc(0));
        }
      } catch (e) {
        if (e instanceof _errors_Common__WEBPACK_IMPORTED_MODULE_8__.TypeNotFoundError) {
          this._log.info(`Received response without parent request: ${result.body}`);
          return;
        } else if (this._isFallback) {
          // If we're using HTTP transport, there might be a chance that the response comes through
          // multiple times if didn't send acknowledgment in time, so we should just ignore it
          return;
        }
        throw e;
      }
      return;
    }
    if (result.error) {
      const error = (0,_errors__WEBPACK_IMPORTED_MODULE_0__.RPCMessageToError)(result.error, state.request);
      this._sendQueue.append(new _RequestState__WEBPACK_IMPORTED_MODULE_15__["default"](new _tl__WEBPACK_IMPORTED_MODULE_2__.Api.MsgsAck({
        msgIds: [state.msgId]
      })));
      state.reject?.(error);
      throw error;
    } else {
      try {
        const reader = new _extensions__WEBPACK_IMPORTED_MODULE_1__.BinaryReader(result.body);
        const read = state.request.readResult(reader);
        this.logWithIndex.debug('Handling RPC result', read);
        state.resolve?.(read);
      } catch (err) {
        state.reject?.(err);
        throw err;
      }
    }
  }

  /**
   * Processes the inner messages of a container with many of them:
   * msg_container#73f1f8dc messages:vector<%Message> = MessageContainer;
   * @param message
   * @returns {Promise<void>}
   * @private
   */
  async _handleContainer(message) {
    this._log.debug('Handling container');
    for (const innerMessage of message.obj.messages) {
      await this._processMessage(innerMessage);
    }
  }

  /**
   * Unpacks the data from a gzipped object and processes it:
   * gzip_packed#3072cfa1 packed_data:bytes = Object;
   * @param message
   * @returns {Promise<void>}
   * @private
   */
  async _handleGzipPacked(message) {
    this._log.debug('Handling gzipped data');
    const reader = new _extensions__WEBPACK_IMPORTED_MODULE_1__.BinaryReader(message.obj.data);
    message.obj = reader.tgReadObject();
    await this._processMessage(message);
  }
  _handleUpdate(message) {
    if (message.obj.SUBCLASS_OF_ID !== 0x8af52aac) {
      // crc32(b'Updates')
      this._log.warn(`Note: ${message.obj.className} is not an update, not dispatching it`);
      return;
    }
    this._log.debug(`Handling update ${message.obj.className}`);
    if (!this._isExported) {
      this._updateCallback?.(message.obj);
    }
  }

  /**
   * Handles pong results, which don't come inside a ``RPCResult``
   * but are still sent through a request:
   * pong#347773c5 msg_id:long ping_id:long = Pong;
   * @param message
   * @returns {Promise<void>}
   * @private
   */
  _handlePong(message) {
    const pong = message.obj;
    const newTimeOffset = this._state.updateTimeOffset(message.msgId);
    if (!this._isExported) {
      this._updateCallback?.(new _updates__WEBPACK_IMPORTED_MODULE_6__.UpdateServerTimeOffset(newTimeOffset));
    }
    this._log.debug(`Handling pong for message ${pong.msgId}`);
    const state = this._pendingState.getAndDelete(pong.msgId);

    // Todo Check result
    if (state) {
      state.resolve?.(pong);
    }
  }

  /**
   * Corrects the currently used server salt to use the right value
   * before enqueuing the rejected message to be re-sent:
   * bad_server_salt#edab447b bad_msg_id:long bad_msg_seqno:int
   * error_code:int new_server_salt:long = BadMsgNotification;
   * @param message
   * @returns {Promise<void>}
   * @private
   */
  _handleBadServerSalt(message) {
    const badSalt = message.obj;
    this._log.debug(`Handling bad salt for message ${badSalt.badMsgId}`);
    this._state.salt = badSalt.newServerSalt;
    const states = this._popStates(badSalt.badMsgId);
    this._sendQueue.extend(states);
    this._log.debug(`${states.length} message(s) will be resent`);
  }

  /**
   * Adjusts the current state to be correct based on the
   * received bad message notification whenever possible:
   * bad_msg_notification#a7eff811 bad_msg_id:long bad_msg_seqno:int
   * error_code:int = BadMsgNotification;
   * @param message
   * @returns {Promise<void>}
   * @private
   */
  _handleBadNotification(message) {
    const badMsg = message.obj;
    const states = this._popStates(badMsg.badMsgId);
    this._log.debug(`Handling bad msg ${JSON.stringify(badMsg)}`);
    if ([16, 17].includes(badMsg.errorCode)) {
      // Sent msg_id too low or too high (respectively).
      // Use the current msg_id to determine the right time offset.
      const newTimeOffset = this._state.updateTimeOffset(message.msgId);
      if (!this._isExported) {
        this._updateCallback?.(new _updates__WEBPACK_IMPORTED_MODULE_6__.UpdateServerTimeOffset(newTimeOffset));
      }
      this._log.info(`System clock is wrong, set time offset to ${newTimeOffset}s`);
    } else if (badMsg.errorCode === 32) {
      // msg_seqno too low, so just pump it up by some "large" amount
      // TODO A better fix would be to start with a new fresh session ID
      this._state._sequence += 64;
    } else if (badMsg.errorCode === 33) {
      // msg_seqno too high never seems to happen but just in case
      this._state._sequence -= 16;
    } else {
      for (const state of states) {
        state.reject(new _errors_Common__WEBPACK_IMPORTED_MODULE_8__.BadMessageError(state.request, badMsg.errorCode));
      }
      return;
    }
    // Messages are to be re-sent once we've corrected the issue
    this._sendQueue.extend(states);
    this._log.debug(`${states.length} messages will be resent due to bad msg`);
  }

  /**
   * Updates the current status with the received detailed information:
   * msg_detailed_info#276d3ec6 msg_id:long answer_msg_id:long
   * bytes:int status:int = MsgDetailedInfo;
   * @param message
   * @returns {Promise<void>}
   * @private
   */
  _handleDetailedInfo(message) {
    // TODO https://goo.gl/VvpCC6
    const msgId = message.obj.answerMsgId;
    this._log.debug(`Handling detailed info for message ${msgId}`);
    this._pendingAck.add(msgId);
  }

  /**
   * Updates the current status with the received detailed information:
   * msg_new_detailed_info#809db6df answer_msg_id:long
   * bytes:int status:int = MsgDetailedInfo;
   * @param message
   * @returns {Promise<void>}
   * @private
   */
  _handleNewDetailedInfo(message) {
    // TODO https://goo.gl/VvpCC6
    const msgId = message.obj.answerMsgId;
    this._log.debug(`Handling new detailed info for message ${msgId}`);
    this._pendingAck.add(msgId);
  }

  /**
   * Updates the current status with the received session information:
   * new_session_created#9ec20908 first_msg_id:long unique_id:long
   * server_salt:long = NewSession;
   * @param message
   * @returns {Promise<void>}
   * @private
   */
  _handleNewSessionCreated(message) {
    // TODO https://goo.gl/LMyN7A
    this._log.debug('Handling new session created');
    this._state.salt = message.obj.serverSalt;
  }

  /**
   * Handles a server acknowledge about our messages. Normally these can be ignored
  */
  _handleAck() {}

  /**
   * Handles future salt results, which don't come inside a
   * ``rpc_result`` but are still sent through a request:
   *     future_salts#ae500895 req_msg_id:long now:int
   *     salts:vector<future_salt> = FutureSalts;
   * @param message
   * @returns {Promise<void>}
   * @private
   */
  _handleFutureSalts(message) {
    // TODO save these salts and automatically adjust to the
    // correct one whenever the salt in use expires.
    this._log.debug(`Handling future salts for message ${message.msgId.toString()}`);
    const state = this._pendingState.getAndDelete(message.msgId);
    if (state) {
      state.resolve?.(message.obj);
    }
  }

  /**
   * Handles both :tl:`MsgsStateReq` and :tl:`MsgResendReq` by
   * enqueuing a :tl:`MsgsStateInfo` to be sent at a later point.
   * @param message
   * @returns {Promise<void>}
   * @private
   */
  _handleStateForgotten(message) {
    this._sendQueue.append(new _RequestState__WEBPACK_IMPORTED_MODULE_15__["default"](new _tl__WEBPACK_IMPORTED_MODULE_2__.Api.MsgsStateInfo({
      reqMsgId: message.msgId,
      info: String.fromCharCode(1).repeat(message.obj.msgIds)
    })));
  }

  /**
   * Handles :tl:`MsgsAllInfo` by doing nothing (yet).
   * used as part of the telegram protocol https://core.telegram.org/mtproto/service_messages_about_messages
   * This message does not require an acknowledgment.
   * @param message
   * @returns {Promise<void>}
   * @private
   */

  _handleMsgAll(message) {}
  reconnect() {
    if (this._userConnected && !this.isReconnecting) {
      this.isReconnecting = true;
      // TODO Should we set this?
      // this._user_connected = false
      // we want to wait a second between each reconnect try to not flood the server with reconnects
      // in case of internal server issues.
      (0,_Helpers__WEBPACK_IMPORTED_MODULE_10__.sleep)(1000).then(() => {
        this.logWithIndex.log('Reconnecting...');
        this._log.info('Started reconnecting');
        this._reconnect();
      });
    }
  }
  async _reconnect() {
    const currentConnection = this._connection;
    const currentFallbackConnection = this._fallbackConnection;
    this._log.debug('Closing current connection...');
    try {
      this.logWithIndex.warn('[Reconnect] Closing current connection...');
      if (currentConnection) this._disconnect(currentConnection);
      if (currentFallbackConnection) this._disconnect(currentFallbackConnection);
    } catch (err) {
      this._log.warn(err);
    }
    this._sendQueue.append(undefined);
    this._state.reset();

    // For some reason reusing existing connection caused stuck requests
    // @ts-expect-error -- Hacky way to create new class instance
    const newConnection = new currentConnection.constructor({
      ip: currentConnection._ip,
      port: currentConnection._port,
      dcId: currentConnection._dcId,
      loggers: currentConnection._log,
      isTestServer: currentConnection._isTestServer,
      isPremium: currentConnection._isPremium
    });
    // @ts-expect-error -- Hacky way to create new class instance
    const newFallbackConnection = new this._fallbackConnection.constructor({
      ip: currentConnection._ip,
      port: currentConnection._port,
      dcId: currentConnection._dcId,
      loggers: currentConnection._log,
      isTestServer: currentConnection._isTestServer,
      isPremium: currentConnection._isPremium
    });
    await this.connect(newConnection, true, newFallbackConnection);
    this.isReconnecting = false;
    this._sendQueue.prepend(this._pendingState.values());
    this._pendingState.clear();
    if (this._autoReconnectCallback) {
      await this._autoReconnectCallback();
    }
  }
}

/***/ }),

/***/ "./src/lib/gramjs/network/MTProtoState.ts":
/*!************************************************!*\
  !*** ./src/lib/gramjs/network/MTProtoState.ts ***!
  \************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ MTProtoState)
/* harmony export */ });
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! big-integer */ "./node_modules/big-integer/BigInteger.js");
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(big_integer__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _crypto_CTR__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../crypto/CTR */ "./src/lib/gramjs/crypto/CTR.ts");
/* harmony import */ var _crypto_IGE__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../crypto/IGE */ "./src/lib/gramjs/crypto/IGE.ts");
/* harmony import */ var _extensions__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../extensions */ "./src/lib/gramjs/extensions/index.ts");
/* harmony import */ var _tl__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../tl */ "./src/lib/gramjs/tl/index.ts");
/* harmony import */ var _tl_core__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../tl/core */ "./src/lib/gramjs/tl/core/index.ts");
/* harmony import */ var _tl_core_GZIPPacked__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../tl/core/GZIPPacked */ "./src/lib/gramjs/tl/core/GZIPPacked.ts");
/* harmony import */ var _errors_Common__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../errors/Common */ "./src/lib/gramjs/errors/Common.ts");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];









class MTProtoState {
  /**
   *
   `telethon.network.mtprotosender.MTProtoSender` needs to hold a state
   in order to be able to encrypt and decrypt incoming/outgoing messages,
   as well as generating the message IDs. Instances of this class hold
   together all the required information.
    It doesn't make sense to use `telethon.sessions.abstract.Session` for
   the sender because the sender should *not* be concerned about storing
   this information to disk, as one may create as many senders as they
   desire to any other data center, or some CDN. Using the same session
   for all these is not a good idea as each need their own authkey, and
   the concept of "copying" sessions with the unnecessary entities or
   updates state for these connections doesn't make sense.
    While it would be possible to have a `MTProtoPlainState` that does no
   encryption so that it was usable through the `MTProtoLayer` and thus
   avoid the need for a `MTProtoPlainSender`, the `MTProtoLayer` is more
   focused to efficiency and this state is also more advanced (since it
   supports gzipping and invoking after other message IDs). There are too
   many methods that would be needed to make it convenient to use for the
   authentication process, at which point the `MTProtoPlainSender` is better
   * @param authKey
   * @param loggers
   * @param isCall
   * @param isOutgoing
   */
  constructor(authKey, loggers, isCall = false, isOutgoing = false) {
    this.authKey = authKey;
    this._log = loggers;
    this._isCall = isCall;
    this._isOutgoing = isOutgoing;
    this.timeOffset = 0;
    this.salt = (big_integer__WEBPACK_IMPORTED_MODULE_0___default().zero);
    this.id = (big_integer__WEBPACK_IMPORTED_MODULE_0___default().zero);
    this._sequence = 0;
    this._lastMsgId = (big_integer__WEBPACK_IMPORTED_MODULE_0___default().zero);
    this.msgIds = [];
    this.reset();
  }

  /**
   * Resets the state
   */
  reset() {
    // Session IDs can be random on every connection
    this.id = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.generateRandomLong)(true);
    this._sequence = 0;
    this._lastMsgId = big_integer__WEBPACK_IMPORTED_MODULE_0___default()(0);
    this.msgIds = [];
  }

  /**
   * Updates the message ID to a new one,
   * used when the time offset changed.
   * @param message
   */
  updateMessageId(message) {
    message.msgId = this._getNewMsgId();
  }

  /**
   * Calculate the key based on Telegram guidelines, specifying whether it's the client or not
   * @param authKey
   * @param msgKey
   * @param client
   * @returns {{iv: Buffer, key: Buffer}}
   */
  async _calcKey(authKey, msgKey, client) {
    const x = this._isCall ? 128 + (this._isOutgoing !== client ? 8 : 0) : client ? 0 : 8;
    const [sha256a, sha256b] = await Promise.all([(0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.sha256)(Buffer.concat([msgKey, authKey.slice(x, x + 36)])), (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.sha256)(Buffer.concat([authKey.slice(x + 40, x + 76), msgKey]))]);
    const key = Buffer.concat([sha256a.slice(0, 8), sha256b.slice(8, 24), sha256a.slice(24, 32)]);
    if (this._isCall) {
      const iv = Buffer.concat([sha256b.slice(0, 4), sha256a.slice(8, 16), sha256b.slice(24, 28)]);
      return {
        key,
        iv
      };
    }
    const iv = Buffer.concat([sha256b.slice(0, 8), sha256a.slice(8, 24), sha256b.slice(24, 32)]);
    return {
      key,
      iv
    };
  }

  /**
   * Writes a message containing the given data into buffer.
   * Returns the message id.
   * @param buffer
   * @param data
   * @param contentRelated
   * @param afterId
   */
  async writeDataAsMessage(buffer, data, contentRelated, afterId) {
    const msgId = this._getNewMsgId();
    const seqNo = this._getSeqNo(contentRelated);
    let body;
    if (!afterId) {
      body = await _tl_core_GZIPPacked__WEBPACK_IMPORTED_MODULE_6__["default"].gzipIfSmaller(contentRelated, data);
    } else {
      // Invoke query expects a query with a getBytes func
      body = await _tl_core_GZIPPacked__WEBPACK_IMPORTED_MODULE_6__["default"].gzipIfSmaller(contentRelated, new _tl__WEBPACK_IMPORTED_MODULE_4__.Api.InvokeAfterMsg({
        msgId: afterId,
        query: {
          getBytes() {
            return data;
          }
        }
      }).getBytes());
    }
    const s = Buffer.alloc(4);
    s.writeInt32LE(seqNo, 0);
    const b = Buffer.alloc(4);
    b.writeInt32LE(body.length, 0);
    const m = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.toSignedLittleBuffer)(msgId, 8);
    buffer.write(Buffer.concat([m, s, b]));
    buffer.write(body);
    return msgId;
  }

  /**
   * Encrypts the given message data using the current authorization key
   * following MTProto 2.0 guidelines core.telegram.org/mtproto/description.
   * @param data
   */
  async encryptMessageData(data) {
    if (!this.authKey) {
      throw new Error('Auth key unset');
    }
    await this.authKey.waitForKey();
    const authKey = this.authKey.getKey();
    if (!authKey) {
      throw new Error('Auth key unset');
    }
    if (!this.salt || !this.id || !authKey || !this.authKey.keyId) {
      throw new Error('Unset params');
    }
    if (this._isCall) {
      const x = 128 + (this._isOutgoing ? 0 : 8);
      const lengthStart = data.length;
      data = Buffer.from(data);
      if (lengthStart % 4 !== 0) {
        data = Buffer.concat([data, Buffer.from(new Array(4 - lengthStart % 4).fill(0x20))]);
      }
      const msgKeyLarge = await (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.sha256)(Buffer.concat([authKey.slice(88 + x, 88 + x + 32), Buffer.from(data)]));
      const msgKey = msgKeyLarge.slice(8, 24);
      const {
        iv,
        key
      } = await this._calcKey(authKey, msgKey, true);
      data = new _crypto_CTR__WEBPACK_IMPORTED_MODULE_1__.CTR(key, iv).encrypt(data);
      // data = data.slice(0, lengthStart)
      return Buffer.concat([msgKey, data]);
    } else {
      const s = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.toSignedLittleBuffer)(this.salt, 8);
      const i = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.toSignedLittleBuffer)(this.id, 8);
      data = Buffer.concat([Buffer.concat([s, i]), data]);
      const padding = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.generateRandomBytes)((0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.mod)(-(data.length + 12), 16) + 12);
      // Being substr(what, offset, length); x = 0 for client
      // "msg_key_large = SHA256(substr(auth_key, 88+x, 32) + pt + padding)"
      const msgKeyLarge = await (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.sha256)(Buffer.concat([authKey.slice(88, 88 + 32), data, padding]));
      // "msg_key = substr (msg_key_large, 8, 16)"
      const msgKey = msgKeyLarge.slice(8, 24);
      const {
        iv,
        key
      } = await this._calcKey(authKey, msgKey, true);
      const keyId = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.readBufferFromBigInt)(this.authKey.keyId, 8);
      return Buffer.concat([keyId, msgKey, new _crypto_IGE__WEBPACK_IMPORTED_MODULE_2__.IGE(key, iv).encryptIge(Buffer.concat([data, padding]))]);
    }
  }

  /**
   * Inverse of `encrypt_message_data` for incoming server messages.
   * @param body
   */
  async decryptMessageData(body) {
    if (!this.authKey) {
      throw new Error('Auth key unset');
    }
    if (body.length < 8) {
      throw new _errors_Common__WEBPACK_IMPORTED_MODULE_7__.InvalidBufferError(body);
    }
    if (body.length < 0) {
      // length needs to be positive
      throw new _errors_Common__WEBPACK_IMPORTED_MODULE_7__.SecurityError('Server replied with negative length');
    }
    if (body.length % 4 !== 0 && !this._isCall) {
      throw new _errors_Common__WEBPACK_IMPORTED_MODULE_7__.SecurityError('Server replied with length not divisible by 4');
    }
    // TODO Check salt,sessionId, and sequenceNumber
    if (!this._isCall) {
      const keyId = (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.readBigIntFromBuffer)(body.slice(0, 8));
      if (!this.authKey.keyId || keyId.neq(this.authKey.keyId)) {
        throw new _errors_Common__WEBPACK_IMPORTED_MODULE_7__.SecurityError('Server replied with an invalid auth key');
      }
    }
    const authKey = this.authKey.getKey();
    if (!authKey) {
      throw new _errors_Common__WEBPACK_IMPORTED_MODULE_7__.SecurityError('Unset AuthKey');
    }
    const msgKey = this._isCall ? body.slice(0, 16) : body.slice(8, 24);
    const x = this._isCall ? 128 + (this._isOutgoing ? 8 : 0) : 0;
    const {
      iv,
      key
    } = await this._calcKey(authKey, msgKey, false);
    if (this._isCall) {
      body = body.slice(16);
      const lengthStart = body.length;
      body = Buffer.concat([body, Buffer.from(new Array(4 - lengthStart % 4).fill(0))]);
      body = new _crypto_CTR__WEBPACK_IMPORTED_MODULE_1__.CTR(key, iv).decrypt(body);
      body = body.slice(0, lengthStart);
    } else {
      body = new _crypto_IGE__WEBPACK_IMPORTED_MODULE_2__.IGE(key, iv).decryptIge(this._isCall ? body.slice(16) : body.slice(24));
    }
    // https://core.telegram.org/mtproto/security_guidelines
    // Sections "checking sha256 hash" and "message length"

    const ourKey = this._isCall ? await (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.sha256)(Buffer.concat([authKey.slice(88 + x, 88 + x + 32), body])) : await (0,_Helpers__WEBPACK_IMPORTED_MODULE_8__.sha256)(Buffer.concat([authKey.slice(96, 96 + 32), body]));
    if (!this._isCall && !msgKey.equals(ourKey.slice(8, 24))) {
      throw new _errors_Common__WEBPACK_IMPORTED_MODULE_7__.SecurityError('Received msg_key doesn\'t match with expected one');
    }
    const reader = new _extensions__WEBPACK_IMPORTED_MODULE_3__.BinaryReader(body);
    if (this._isCall) {
      // Seq
      reader.readInt(false);
      return reader.read(body.length - 4);
    } else {
      reader.readLong(); // removeSalt
      const serverId = reader.readLong();
      if (!serverId.eq(this.id)) {
        throw new _errors_Common__WEBPACK_IMPORTED_MODULE_7__.SecurityError('Server replied with a wrong session ID');
      }
      const remoteMsgId = reader.readLong();
      // if we get a duplicate message id we should ignore it.
      if (this.msgIds.includes(remoteMsgId.toString())) {
        throw new _errors_Common__WEBPACK_IMPORTED_MODULE_7__.SecurityError('Duplicate msgIds');
      }
      // we only store the latest 500 message ids from the server
      if (this.msgIds.length > 500) {
        this.msgIds.shift();
      }
      const remoteSequence = reader.readInt();
      const containerLen = reader.readInt(); // msgLen for the inner object, padding ignored
      const diff = body.length - containerLen;
      // We want to check if it's between 12 and 1024
      // https://core.telegram.org/mtproto/security_guidelines#checking-message-length
      if (diff < 12 || diff > 1024) {
        throw new _errors_Common__WEBPACK_IMPORTED_MODULE_7__.SecurityError('Server replied with the wrong message padding');
      }

      // We could read msg_len bytes and use those in a new reader to read
      // the next TLObject without including the padding, but since the
      // reader isn't used for anything else after this, it's unnecessary.
      const obj = await reader.tgReadObject();
      // We only check for objects that telegram has returned to us (Updates) not ones we send.
      if (obj?.className?.startsWith('Update')) {
        const now = Math.floor(Date.now() / 1000);
        const msgLocalTime = this.getMsgIdTimeLocal(remoteMsgId);
        if (msgLocalTime && (msgLocalTime - now > 30 || now - msgLocalTime > 300)) {
          // 30 sec in the future or 300 sec in the past
          throw new _errors_Common__WEBPACK_IMPORTED_MODULE_7__.SecurityError('The message time is incorrect.');
        }
      }
      if (obj && !('errorCode' in obj)) {
        this.msgIds.push(remoteMsgId.toString());
      }
      return new _tl_core__WEBPACK_IMPORTED_MODULE_5__.TLMessage(remoteMsgId, remoteSequence, obj);
    }
  }

  /**
   * Generates a new unique message ID based on the current
   * time (in ms) since epoch, applying a known time offset.
   * @private
   */
  _getNewMsgId() {
    const now = Date.now() / 1000 + this.timeOffset;
    const nanoseconds = Math.floor((now - Math.floor(now)) * 1e9);
    let newMsgId = big_integer__WEBPACK_IMPORTED_MODULE_0___default()(Math.floor(now)).shiftLeft(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(32)).or(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(nanoseconds).shiftLeft(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(2)));
    if (this._lastMsgId.greaterOrEquals(newMsgId)) {
      newMsgId = this._lastMsgId.add(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(4));
    }
    this._lastMsgId = newMsgId;
    return newMsgId;
  }

  /**
   * Returns the understood time by the message id (server time + local offset)
   */
  getMsgIdTimeLocal(msgId) {
    if (this._lastMsgId.eq(0)) {
      // this means it's the first message sent/received so don't check yet
      return false;
    }
    return msgId.shiftRight(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(32)).toJSNumber() - this.timeOffset;
  }

  /**
   * Updates the time offset to the correct
   * one given a known valid message ID.
   * @param correctMsgId {BigInteger}
   */
  updateTimeOffset(correctMsgId) {
    const bad = this._getNewMsgId();
    const old = this.timeOffset;
    const now = Math.floor(Date.now() / 1000);
    const correct = correctMsgId.shiftRight(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(32)).toJSNumber();
    this.timeOffset = correct - now;
    if (this.timeOffset !== old) {
      this._lastMsgId = big_integer__WEBPACK_IMPORTED_MODULE_0___default()(0);
      this._log.debug(
      // eslint-disable-next-line @stylistic/max-len
      `Updated time offset (old offset ${old}, bad ${bad.toString()}, good ${correctMsgId.toString()}, new ${this.timeOffset})`);
    }
    return this.timeOffset;
  }

  /**
   * Generates the next sequence number depending on whether
   * it should be for a content-related query or not.
   * @param contentRelated
   * @private
   */
  _getSeqNo(contentRelated) {
    if (contentRelated) {
      const result = this._sequence * 2 + 1;
      this._sequence += 1;
      return result;
    } else {
      return this._sequence * 2;
    }
  }
}

/***/ }),

/***/ "./src/lib/gramjs/network/RequestState.ts":
/*!************************************************!*\
  !*** ./src/lib/gramjs/network/RequestState.ts ***!
  \************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ RequestState)
/* harmony export */ });
/* harmony import */ var _util_Deferred__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../util/Deferred */ "./src/util/Deferred.ts");

class RequestState {
  constructor(request, abortSignal) {
    this.containerId = undefined;
    this.msgId = undefined;
    this.request = request;
    this.data = request.getBytes();
    this.after = undefined;
    this.result = undefined;
    this.abortSignal = abortSignal;
    this.finished = new _util_Deferred__WEBPACK_IMPORTED_MODULE_0__["default"]();
    this.resetPromise();
  }
  isReady() {
    if (!this.after) {
      return true;
    }
    return this.after.finished.promise;
  }
  resetPromise() {
    // Prevent stuck await
    this.reject?.();
    this.promise = new Promise((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
  }
}

/***/ }),

/***/ "./src/lib/gramjs/network/connection/Connection.ts":
/*!*********************************************************!*\
  !*** ./src/lib/gramjs/network/connection/Connection.ts ***!
  \*********************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Connection: () => (/* binding */ Connection),
/* harmony export */   HttpConnection: () => (/* binding */ HttpConnection),
/* harmony export */   ObfuscatedConnection: () => (/* binding */ ObfuscatedConnection),
/* harmony export */   PacketCodec: () => (/* binding */ PacketCodec)
/* harmony export */ });
/* harmony import */ var _extensions__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../extensions */ "./src/lib/gramjs/extensions/index.ts");
/* harmony import */ var _extensions_HttpStream__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../extensions/HttpStream */ "./src/lib/gramjs/extensions/HttpStream.ts");


/**
 * The `Connection` class is a wrapper around ``asyncio.open_connection``.
 *
 * Subclasses will implement different transport modes as atomic operations,
 * which this class eases doing since the exposed interface simply puts and
 * gets complete data payloads to and from queues.
 *
 * The only error that will raise from send and receive methods is
 * ``ConnectionError``, which will raise when attempting to send if
 * the client is disconnected (includes remote disconnections).
 */
class Connection {
  constructor({
    ip,
    port,
    dcId,
    loggers,
    isPremium,
    isTestServer
  }) {
    this._ip = ip;
    this._port = port;
    this._dcId = dcId;
    this._log = loggers;
    this._isTestServer = isTestServer;
    this._isPremium = isPremium;
    this._connected = false;
    this._sendTask = undefined;
    this._recvTask = undefined;
    this._codec = undefined;
    this._obfuscation = undefined; // TcpObfuscated and MTProxy
    this._sendArray = new _extensions__WEBPACK_IMPORTED_MODULE_0__.AsyncQueue();
    this._recvArray = new _extensions__WEBPACK_IMPORTED_MODULE_0__.AsyncQueue();
    // this.socket = new PromiseSocket(new Socket())

    this.shouldLongPoll = false;
    this.socket = new _extensions__WEBPACK_IMPORTED_MODULE_0__.PromisedWebSockets(this.disconnectCallback.bind(this));
  }
  isConnected() {
    return this._connected;
  }
  disconnectCallback() {
    this.disconnect(true);
  }
  async _connect() {
    this._log.debug('Connecting');
    this._codec = new this.PacketCodecClass(this);
    await this.socket.connect(this._port, this._ip, this._isTestServer, this._isPremium);
    this._log.debug('Finished connecting');
    await this._initConn();
  }
  async connect() {
    await this._connect();
    this._connected = true;
    if (!this._sendTask) {
      this._sendTask = this._sendLoop();
    }
    this._recvTask = this._recvLoop();
  }
  disconnect(fromCallback = false) {
    if (!this._connected) {
      return;
    }
    this._connected = false;
    void this._recvArray.push(undefined);
    if (!fromCallback) {
      this.socket.close();
    }
  }
  async send(data) {
    if (!this._connected) {
      throw new Error('Not connected');
    }
    await this._sendArray.push(data);
  }
  async recv() {
    while (this._connected) {
      const result = await this._recvArray.pop();
      // null = sentinel value = keep trying
      if (result) {
        return result;
      }
    }
    throw new Error('Not connected');
  }
  async _sendLoop() {
    // TODO handle errors
    try {
      while (this._connected) {
        const data = await this._sendArray.pop();
        if (!data) {
          this._sendTask = undefined;
          return;
        }
        this._send(data);
      }
    } catch (e) {
      this._log.info('The server closed the connection while sending');
    }
  }
  async _recvLoop() {
    let data;
    while (this._connected) {
      try {
        data = await this._recv();
        if (!data) {
          throw new Error('no data received');
        }
      } catch (e) {
        this._log.info('connection closed');
        // await this._recvArray.push()

        this.disconnect();
        return;
      }
      await this._recvArray.push(data);
    }
  }
  async _initConn() {
    if (this._codec.tag) {
      await this.socket.write(this._codec.tag);
    }
  }
  _send(data) {
    const encodedPacket = this._codec.encodePacket(data);
    this.socket.write(encodedPacket);
  }
  _recv() {
    return this._codec.readPacket(this.socket);
  }
  toString() {
    return `${this._ip}:${this._port}/${this.constructor.name.replace('Connection', '')}`;
  }
}
class ObfuscatedConnection extends Connection {
  ObfuscatedIO = undefined;
  async _initConn() {
    this._obfuscation = new this.ObfuscatedIO(this);
    await this.socket.write(this._obfuscation.header);
  }
  _send(data) {
    this._obfuscation.write(this._codec.encodePacket(data));
  }
  _recv() {
    return this._codec.readPacket(this._obfuscation);
  }
}
class PacketCodec {
  constructor(connection) {
    this._conn = connection;
  }
  encodePacket(data) {
    throw new Error('Not Implemented');

    // Override
  }
  readPacket(reader) {
    // override
    throw new Error('Not Implemented');
  }
}
class HttpConnection extends Connection {
  constructor(params) {
    super(params);
    this.shouldLongPoll = true;
    this.socket = new _extensions_HttpStream__WEBPACK_IMPORTED_MODULE_1__["default"](this.disconnectCallback.bind(this));
    this.href = _extensions_HttpStream__WEBPACK_IMPORTED_MODULE_1__["default"].getURL(this._ip, this._port, this._isTestServer, this._isPremium);
  }
  send(data) {
    return this.socket.write(data);
  }
  recv() {
    return this.socket.read();
  }
  async _connect() {
    this._log.debug('Connecting');
    await this.socket.connect(this._port, this._ip, this._isTestServer, this._isPremium);
    this._log.debug('Finished connecting');
  }
  async connect() {
    await this._connect();
    this._connected = true;
  }
}

/***/ }),

/***/ "./src/lib/gramjs/network/connection/TCPAbridged.ts":
/*!**********************************************************!*\
  !*** ./src/lib/gramjs/network/connection/TCPAbridged.ts ***!
  \**********************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   AbridgedPacketCodec: () => (/* binding */ AbridgedPacketCodec),
/* harmony export */   ConnectionTCPAbridged: () => (/* binding */ ConnectionTCPAbridged)
/* harmony export */ });
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! big-integer */ "./node_modules/big-integer/BigInteger.js");
/* harmony import */ var big_integer__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(big_integer__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* harmony import */ var _Connection__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./Connection */ "./src/lib/gramjs/network/connection/Connection.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];



class AbridgedPacketCodec extends _Connection__WEBPACK_IMPORTED_MODULE_2__.PacketCodec {
  static tag = Buffer.from('ef', 'hex');
  static obfuscateTag = Buffer.from('efefefef', 'hex');
  constructor(props) {
    super(props);
    this.tag = AbridgedPacketCodec.tag;
    this.obfuscateTag = AbridgedPacketCodec.obfuscateTag;
  }
  encodePacket(data) {
    const length = data.length >> 2;
    let temp;
    if (length < 127) {
      const b = Buffer.alloc(1);
      b.writeUInt8(length, 0);
      temp = b;
    } else {
      temp = Buffer.concat([Buffer.from('7f', 'hex'), (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.readBufferFromBigInt)(big_integer__WEBPACK_IMPORTED_MODULE_0___default()(length), 3)]);
    }
    return Buffer.concat([temp, data]);
  }
  async readPacket(reader) {
    const readData = await reader.read(1);
    let length = readData[0];
    if (length >= 127) {
      length = Buffer.concat([await reader.read(3), Buffer.alloc(1)]).readInt32LE(0);
    }
    return reader.read(length << 2);
  }
}

/**
 * This is the mode with the lowest overhead, as it will
 * only require 1 byte if the packet length is less than
 * 508 bytes (127 << 2, which is very common).
 */
class ConnectionTCPAbridged extends _Connection__WEBPACK_IMPORTED_MODULE_2__.Connection {
  PacketCodecClass = AbridgedPacketCodec;
}

/***/ }),

/***/ "./src/lib/gramjs/network/connection/TCPObfuscated.ts":
/*!************************************************************!*\
  !*** ./src/lib/gramjs/network/connection/TCPObfuscated.ts ***!
  \************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ConnectionTCPObfuscated: () => (/* binding */ ConnectionTCPObfuscated)
/* harmony export */ });
/* harmony import */ var _crypto_CTR__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../crypto/CTR */ "./src/lib/gramjs/crypto/CTR.ts");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* harmony import */ var _Connection__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./Connection */ "./src/lib/gramjs/network/connection/Connection.ts");
/* harmony import */ var _TCPAbridged__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./TCPAbridged */ "./src/lib/gramjs/network/connection/TCPAbridged.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];




class ObfuscatedIO {
  header = undefined;
  constructor(connection) {
    this.connection = connection.socket;
    const res = this.initHeader(connection.PacketCodecClass);
    this.header = res.random;
    this._encrypt = res.encryptor;
    this._decrypt = res.decryptor;
  }
  initHeader(packetCodec) {
    // Obfuscated messages secrets cannot start with any of these
    const keywords = [Buffer.from('50567247', 'hex'), Buffer.from('474554', 'hex'), Buffer.from('504f5354', 'hex'), Buffer.from('eeeeeeee', 'hex')];
    let random;
    while (true) {
      random = (0,_Helpers__WEBPACK_IMPORTED_MODULE_1__.generateRandomBytes)(64);
      if (random[0] !== 0xef && !random.slice(4, 8).equals(Buffer.alloc(4))) {
        let ok = true;
        for (const key of keywords) {
          if (key.equals(random.slice(0, 4))) {
            ok = false;
            break;
          }
        }
        if (ok) {
          break;
        }
      }
    }
    random = random.toJSON().data;
    const randomReversed = Buffer.from(random.slice(8, 56)).reverse();
    // Encryption has "continuous buffer" enabled
    const encryptKey = Buffer.from(random.slice(8, 40));
    const encryptIv = Buffer.from(random.slice(40, 56));
    const decryptKey = Buffer.from(randomReversed.slice(0, 32));
    const decryptIv = Buffer.from(randomReversed.slice(32, 48));
    const encryptor = new _crypto_CTR__WEBPACK_IMPORTED_MODULE_0__.CTR(encryptKey, encryptIv);
    const decryptor = new _crypto_CTR__WEBPACK_IMPORTED_MODULE_0__.CTR(decryptKey, decryptIv);
    random = Buffer.concat([Buffer.from(random.slice(0, 56)), packetCodec.obfuscateTag, Buffer.from(random.slice(60))]);
    random = Buffer.concat([Buffer.from(random.slice(0, 56)), Buffer.from(encryptor.encrypt(random).slice(56, 64)), Buffer.from(random.slice(64))]);
    return {
      random,
      encryptor,
      decryptor
    };
  }
  async read(n) {
    const data = await this.connection.readExactly(n);
    return this._decrypt.encrypt(data);
  }
  write(data) {
    this.connection.write(this._encrypt.encrypt(data));
  }
}
class ConnectionTCPObfuscated extends _Connection__WEBPACK_IMPORTED_MODULE_2__.ObfuscatedConnection {
  ObfuscatedIO = ObfuscatedIO;
  PacketCodecClass = _TCPAbridged__WEBPACK_IMPORTED_MODULE_3__.AbridgedPacketCodec;
}

/***/ }),

/***/ "./src/lib/gramjs/network/connection/index.ts":
/*!****************************************************!*\
  !*** ./src/lib/gramjs/network/connection/index.ts ***!
  \****************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Connection: () => (/* reexport safe */ _Connection__WEBPACK_IMPORTED_MODULE_0__.Connection),
/* harmony export */   ConnectionTCPAbridged: () => (/* reexport safe */ _TCPAbridged__WEBPACK_IMPORTED_MODULE_1__.ConnectionTCPAbridged),
/* harmony export */   ConnectionTCPObfuscated: () => (/* reexport safe */ _TCPObfuscated__WEBPACK_IMPORTED_MODULE_2__.ConnectionTCPObfuscated),
/* harmony export */   HttpConnection: () => (/* reexport safe */ _Connection__WEBPACK_IMPORTED_MODULE_0__.HttpConnection)
/* harmony export */ });
/* harmony import */ var _Connection__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./Connection */ "./src/lib/gramjs/network/connection/Connection.ts");
/* harmony import */ var _TCPAbridged__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./TCPAbridged */ "./src/lib/gramjs/network/connection/TCPAbridged.ts");
/* harmony import */ var _TCPObfuscated__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./TCPObfuscated */ "./src/lib/gramjs/network/connection/TCPObfuscated.ts");




/***/ }),

/***/ "./src/lib/gramjs/network/index.ts":
/*!*****************************************!*\
  !*** ./src/lib/gramjs/network/index.ts ***!
  \*****************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Connection: () => (/* reexport safe */ _connection__WEBPACK_IMPORTED_MODULE_0__.Connection),
/* harmony export */   ConnectionTCPAbridged: () => (/* reexport safe */ _connection__WEBPACK_IMPORTED_MODULE_0__.ConnectionTCPAbridged),
/* harmony export */   ConnectionTCPObfuscated: () => (/* reexport safe */ _connection__WEBPACK_IMPORTED_MODULE_0__.ConnectionTCPObfuscated),
/* harmony export */   HttpConnection: () => (/* reexport safe */ _connection__WEBPACK_IMPORTED_MODULE_0__.HttpConnection),
/* harmony export */   MTProtoPlainSender: () => (/* reexport safe */ _MTProtoPlainSender__WEBPACK_IMPORTED_MODULE_2__["default"]),
/* harmony export */   MTProtoSender: () => (/* reexport safe */ _MTProtoSender__WEBPACK_IMPORTED_MODULE_3__["default"]),
/* harmony export */   UpdateConnectionState: () => (/* reexport safe */ _updates__WEBPACK_IMPORTED_MODULE_1__.UpdateConnectionState),
/* harmony export */   UpdateServerTimeOffset: () => (/* reexport safe */ _updates__WEBPACK_IMPORTED_MODULE_1__.UpdateServerTimeOffset)
/* harmony export */ });
/* harmony import */ var _connection__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./connection */ "./src/lib/gramjs/network/connection/index.ts");
/* harmony import */ var _updates__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./updates */ "./src/lib/gramjs/network/updates.ts");
/* harmony import */ var _MTProtoPlainSender__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./MTProtoPlainSender */ "./src/lib/gramjs/network/MTProtoPlainSender.ts");
/* harmony import */ var _MTProtoSender__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./MTProtoSender */ "./src/lib/gramjs/network/MTProtoSender.ts");






/***/ }),

/***/ "./src/lib/gramjs/network/updates.ts":
/*!*******************************************!*\
  !*** ./src/lib/gramjs/network/updates.ts ***!
  \*******************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   UpdateConnectionState: () => (/* binding */ UpdateConnectionState),
/* harmony export */   UpdateServerTimeOffset: () => (/* binding */ UpdateServerTimeOffset)
/* harmony export */ });
class UpdateConnectionState {
  static disconnected = -1;
  static connected = 1;
  static broken = 0;
  constructor(state) {
    this.state = state;
  }
}
class UpdateServerTimeOffset {
  constructor(timeOffset) {
    this.timeOffset = timeOffset;
  }
}

/***/ }),

/***/ "./src/lib/gramjs/sessions/Abstract.ts":
/*!*********************************************!*\
  !*** ./src/lib/gramjs/sessions/Abstract.ts ***!
  \*********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ Session)
/* harmony export */ });
class Session {}

/***/ }),

/***/ "./src/lib/gramjs/sessions/CallbackSession.ts":
/*!****************************************************!*\
  !*** ./src/lib/gramjs/sessions/CallbackSession.ts ***!
  \****************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ CallbackSession)
/* harmony export */ });
/* harmony import */ var _crypto_AuthKey__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../crypto/AuthKey */ "./src/lib/gramjs/crypto/AuthKey.ts");
/* harmony import */ var _Utils__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../Utils */ "./src/lib/gramjs/Utils.ts");
/* harmony import */ var _Memory__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./Memory */ "./src/lib/gramjs/sessions/Memory.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];



class CallbackSession extends _Memory__WEBPACK_IMPORTED_MODULE_2__["default"] {
  constructor(sessionData, callback) {
    super();
    this._sessionData = sessionData;
    this._callback = callback;
    this._authKeys = {};
  }
  async load() {
    if (!this._sessionData) {
      return;
    }
    const {
      mainDcId,
      keys,
      isTest
    } = this._sessionData;
    const {
      ipAddress,
      port
    } = (0,_Utils__WEBPACK_IMPORTED_MODULE_1__.getDC)(mainDcId);
    this.setDC(mainDcId, ipAddress, port, isTest, true);
    await Promise.all(Object.keys(keys).map(async dcIdStr => {
      const dcId = Number(dcIdStr);
      const key = Buffer.from(keys[dcId], 'hex');
      this._authKeys[dcId] = new _crypto_AuthKey__WEBPACK_IMPORTED_MODULE_0__.AuthKey();
      await this._authKeys[dcId].setKey(key);
    }));
  }
  setDC(dcId, serverAddress, port, isTestServer, skipOnUpdate = false) {
    this._dcId = dcId;
    this._serverAddress = serverAddress;
    this._port = port;
    this._isTestServer = isTestServer;
    delete this._authKeys[dcId];
    if (!skipOnUpdate) {
      void this._onUpdate();
    }
  }
  getAuthKey(dcId = this._dcId) {
    return this._authKeys[dcId];
  }
  setAuthKey(authKey, dcId = this._dcId) {
    this._authKeys[dcId] = authKey;
    void this._onUpdate();
  }
  getSessionData() {
    const sessionData = {
      mainDcId: this._dcId,
      keys: {},
      isTest: this._isTestServer || undefined
    };
    Object.keys(this._authKeys).forEach(dcIdStr => {
      const dcId = Number(dcIdStr);
      const authKey = this._authKeys[dcId];
      if (!authKey?._key) return;
      sessionData.keys[dcId] = authKey._key.toString('hex');
    });
    return sessionData;
  }
  _onUpdate() {
    this._callback(this.getSessionData());
  }
  delete() {
    this._callback(undefined);
  }
}

/***/ }),

/***/ "./src/lib/gramjs/sessions/Memory.ts":
/*!*******************************************!*\
  !*** ./src/lib/gramjs/sessions/Memory.ts ***!
  \*******************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ MemorySession)
/* harmony export */ });
/* harmony import */ var _crypto_AuthKey__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../crypto/AuthKey */ "./src/lib/gramjs/crypto/AuthKey.ts");
/* harmony import */ var _Abstract__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./Abstract */ "./src/lib/gramjs/sessions/Abstract.ts");



// Dummy implementation
class MemorySession extends _Abstract__WEBPACK_IMPORTED_MODULE_1__["default"] {
  constructor() {
    super();
    this._serverAddress = undefined;
    this._dcId = 0;
    this._port = undefined;
    this._takeoutId = undefined;
    this._isTestServer = false;
    this._entities = new Set();
  }
  get dcId() {
    return this._dcId;
  }
  get serverAddress() {
    return this._serverAddress;
  }
  get port() {
    return this._port;
  }
  get isTestServer() {
    return this._isTestServer;
  }
  setDC(dcId, serverAddress, port, isTestServer) {
    this._dcId = dcId | 0;
    this._serverAddress = serverAddress;
    this._port = port;
    this._isTestServer = isTestServer;
  }
  getAuthKey(dcId) {
    return new _crypto_AuthKey__WEBPACK_IMPORTED_MODULE_0__.AuthKey();
  }
  setAuthKey(authKey, dcId) {}
  async load() {}
  save() {}
  delete() {}
}

/***/ }),

/***/ "./src/lib/gramjs/sessions/index.ts":
/*!******************************************!*\
  !*** ./src/lib/gramjs/sessions/index.ts ***!
  \******************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   CallbackSession: () => (/* reexport safe */ _CallbackSession__WEBPACK_IMPORTED_MODULE_0__["default"]),
/* harmony export */   MemorySession: () => (/* reexport safe */ _Memory__WEBPACK_IMPORTED_MODULE_1__["default"])
/* harmony export */ });
/* harmony import */ var _CallbackSession__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./CallbackSession */ "./src/lib/gramjs/sessions/CallbackSession.ts");
/* harmony import */ var _Memory__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./Memory */ "./src/lib/gramjs/sessions/Memory.ts");




/***/ }),

/***/ "./src/lib/gramjs/tl/AllTLObjects.ts":
/*!*******************************************!*\
  !*** ./src/lib/gramjs/tl/AllTLObjects.ts ***!
  \*******************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   LAYER: () => (/* binding */ LAYER),
/* harmony export */   tlobjects: () => (/* binding */ tlobjects)
/* harmony export */ });
/* harmony import */ var ___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! . */ "./src/lib/gramjs/tl/index.ts");

const tlobjects = {};
for (const tl of Object.values(___WEBPACK_IMPORTED_MODULE_0__.Api)) {
  if ('CONSTRUCTOR_ID' in tl) {
    tlobjects[tl.CONSTRUCTOR_ID] = tl;
  } else {
    for (const sub of Object.values(tl)) {
      tlobjects[sub.CONSTRUCTOR_ID] = sub;
    }
  }
}
const LAYER = 212;


/***/ }),

/***/ "./src/lib/gramjs/tl/api.js":
/*!**********************************!*\
  !*** ./src/lib/gramjs/tl/api.js ***!
  \**********************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var _apiHelpers_ts__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./apiHelpers.ts */ "./src/lib/gramjs/tl/apiHelpers.ts");

const Api = (0,_apiHelpers_ts__WEBPACK_IMPORTED_MODULE_0__.buildApiFromTlSchema)();
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (Api);

/***/ }),

/***/ "./src/lib/gramjs/tl/apiHelpers.ts":
/*!*****************************************!*\
  !*** ./src/lib/gramjs/tl/apiHelpers.ts ***!
  \*****************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   buildApiFromTlSchema: () => (/* binding */ buildApiFromTlSchema)
/* harmony export */ });
/* harmony import */ var _apiTl__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./apiTl */ "./src/lib/gramjs/tl/apiTl.ts");
/* harmony import */ var _generationHelpers__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./generationHelpers */ "./src/lib/gramjs/tl/generationHelpers.ts");
/* harmony import */ var _schemaTl__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./schemaTl */ "./src/lib/gramjs/tl/schemaTl.ts");
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];





// eslint-disable-next-line no-restricted-globals
const CACHING_SUPPORTED = typeof self !== 'undefined' && self.localStorage !== undefined;
const CACHE_KEY = 'GramJs:apiCache';
function buildApiFromTlSchema() {
  let definitions;
  const fromCache = CACHING_SUPPORTED && loadFromCache();
  if (fromCache) {
    definitions = fromCache;
  } else {
    definitions = loadFromTlSchemas();
    if (CACHING_SUPPORTED) {
      localStorage.setItem(CACHE_KEY, JSON.stringify(definitions));
    }
  }
  return mergeWithNamespaces(createClasses('constructor', definitions.constructors), createClasses('request', definitions.requests));
}
function loadFromCache() {
  const jsonCache = localStorage.getItem(CACHE_KEY);
  return jsonCache && JSON.parse(jsonCache);
}
function loadFromTlSchemas() {
  const [constructorParamsApi, functionParamsApi] = extractParams(_apiTl__WEBPACK_IMPORTED_MODULE_0__["default"]);
  const [constructorParamsSchema, functionParamsSchema] = extractParams(_schemaTl__WEBPACK_IMPORTED_MODULE_2__["default"]);
  const constructors = [].concat(constructorParamsApi, constructorParamsSchema);
  const requests = [].concat(functionParamsApi, functionParamsSchema);
  return {
    constructors,
    requests
  };
}
function mergeWithNamespaces(obj1, obj2) {
  const result = {
    ...obj1
  };
  Object.keys(obj2).forEach(key => {
    if (typeof obj2[key] === 'function' || !result[key]) {
      result[key] = obj2[key];
    } else {
      Object.assign(result[key], obj2[key]);
    }
  });
  return result;
}
function extractParams(fileContent) {
  const f = (0,_generationHelpers__WEBPACK_IMPORTED_MODULE_1__.parseTl)(fileContent);
  const constructors = [];
  const functions = [];
  for (const d of f) {
    if (d.isFunction) {
      functions.push(d);
    } else {
      constructors.push(d);
    }
  }
  return [constructors, functions];
}
function argToBytes(x, type) {
  switch (type) {
    case 'int':
      {
        const i = Buffer.alloc(4);
        i.writeInt32LE(x, 0);
        return i;
      }
    case 'long':
      return (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.toSignedLittleBuffer)(x, 8);
    case 'int128':
      return (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.toSignedLittleBuffer)(x, 16);
    case 'int256':
      return (0,_Helpers__WEBPACK_IMPORTED_MODULE_3__.toSignedLittleBuffer)(x, 32);
    case 'double':
      {
        const d = Buffer.alloc(8);
        d.writeDoubleLE(x, 0);
        return d;
      }
    case 'string':
      return (0,_generationHelpers__WEBPACK_IMPORTED_MODULE_1__.serializeBytes)(x);
    case 'Bool':
      return x ? Buffer.from('b5757299', 'hex') : Buffer.from('379779bc', 'hex');
    case 'true':
      return Buffer.alloc(0);
    case 'bytes':
      return (0,_generationHelpers__WEBPACK_IMPORTED_MODULE_1__.serializeBytes)(x);
    case 'date':
      return (0,_generationHelpers__WEBPACK_IMPORTED_MODULE_1__.serializeDate)(x);
    default:
      return x.getBytes();
  }
}
function getArgFromReader(reader, arg) {
  if (arg.isVector) {
    if (arg.useVectorId) {
      reader.readInt();
    }
    const temp = [];
    const len = reader.readInt();
    arg.isVector = false;
    for (let i = 0; i < len; i++) {
      temp.push(getArgFromReader(reader, arg));
    }
    arg.isVector = true;
    return temp;
  } else if (arg.flagIndicator) {
    return reader.readInt();
  } else {
    switch (arg.type) {
      case 'int':
        return reader.readInt();
      case 'long':
        return reader.readLong();
      case 'int128':
        return reader.readLargeInt(128);
      case 'int256':
        return reader.readLargeInt(256);
      case 'double':
        return reader.readDouble();
      case 'string':
        return reader.tgReadString();
      case 'Bool':
        return reader.tgReadBool();
      case 'true':
        return true;
      case 'bytes':
        return reader.tgReadBytes();
      case 'date':
        return reader.tgReadDate();
      default:
        if (!arg.skipConstructorId) {
          return reader.tgReadObject();
        } else {
          throw new Error(`Unknown type ${arg}`);
        }
    }
  }
}
function createClasses(classesType, params) {
  const classes = {};
  for (const classParams of params) {
    const {
      name,
      constructorId,
      subclassOfId,
      argsConfig,
      namespace,
      result
    } = classParams;
    const fullName = [namespace, name].join('.').replace(/^\./, '');
    class VirtualClass {
      static CONSTRUCTOR_ID = constructorId;
      static SUBCLASS_OF_ID = subclassOfId;
      static className = fullName;
      static classType = classesType;
      CONSTRUCTOR_ID = constructorId;
      SUBCLASS_OF_ID = subclassOfId;
      className = fullName;
      classType = classesType;
      constructor(args) {
        args = args || {};
        Object.keys(args).forEach(argName => {
          this[argName] = args[argName];
        });
      }
      static fromReader(reader) {
        const args = {};
        for (const argName in argsConfig) {
          if (argsConfig.hasOwnProperty(argName)) {
            const arg = argsConfig[argName];
            if (arg.isFlag) {
              const flagGroupSuffix = arg.flagGroup > 1 ? arg.flagGroup : '';
              const flagValue = args[`flags${flagGroupSuffix}`] & 1 << arg.flagIndex;
              if (arg.type === 'true') {
                args[argName] = Boolean(flagValue);
                continue;
              }
              args[argName] = flagValue ? getArgFromReader(reader, arg) : undefined;
            } else {
              args[argName] = getArgFromReader(reader, arg);
            }
          }
        }
        return new VirtualClass(args);
      }
      getBytes() {
        // The next is pseudo-code:
        const idForBytes = this.CONSTRUCTOR_ID;
        const c = Buffer.alloc(4);
        c.writeUInt32LE(idForBytes, 0);
        const buffers = [c];
        for (const arg in argsConfig) {
          if (argsConfig.hasOwnProperty(arg)) {
            if (argsConfig[arg].isFlag) {
              if (this[arg] === false && argsConfig[arg].type === 'true' || this[arg] === undefined) {
                continue;
              }
            }
            if (argsConfig[arg].isVector) {
              if (argsConfig[arg].useVectorId) {
                buffers.push(Buffer.from('15c4b51c', 'hex'));
              }
              const l = Buffer.alloc(4);
              l.writeInt32LE(this[arg].length, 0);
              buffers.push(l, Buffer.concat(this[arg].map(x => argToBytes(x, argsConfig[arg].type))));
            } else if (argsConfig[arg].flagIndicator) {
              if (!Object.values(argsConfig).some(f => f.isFlag)) {
                buffers.push(Buffer.alloc(4));
              } else {
                let flagCalculate = 0;
                for (const f in argsConfig) {
                  if (argsConfig[f].isFlag) {
                    if (this[f] === false && argsConfig[f].type === 'true' || this[f] === undefined) {
                      flagCalculate |= 0;
                    } else {
                      flagCalculate |= 1 << argsConfig[f].flagIndex;
                    }
                  }
                }
                const f = Buffer.alloc(4);
                f.writeUInt32LE(flagCalculate, 0);
                buffers.push(f);
              }
            } else {
              buffers.push(argToBytes(this[arg], argsConfig[arg].type));
              if (this[arg] && typeof this[arg].getBytes === 'function') {
                const firstChar = argsConfig[arg].type.charAt(argsConfig[arg].type.indexOf('.') + 1);
                const boxed = firstChar === firstChar.toUpperCase();
                if (!boxed) {
                  buffers.shift();
                }
              }
            }
          }
        }
        return Buffer.concat(buffers);
      }
      readResult(reader) {
        if (classesType !== 'request') {
          throw new Error('`readResult()` called for non-request instance');
        }
        const m = result.match(/Vector<(int|long)>/);
        if (m) {
          reader.readInt();
          const temp = [];
          const len = reader.readInt();
          if (m[1] === 'int') {
            for (let i = 0; i < len; i++) {
              temp.push(reader.readInt());
            }
          } else {
            for (let i = 0; i < len; i++) {
              temp.push(reader.readLong());
            }
          }
          return temp;
        } else {
          return reader.tgReadObject();
        }
      }
    }
    if (namespace) {
      if (!classes[namespace]) {
        classes[namespace] = {};
      }
      classes[namespace][name] = VirtualClass;
    } else {
      classes[name] = VirtualClass;
    }
  }
  return classes;
}

/***/ }),

/***/ "./src/lib/gramjs/tl/apiTl.ts":
/*!************************************!*\
  !*** ./src/lib/gramjs/tl/apiTl.ts ***!
  \************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (`boolFalse#bc799737 = Bool;
boolTrue#997275b5 = Bool;
true#3fedd339 = True;
vector#1cb5c415 {t:Type} # [ t ] = Vector t;
error#c4b9f9bb code:int text:string = Error;
null#56730bcc = Null;
inputPeerEmpty#7f3b18ea = InputPeer;
inputPeerSelf#7da07ec9 = InputPeer;
inputPeerChat#35a95cb9 chat_id:long = InputPeer;
inputPeerUser#dde8a54c user_id:long access_hash:long = InputPeer;
inputPeerChannel#27bcbbfc channel_id:long access_hash:long = InputPeer;
inputPeerUserFromMessage#a87b0a1c peer:InputPeer msg_id:int user_id:long = InputPeer;
inputPeerChannelFromMessage#bd2a0840 peer:InputPeer msg_id:int channel_id:long = InputPeer;
inputUserEmpty#b98886cf = InputUser;
inputUserSelf#f7c1b13f = InputUser;
inputUser#f21158c6 user_id:long access_hash:long = InputUser;
inputUserFromMessage#1da448e2 peer:InputPeer msg_id:int user_id:long = InputUser;
inputPhoneContact#f392b7f4 client_id:long phone:string first_name:string last_name:string = InputContact;
inputFile#f52ff27f id:long parts:int name:string md5_checksum:string = InputFile;
inputFileBig#fa4f0bb5 id:long parts:int name:string = InputFile;
inputFileStoryDocument#62dc8b48 id:InputDocument = InputFile;
inputMediaEmpty#9664f57f = InputMedia;
inputMediaUploadedPhoto#1e287d04 flags:# spoiler:flags.2?true file:InputFile stickers:flags.0?Vector<InputDocument> ttl_seconds:flags.1?int = InputMedia;
inputMediaPhoto#b3ba0635 flags:# spoiler:flags.1?true id:InputPhoto ttl_seconds:flags.0?int = InputMedia;
inputMediaGeoPoint#f9c44144 geo_point:InputGeoPoint = InputMedia;
inputMediaContact#f8ab7dfb phone_number:string first_name:string last_name:string vcard:string = InputMedia;
inputMediaUploadedDocument#37c9330 flags:# nosound_video:flags.3?true force_file:flags.4?true spoiler:flags.5?true file:InputFile thumb:flags.2?InputFile mime_type:string attributes:Vector<DocumentAttribute> stickers:flags.0?Vector<InputDocument> video_cover:flags.6?InputPhoto video_timestamp:flags.7?int ttl_seconds:flags.1?int = InputMedia;
inputMediaDocument#a8763ab5 flags:# spoiler:flags.2?true id:InputDocument video_cover:flags.3?InputPhoto video_timestamp:flags.4?int ttl_seconds:flags.0?int query:flags.1?string = InputMedia;
inputMediaVenue#c13d1c11 geo_point:InputGeoPoint title:string address:string provider:string venue_id:string venue_type:string = InputMedia;
inputMediaPhotoExternal#e5bbfe1a flags:# spoiler:flags.1?true url:string ttl_seconds:flags.0?int = InputMedia;
inputMediaDocumentExternal#779600f9 flags:# spoiler:flags.1?true url:string ttl_seconds:flags.0?int video_cover:flags.2?InputPhoto video_timestamp:flags.3?int = InputMedia;
inputMediaGame#d33f43f3 id:InputGame = InputMedia;
inputMediaInvoice#405fef0d flags:# title:string description:string photo:flags.0?InputWebDocument invoice:Invoice payload:bytes provider:flags.3?string provider_data:DataJSON start_param:flags.1?string extended_media:flags.2?InputMedia = InputMedia;
inputMediaGeoLive#971fa843 flags:# stopped:flags.0?true geo_point:InputGeoPoint heading:flags.2?int period:flags.1?int proximity_notification_radius:flags.3?int = InputMedia;
inputMediaPoll#f94e5f1 flags:# poll:Poll correct_answers:flags.0?Vector<bytes> solution:flags.1?string solution_entities:flags.1?Vector<MessageEntity> = InputMedia;
inputMediaDice#e66fbf7b emoticon:string = InputMedia;
inputMediaStory#89fdd778 peer:InputPeer id:int = InputMedia;
inputMediaWebPage#c21b8849 flags:# force_large_media:flags.0?true force_small_media:flags.1?true optional:flags.2?true url:string = InputMedia;
inputMediaPaidMedia#c4103386 flags:# stars_amount:long extended_media:Vector<InputMedia> payload:flags.0?string = InputMedia;
inputMediaTodo#9fc55fde todo:TodoList = InputMedia;
inputChatPhotoEmpty#1ca48f57 = InputChatPhoto;
inputChatUploadedPhoto#bdcdaec0 flags:# file:flags.0?InputFile video:flags.1?InputFile video_start_ts:flags.2?double video_emoji_markup:flags.3?VideoSize = InputChatPhoto;
inputChatPhoto#8953ad37 id:InputPhoto = InputChatPhoto;
inputGeoPointEmpty#e4c123d6 = InputGeoPoint;
inputGeoPoint#48222faf flags:# lat:double long:double accuracy_radius:flags.0?int = InputGeoPoint;
inputPhotoEmpty#1cd7bf0d = InputPhoto;
inputPhoto#3bb3b94a id:long access_hash:long file_reference:bytes = InputPhoto;
inputFileLocation#dfdaabe1 volume_id:long local_id:int secret:long file_reference:bytes = InputFileLocation;
inputEncryptedFileLocation#f5235d55 id:long access_hash:long = InputFileLocation;
inputDocumentFileLocation#bad07584 id:long access_hash:long file_reference:bytes thumb_size:string = InputFileLocation;
inputSecureFileLocation#cbc7ee28 id:long access_hash:long = InputFileLocation;
inputTakeoutFileLocation#29be5899 = InputFileLocation;
inputPhotoFileLocation#40181ffe id:long access_hash:long file_reference:bytes thumb_size:string = InputFileLocation;
inputPhotoLegacyFileLocation#d83466f3 id:long access_hash:long file_reference:bytes volume_id:long local_id:int secret:long = InputFileLocation;
inputPeerPhotoFileLocation#37257e99 flags:# big:flags.0?true peer:InputPeer photo_id:long = InputFileLocation;
inputStickerSetThumb#9d84f3db stickerset:InputStickerSet thumb_version:int = InputFileLocation;
inputGroupCallStream#598a92a flags:# call:InputGroupCall time_ms:long scale:int video_channel:flags.0?int video_quality:flags.0?int = InputFileLocation;
peerUser#59511722 user_id:long = Peer;
peerChat#36c6019a chat_id:long = Peer;
peerChannel#a2a5371e channel_id:long = Peer;
storage.fileUnknown#aa963b05 = storage.FileType;
storage.filePartial#40bc6f52 = storage.FileType;
storage.fileJpeg#7efe0e = storage.FileType;
storage.fileGif#cae1aadf = storage.FileType;
storage.filePng#a4f63c0 = storage.FileType;
storage.filePdf#ae1e508d = storage.FileType;
storage.fileMp3#528a0677 = storage.FileType;
storage.fileMov#4b09ebbc = storage.FileType;
storage.fileMp4#b3cea0e4 = storage.FileType;
storage.fileWebp#1081464c = storage.FileType;
userEmpty#d3bc4b7a id:long = User;
user#20b1422 flags:# self:flags.10?true contact:flags.11?true mutual_contact:flags.12?true deleted:flags.13?true bot:flags.14?true bot_chat_history:flags.15?true bot_nochats:flags.16?true verified:flags.17?true restricted:flags.18?true min:flags.20?true bot_inline_geo:flags.21?true support:flags.23?true scam:flags.24?true apply_min_photo:flags.25?true fake:flags.26?true bot_attach_menu:flags.27?true premium:flags.28?true attach_menu_enabled:flags.29?true flags2:# bot_can_edit:flags2.1?true close_friend:flags2.2?true stories_hidden:flags2.3?true stories_unavailable:flags2.4?true contact_require_premium:flags2.10?true bot_business:flags2.11?true bot_has_main_app:flags2.13?true id:long access_hash:flags.0?long first_name:flags.1?string last_name:flags.2?string username:flags.3?string phone:flags.4?string photo:flags.5?UserProfilePhoto status:flags.6?UserStatus bot_info_version:flags.14?int restriction_reason:flags.18?Vector<RestrictionReason> bot_inline_placeholder:flags.19?string lang_code:flags.22?string emoji_status:flags.30?EmojiStatus usernames:flags2.0?Vector<Username> stories_max_id:flags2.5?int color:flags2.8?PeerColor profile_color:flags2.9?PeerColor bot_active_users:flags2.12?int bot_verification_icon:flags2.14?long send_paid_messages_stars:flags2.15?long = User;
userProfilePhotoEmpty#4f11bae1 = UserProfilePhoto;
userProfilePhoto#82d1f706 flags:# has_video:flags.0?true personal:flags.2?true photo_id:long stripped_thumb:flags.1?bytes dc_id:int = UserProfilePhoto;
userStatusEmpty#9d05049 = UserStatus;
userStatusOnline#edb93949 expires:int = UserStatus;
userStatusOffline#8c703f was_online:int = UserStatus;
userStatusRecently#7b197dc8 flags:# by_me:flags.0?true = UserStatus;
userStatusLastWeek#541a1d1a flags:# by_me:flags.0?true = UserStatus;
userStatusLastMonth#65899777 flags:# by_me:flags.0?true = UserStatus;
chatEmpty#29562865 id:long = Chat;
chat#41cbf256 flags:# creator:flags.0?true left:flags.2?true deactivated:flags.5?true call_active:flags.23?true call_not_empty:flags.24?true noforwards:flags.25?true id:long title:string photo:ChatPhoto participants_count:int date:int version:int migrated_to:flags.6?InputChannel admin_rights:flags.14?ChatAdminRights default_banned_rights:flags.18?ChatBannedRights = Chat;
chatForbidden#6592a1a7 id:long title:string = Chat;
channel#fe685355 flags:# creator:flags.0?true left:flags.2?true broadcast:flags.5?true verified:flags.7?true megagroup:flags.8?true restricted:flags.9?true signatures:flags.11?true min:flags.12?true scam:flags.19?true has_link:flags.20?true has_geo:flags.21?true slowmode_enabled:flags.22?true call_active:flags.23?true call_not_empty:flags.24?true fake:flags.25?true gigagroup:flags.26?true noforwards:flags.27?true join_to_send:flags.28?true join_request:flags.29?true forum:flags.30?true flags2:# stories_hidden:flags2.1?true stories_hidden_min:flags2.2?true stories_unavailable:flags2.3?true signature_profiles:flags2.12?true autotranslation:flags2.15?true broadcast_messages_allowed:flags2.16?true monoforum:flags2.17?true forum_tabs:flags2.19?true id:long access_hash:flags.13?long title:string username:flags.6?string photo:ChatPhoto date:int restriction_reason:flags.9?Vector<RestrictionReason> admin_rights:flags.14?ChatAdminRights banned_rights:flags.15?ChatBannedRights default_banned_rights:flags.18?ChatBannedRights participants_count:flags.17?int usernames:flags2.0?Vector<Username> stories_max_id:flags2.4?int color:flags2.7?PeerColor profile_color:flags2.8?PeerColor emoji_status:flags2.9?EmojiStatus level:flags2.10?int subscription_until_date:flags2.11?int bot_verification_icon:flags2.13?long send_paid_messages_stars:flags2.14?long linked_monoforum_id:flags2.18?long = Chat;
channelForbidden#17d493d5 flags:# broadcast:flags.5?true megagroup:flags.8?true id:long access_hash:long title:string until_date:flags.16?int = Chat;
chatFull#2633421b flags:# can_set_username:flags.7?true has_scheduled:flags.8?true translations_disabled:flags.19?true id:long about:string participants:ChatParticipants chat_photo:flags.2?Photo notify_settings:PeerNotifySettings exported_invite:flags.13?ExportedChatInvite bot_info:flags.3?Vector<BotInfo> pinned_msg_id:flags.6?int folder_id:flags.11?int call:flags.12?InputGroupCall ttl_period:flags.14?int groupcall_default_join_as:flags.15?Peer theme_emoticon:flags.16?string requests_pending:flags.17?int recent_requesters:flags.17?Vector<long> available_reactions:flags.18?ChatReactions reactions_limit:flags.20?int = ChatFull;
channelFull#e07429de flags:# can_view_participants:flags.3?true can_set_username:flags.6?true can_set_stickers:flags.7?true hidden_prehistory:flags.10?true can_set_location:flags.16?true has_scheduled:flags.19?true can_view_stats:flags.20?true blocked:flags.22?true flags2:# can_delete_channel:flags2.0?true antispam:flags2.1?true participants_hidden:flags2.2?true translations_disabled:flags2.3?true stories_pinned_available:flags2.5?true view_forum_as_messages:flags2.6?true restricted_sponsored:flags2.11?true can_view_revenue:flags2.12?true paid_media_allowed:flags2.14?true can_view_stars_revenue:flags2.15?true paid_reactions_available:flags2.16?true stargifts_available:flags2.19?true paid_messages_available:flags2.20?true id:long about:string participants_count:flags.0?int admins_count:flags.1?int kicked_count:flags.2?int banned_count:flags.2?int online_count:flags.13?int read_inbox_max_id:int read_outbox_max_id:int unread_count:int chat_photo:Photo notify_settings:PeerNotifySettings exported_invite:flags.23?ExportedChatInvite bot_info:Vector<BotInfo> migrated_from_chat_id:flags.4?long migrated_from_max_id:flags.4?int pinned_msg_id:flags.5?int stickerset:flags.8?StickerSet available_min_id:flags.9?int folder_id:flags.11?int linked_chat_id:flags.14?long location:flags.15?ChannelLocation slowmode_seconds:flags.17?int slowmode_next_send_date:flags.18?int stats_dc:flags.12?int pts:int call:flags.21?InputGroupCall ttl_period:flags.24?int pending_suggestions:flags.25?Vector<string> groupcall_default_join_as:flags.26?Peer theme_emoticon:flags.27?string requests_pending:flags.28?int recent_requesters:flags.28?Vector<long> default_send_as:flags.29?Peer available_reactions:flags.30?ChatReactions reactions_limit:flags2.13?int stories:flags2.4?PeerStories wallpaper:flags2.7?WallPaper boosts_applied:flags2.8?int boosts_unrestrict:flags2.9?int emojiset:flags2.10?StickerSet bot_verification:flags2.17?BotVerification stargifts_count:flags2.18?int send_paid_messages_stars:flags2.21?long = ChatFull;
chatParticipant#c02d4007 user_id:long inviter_id:long date:int = ChatParticipant;
chatParticipantCreator#e46bcee4 user_id:long = ChatParticipant;
chatParticipantAdmin#a0933f5b user_id:long inviter_id:long date:int = ChatParticipant;
chatParticipantsForbidden#8763d3e1 flags:# chat_id:long self_participant:flags.0?ChatParticipant = ChatParticipants;
chatParticipants#3cbc93f8 chat_id:long participants:Vector<ChatParticipant> version:int = ChatParticipants;
chatPhotoEmpty#37c1011c = ChatPhoto;
chatPhoto#1c6e1c11 flags:# has_video:flags.0?true photo_id:long stripped_thumb:flags.1?bytes dc_id:int = ChatPhoto;
messageEmpty#90a6ca84 flags:# id:int peer_id:flags.0?Peer = Message;
message#9815cec8 flags:# out:flags.1?true mentioned:flags.4?true media_unread:flags.5?true silent:flags.13?true post:flags.14?true from_scheduled:flags.18?true legacy:flags.19?true edit_hide:flags.21?true pinned:flags.24?true noforwards:flags.26?true invert_media:flags.27?true flags2:# offline:flags2.1?true video_processing_pending:flags2.4?true paid_suggested_post_stars:flags2.8?true paid_suggested_post_ton:flags2.9?true id:int from_id:flags.8?Peer from_boosts_applied:flags.29?int peer_id:Peer saved_peer_id:flags.28?Peer fwd_from:flags.2?MessageFwdHeader via_bot_id:flags.11?long via_business_bot_id:flags2.0?long reply_to:flags.3?MessageReplyHeader date:int message:string media:flags.9?MessageMedia reply_markup:flags.6?ReplyMarkup entities:flags.7?Vector<MessageEntity> views:flags.10?int forwards:flags.10?int replies:flags.23?MessageReplies edit_date:flags.15?int post_author:flags.16?string grouped_id:flags.17?long reactions:flags.20?MessageReactions restriction_reason:flags.22?Vector<RestrictionReason> ttl_period:flags.25?int quick_reply_shortcut_id:flags.30?int effect:flags2.2?long factcheck:flags2.3?FactCheck report_delivery_until_date:flags2.5?int paid_message_stars:flags2.6?long suggested_post:flags2.7?SuggestedPost = Message;
messageService#7a800e0a flags:# out:flags.1?true mentioned:flags.4?true media_unread:flags.5?true reactions_are_possible:flags.9?true silent:flags.13?true post:flags.14?true legacy:flags.19?true id:int from_id:flags.8?Peer peer_id:Peer saved_peer_id:flags.28?Peer reply_to:flags.3?MessageReplyHeader date:int action:MessageAction reactions:flags.20?MessageReactions ttl_period:flags.25?int = Message;
messageMediaEmpty#3ded6320 = MessageMedia;
messageMediaPhoto#695150d7 flags:# spoiler:flags.3?true photo:flags.0?Photo ttl_seconds:flags.2?int = MessageMedia;
messageMediaGeo#56e0d474 geo:GeoPoint = MessageMedia;
messageMediaContact#70322949 phone_number:string first_name:string last_name:string vcard:string user_id:long = MessageMedia;
messageMediaUnsupported#9f84f49e = MessageMedia;
messageMediaDocument#52d8ccd9 flags:# nopremium:flags.3?true spoiler:flags.4?true video:flags.6?true round:flags.7?true voice:flags.8?true document:flags.0?Document alt_documents:flags.5?Vector<Document> video_cover:flags.9?Photo video_timestamp:flags.10?int ttl_seconds:flags.2?int = MessageMedia;
messageMediaWebPage#ddf10c3b flags:# force_large_media:flags.0?true force_small_media:flags.1?true manual:flags.3?true safe:flags.4?true webpage:WebPage = MessageMedia;
messageMediaVenue#2ec0533f geo:GeoPoint title:string address:string provider:string venue_id:string venue_type:string = MessageMedia;
messageMediaGame#fdb19008 game:Game = MessageMedia;
messageMediaInvoice#f6a548d3 flags:# shipping_address_requested:flags.1?true test:flags.3?true title:string description:string photo:flags.0?WebDocument receipt_msg_id:flags.2?int currency:string total_amount:long start_param:string extended_media:flags.4?MessageExtendedMedia = MessageMedia;
messageMediaGeoLive#b940c666 flags:# geo:GeoPoint heading:flags.0?int period:int proximity_notification_radius:flags.1?int = MessageMedia;
messageMediaPoll#4bd6e798 poll:Poll results:PollResults = MessageMedia;
messageMediaDice#3f7ee58b value:int emoticon:string = MessageMedia;
messageMediaStory#68cb6283 flags:# via_mention:flags.1?true peer:Peer id:int story:flags.0?StoryItem = MessageMedia;
messageMediaGiveaway#aa073beb flags:# only_new_subscribers:flags.0?true winners_are_visible:flags.2?true channels:Vector<long> countries_iso2:flags.1?Vector<string> prize_description:flags.3?string quantity:int months:flags.4?int stars:flags.5?long until_date:int = MessageMedia;
messageMediaGiveawayResults#ceaa3ea1 flags:# only_new_subscribers:flags.0?true refunded:flags.2?true channel_id:long additional_peers_count:flags.3?int launch_msg_id:int winners_count:int unclaimed_count:int winners:Vector<long> months:flags.4?int stars:flags.5?long prize_description:flags.1?string until_date:int = MessageMedia;
messageMediaPaidMedia#a8852491 stars_amount:long extended_media:Vector<MessageExtendedMedia> = MessageMedia;
messageMediaToDo#8a53b014 flags:# todo:TodoList completions:flags.0?Vector<TodoCompletion> = MessageMedia;
messageActionEmpty#b6aef7b0 = MessageAction;
messageActionChatCreate#bd47cbad title:string users:Vector<long> = MessageAction;
messageActionChatEditTitle#b5a1ce5a title:string = MessageAction;
messageActionChatEditPhoto#7fcb13a8 photo:Photo = MessageAction;
messageActionChatDeletePhoto#95e3fbef = MessageAction;
messageActionChatAddUser#15cefd00 users:Vector<long> = MessageAction;
messageActionChatDeleteUser#a43f30cc user_id:long = MessageAction;
messageActionChatJoinedByLink#31224c3 inviter_id:long = MessageAction;
messageActionChannelCreate#95d2ac92 title:string = MessageAction;
messageActionChatMigrateTo#e1037f92 channel_id:long = MessageAction;
messageActionChannelMigrateFrom#ea3948e9 title:string chat_id:long = MessageAction;
messageActionPinMessage#94bd38ed = MessageAction;
messageActionHistoryClear#9fbab604 = MessageAction;
messageActionGameScore#92a72876 game_id:long score:int = MessageAction;
messageActionPaymentSentMe#ffa00ccc flags:# recurring_init:flags.2?true recurring_used:flags.3?true currency:string total_amount:long payload:bytes info:flags.0?PaymentRequestedInfo shipping_option_id:flags.1?string charge:PaymentCharge subscription_until_date:flags.4?int = MessageAction;
messageActionPaymentSent#c624b16e flags:# recurring_init:flags.2?true recurring_used:flags.3?true currency:string total_amount:long invoice_slug:flags.0?string subscription_until_date:flags.4?int = MessageAction;
messageActionPhoneCall#80e11a7f flags:# video:flags.2?true call_id:long reason:flags.0?PhoneCallDiscardReason duration:flags.1?int = MessageAction;
messageActionScreenshotTaken#4792929b = MessageAction;
messageActionCustomAction#fae69f56 message:string = MessageAction;
messageActionBotAllowed#c516d679 flags:# attach_menu:flags.1?true from_request:flags.3?true domain:flags.0?string app:flags.2?BotApp = MessageAction;
messageActionSecureValuesSentMe#1b287353 values:Vector<SecureValue> credentials:SecureCredentialsEncrypted = MessageAction;
messageActionSecureValuesSent#d95c6154 types:Vector<SecureValueType> = MessageAction;
messageActionContactSignUp#f3f25f76 = MessageAction;
messageActionGeoProximityReached#98e0d697 from_id:Peer to_id:Peer distance:int = MessageAction;
messageActionGroupCall#7a0d7f42 flags:# call:InputGroupCall duration:flags.0?int = MessageAction;
messageActionInviteToGroupCall#502f92f7 call:InputGroupCall users:Vector<long> = MessageAction;
messageActionSetMessagesTTL#3c134d7b flags:# period:int auto_setting_from:flags.0?long = MessageAction;
messageActionGroupCallScheduled#b3a07661 call:InputGroupCall schedule_date:int = MessageAction;
messageActionSetChatTheme#aa786345 emoticon:string = MessageAction;
messageActionChatJoinedByRequest#ebbca3cb = MessageAction;
messageActionWebViewDataSentMe#47dd8079 text:string data:string = MessageAction;
messageActionWebViewDataSent#b4c38cb5 text:string = MessageAction;
messageActionGiftPremium#6c6274fa flags:# currency:string amount:long months:int crypto_currency:flags.0?string crypto_amount:flags.0?long message:flags.1?TextWithEntities = MessageAction;
messageActionTopicCreate#d999256 flags:# title:string icon_color:int icon_emoji_id:flags.0?long = MessageAction;
messageActionTopicEdit#c0944820 flags:# title:flags.0?string icon_emoji_id:flags.1?long closed:flags.2?Bool hidden:flags.3?Bool = MessageAction;
messageActionSuggestProfilePhoto#57de635e photo:Photo = MessageAction;
messageActionRequestedPeer#31518e9b button_id:int peers:Vector<Peer> = MessageAction;
messageActionSetChatWallPaper#5060a3f4 flags:# same:flags.0?true for_both:flags.1?true wallpaper:WallPaper = MessageAction;
messageActionGiftCode#56d03994 flags:# via_giveaway:flags.0?true unclaimed:flags.5?true boost_peer:flags.1?Peer months:int slug:string currency:flags.2?string amount:flags.2?long crypto_currency:flags.3?string crypto_amount:flags.3?long message:flags.4?TextWithEntities = MessageAction;
messageActionGiveawayLaunch#a80f51e4 flags:# stars:flags.0?long = MessageAction;
messageActionGiveawayResults#87e2f155 flags:# stars:flags.0?true winners_count:int unclaimed_count:int = MessageAction;
messageActionBoostApply#cc02aa6d boosts:int = MessageAction;
messageActionRequestedPeerSentMe#93b31848 button_id:int peers:Vector<RequestedPeer> = MessageAction;
messageActionPaymentRefunded#41b3e202 flags:# peer:Peer currency:string total_amount:long payload:flags.0?bytes charge:PaymentCharge = MessageAction;
messageActionGiftStars#45d5b021 flags:# currency:string amount:long stars:long crypto_currency:flags.0?string crypto_amount:flags.0?long transaction_id:flags.1?string = MessageAction;
messageActionPrizeStars#b00c47a2 flags:# unclaimed:flags.0?true stars:long transaction_id:string boost_peer:Peer giveaway_msg_id:int = MessageAction;
messageActionStarGift#f24de7fa flags:# name_hidden:flags.0?true saved:flags.2?true converted:flags.3?true upgraded:flags.5?true refunded:flags.9?true can_upgrade:flags.10?true prepaid_upgrade:flags.13?true gift:StarGift message:flags.1?TextWithEntities convert_stars:flags.4?long upgrade_msg_id:flags.5?int upgrade_stars:flags.8?long from_id:flags.11?Peer peer:flags.12?Peer saved_id:flags.12?long prepaid_upgrade_hash:flags.14?string gift_msg_id:flags.15?int = MessageAction;
messageActionStarGiftUnique#34f762f3 flags:# upgrade:flags.0?true transferred:flags.1?true saved:flags.2?true refunded:flags.5?true prepaid_upgrade:flags.11?true gift:StarGift can_export_at:flags.3?int transfer_stars:flags.4?long from_id:flags.6?Peer peer:flags.7?Peer saved_id:flags.7?long resale_amount:flags.8?StarsAmount can_transfer_at:flags.9?int can_resell_at:flags.10?int = MessageAction;
messageActionPaidMessagesRefunded#ac1f1fcd count:int stars:long = MessageAction;
messageActionPaidMessagesPrice#84b88578 flags:# broadcast_messages_allowed:flags.0?true stars:long = MessageAction;
messageActionConferenceCall#2ffe2f7a flags:# missed:flags.0?true active:flags.1?true video:flags.4?true call_id:long duration:flags.2?int other_participants:flags.3?Vector<Peer> = MessageAction;
messageActionTodoCompletions#cc7c5c89 completed:Vector<int> incompleted:Vector<int> = MessageAction;
messageActionTodoAppendTasks#c7edbc83 list:Vector<TodoItem> = MessageAction;
messageActionSuggestedPostApproval#ee7a1596 flags:# rejected:flags.0?true balance_too_low:flags.1?true reject_comment:flags.2?string schedule_date:flags.3?int price:flags.4?StarsAmount = MessageAction;
messageActionSuggestedPostSuccess#95ddcf69 price:StarsAmount = MessageAction;
messageActionSuggestedPostRefund#69f916f8 flags:# payer_initiated:flags.0?true = MessageAction;
messageActionGiftTon#a8a3c699 flags:# currency:string amount:long crypto_currency:string crypto_amount:long transaction_id:flags.0?string = MessageAction;
dialog#d58a08c6 flags:# pinned:flags.2?true unread_mark:flags.3?true view_forum_as_messages:flags.6?true peer:Peer top_message:int read_inbox_max_id:int read_outbox_max_id:int unread_count:int unread_mentions_count:int unread_reactions_count:int notify_settings:PeerNotifySettings pts:flags.0?int draft:flags.1?DraftMessage folder_id:flags.4?int ttl_period:flags.5?int = Dialog;
dialogFolder#71bd134c flags:# pinned:flags.2?true folder:Folder peer:Peer top_message:int unread_muted_peers_count:int unread_unmuted_peers_count:int unread_muted_messages_count:int unread_unmuted_messages_count:int = Dialog;
photoEmpty#2331b22d id:long = Photo;
photo#fb197a65 flags:# has_stickers:flags.0?true id:long access_hash:long file_reference:bytes date:int sizes:Vector<PhotoSize> video_sizes:flags.1?Vector<VideoSize> dc_id:int = Photo;
photoSizeEmpty#e17e23c type:string = PhotoSize;
photoSize#75c78e60 type:string w:int h:int size:int = PhotoSize;
photoCachedSize#21e1ad6 type:string w:int h:int bytes:bytes = PhotoSize;
photoStrippedSize#e0b0bc2e type:string bytes:bytes = PhotoSize;
photoSizeProgressive#fa3efb95 type:string w:int h:int sizes:Vector<int> = PhotoSize;
photoPathSize#d8214d41 type:string bytes:bytes = PhotoSize;
geoPointEmpty#1117dd5f = GeoPoint;
geoPoint#b2a2f663 flags:# long:double lat:double access_hash:long accuracy_radius:flags.0?int = GeoPoint;
auth.sentCode#5e002502 flags:# type:auth.SentCodeType phone_code_hash:string next_type:flags.1?auth.CodeType timeout:flags.2?int = auth.SentCode;
auth.sentCodeSuccess#2390fe44 authorization:auth.Authorization = auth.SentCode;
auth.sentCodePaymentRequired#d7cef980 store_product:string phone_code_hash:string = auth.SentCode;
auth.authorization#2ea2c0d4 flags:# setup_password_required:flags.1?true otherwise_relogin_days:flags.1?int tmp_sessions:flags.0?int future_auth_token:flags.2?bytes user:User = auth.Authorization;
auth.authorizationSignUpRequired#44747e9a flags:# terms_of_service:flags.0?help.TermsOfService = auth.Authorization;
auth.exportedAuthorization#b434e2b8 id:long bytes:bytes = auth.ExportedAuthorization;
inputNotifyPeer#b8bc5b0c peer:InputPeer = InputNotifyPeer;
inputNotifyUsers#193b4417 = InputNotifyPeer;
inputNotifyChats#4a95e84e = InputNotifyPeer;
inputNotifyBroadcasts#b1db7c7e = InputNotifyPeer;
inputNotifyForumTopic#5c467992 peer:InputPeer top_msg_id:int = InputNotifyPeer;
inputPeerNotifySettings#cacb6ae2 flags:# show_previews:flags.0?Bool silent:flags.1?Bool mute_until:flags.2?int sound:flags.3?NotificationSound stories_muted:flags.6?Bool stories_hide_sender:flags.7?Bool stories_sound:flags.8?NotificationSound = InputPeerNotifySettings;
peerNotifySettings#99622c0c flags:# show_previews:flags.0?Bool silent:flags.1?Bool mute_until:flags.2?int ios_sound:flags.3?NotificationSound android_sound:flags.4?NotificationSound other_sound:flags.5?NotificationSound stories_muted:flags.6?Bool stories_hide_sender:flags.7?Bool stories_ios_sound:flags.8?NotificationSound stories_android_sound:flags.9?NotificationSound stories_other_sound:flags.10?NotificationSound = PeerNotifySettings;
peerSettings#f47741f7 flags:# report_spam:flags.0?true add_contact:flags.1?true block_contact:flags.2?true share_contact:flags.3?true need_contacts_exception:flags.4?true report_geo:flags.5?true autoarchived:flags.7?true invite_members:flags.8?true request_chat_broadcast:flags.10?true business_bot_paused:flags.11?true business_bot_can_reply:flags.12?true geo_distance:flags.6?int request_chat_title:flags.9?string request_chat_date:flags.9?int business_bot_id:flags.13?long business_bot_manage_url:flags.13?string charge_paid_message_stars:flags.14?long registration_month:flags.15?string phone_country:flags.16?string name_change_date:flags.17?int photo_change_date:flags.18?int = PeerSettings;
wallPaper#a437c3ed id:long flags:# creator:flags.0?true default:flags.1?true pattern:flags.3?true dark:flags.4?true access_hash:long slug:string document:Document settings:flags.2?WallPaperSettings = WallPaper;
wallPaperNoFile#e0804116 id:long flags:# default:flags.1?true dark:flags.4?true settings:flags.2?WallPaperSettings = WallPaper;
inputReportReasonSpam#58dbcab8 = ReportReason;
inputReportReasonViolence#1e22c78d = ReportReason;
inputReportReasonPornography#2e59d922 = ReportReason;
inputReportReasonChildAbuse#adf44ee3 = ReportReason;
inputReportReasonOther#c1e4a2b1 = ReportReason;
inputReportReasonCopyright#9b89f93a = ReportReason;
inputReportReasonGeoIrrelevant#dbd4feed = ReportReason;
inputReportReasonFake#f5ddd6e7 = ReportReason;
inputReportReasonIllegalDrugs#a8eb2be = ReportReason;
inputReportReasonPersonalDetails#9ec7863d = ReportReason;
userFull#7e63ce1f flags:# blocked:flags.0?true phone_calls_available:flags.4?true phone_calls_private:flags.5?true can_pin_message:flags.7?true has_scheduled:flags.12?true video_calls_available:flags.13?true voice_messages_forbidden:flags.20?true translations_disabled:flags.23?true stories_pinned_available:flags.26?true blocked_my_stories_from:flags.27?true wallpaper_overridden:flags.28?true contact_require_premium:flags.29?true read_dates_private:flags.30?true flags2:# sponsored_enabled:flags2.7?true can_view_revenue:flags2.9?true bot_can_manage_emoji_status:flags2.10?true display_gifts_button:flags2.16?true id:long about:flags.1?string settings:PeerSettings personal_photo:flags.21?Photo profile_photo:flags.2?Photo fallback_photo:flags.22?Photo notify_settings:PeerNotifySettings bot_info:flags.3?BotInfo pinned_msg_id:flags.6?int common_chats_count:int folder_id:flags.11?int ttl_period:flags.14?int theme_emoticon:flags.15?string private_forward_name:flags.16?string bot_group_admin_rights:flags.17?ChatAdminRights bot_broadcast_admin_rights:flags.18?ChatAdminRights wallpaper:flags.24?WallPaper stories:flags.25?PeerStories business_work_hours:flags2.0?BusinessWorkHours business_location:flags2.1?BusinessLocation business_greeting_message:flags2.2?BusinessGreetingMessage business_away_message:flags2.3?BusinessAwayMessage business_intro:flags2.4?BusinessIntro birthday:flags2.5?Birthday personal_channel_id:flags2.6?long personal_channel_message:flags2.6?int stargifts_count:flags2.8?int starref_program:flags2.11?StarRefProgram bot_verification:flags2.12?BotVerification send_paid_messages_stars:flags2.14?long disallowed_gifts:flags2.15?DisallowedGiftsSettings stars_rating:flags2.17?StarsRating stars_my_pending_rating:flags2.18?StarsRating stars_my_pending_rating_date:flags2.18?int = UserFull;
contact#145ade0b user_id:long mutual:Bool = Contact;
importedContact#c13e3c50 user_id:long client_id:long = ImportedContact;
contactStatus#16d9703b user_id:long status:UserStatus = ContactStatus;
contacts.contactsNotModified#b74ba9d2 = contacts.Contacts;
contacts.contacts#eae87e42 contacts:Vector<Contact> saved_count:int users:Vector<User> = contacts.Contacts;
contacts.importedContacts#77d01c3b imported:Vector<ImportedContact> popular_invites:Vector<PopularContact> retry_contacts:Vector<long> users:Vector<User> = contacts.ImportedContacts;
contacts.blocked#ade1591 blocked:Vector<PeerBlocked> chats:Vector<Chat> users:Vector<User> = contacts.Blocked;
contacts.blockedSlice#e1664194 count:int blocked:Vector<PeerBlocked> chats:Vector<Chat> users:Vector<User> = contacts.Blocked;
messages.dialogs#15ba6c40 dialogs:Vector<Dialog> messages:Vector<Message> chats:Vector<Chat> users:Vector<User> = messages.Dialogs;
messages.dialogsSlice#71e094f3 count:int dialogs:Vector<Dialog> messages:Vector<Message> chats:Vector<Chat> users:Vector<User> = messages.Dialogs;
messages.dialogsNotModified#f0e3e596 count:int = messages.Dialogs;
messages.messages#8c718e87 messages:Vector<Message> chats:Vector<Chat> users:Vector<User> = messages.Messages;
messages.messagesSlice#762b263d flags:# inexact:flags.1?true count:int next_rate:flags.0?int offset_id_offset:flags.2?int search_flood:flags.3?SearchPostsFlood messages:Vector<Message> chats:Vector<Chat> users:Vector<User> = messages.Messages;
messages.channelMessages#c776ba4e flags:# inexact:flags.1?true pts:int count:int offset_id_offset:flags.2?int messages:Vector<Message> topics:Vector<ForumTopic> chats:Vector<Chat> users:Vector<User> = messages.Messages;
messages.messagesNotModified#74535f21 count:int = messages.Messages;
messages.chats#64ff9fd5 chats:Vector<Chat> = messages.Chats;
messages.chatsSlice#9cd81144 count:int chats:Vector<Chat> = messages.Chats;
messages.chatFull#e5d7d19c full_chat:ChatFull chats:Vector<Chat> users:Vector<User> = messages.ChatFull;
messages.affectedHistory#b45c69d1 pts:int pts_count:int offset:int = messages.AffectedHistory;
inputMessagesFilterEmpty#57e2f66c = MessagesFilter;
inputMessagesFilterPhotos#9609a51c = MessagesFilter;
inputMessagesFilterVideo#9fc00e65 = MessagesFilter;
inputMessagesFilterPhotoVideo#56e9f0e4 = MessagesFilter;
inputMessagesFilterDocument#9eddf188 = MessagesFilter;
inputMessagesFilterUrl#7ef0dd87 = MessagesFilter;
inputMessagesFilterGif#ffc86587 = MessagesFilter;
inputMessagesFilterVoice#50f5c392 = MessagesFilter;
inputMessagesFilterMusic#3751b49e = MessagesFilter;
inputMessagesFilterChatPhotos#3a20ecb8 = MessagesFilter;
inputMessagesFilterPhoneCalls#80c99768 flags:# missed:flags.0?true = MessagesFilter;
inputMessagesFilterRoundVoice#7a7c17a4 = MessagesFilter;
inputMessagesFilterRoundVideo#b549da53 = MessagesFilter;
inputMessagesFilterMyMentions#c1f8e69a = MessagesFilter;
inputMessagesFilterGeo#e7026d0d = MessagesFilter;
inputMessagesFilterContacts#e062db83 = MessagesFilter;
inputMessagesFilterPinned#1bb00451 = MessagesFilter;
updateNewMessage#1f2b0afd message:Message pts:int pts_count:int = Update;
updateMessageID#4e90bfd6 id:int random_id:long = Update;
updateDeleteMessages#a20db0e5 messages:Vector<int> pts:int pts_count:int = Update;
updateUserTyping#c01e857f user_id:long action:SendMessageAction = Update;
updateChatUserTyping#83487af0 chat_id:long from_id:Peer action:SendMessageAction = Update;
updateChatParticipants#7761198 participants:ChatParticipants = Update;
updateUserStatus#e5bdf8de user_id:long status:UserStatus = Update;
updateUserName#a7848924 user_id:long first_name:string last_name:string usernames:Vector<Username> = Update;
updateNewAuthorization#8951abef flags:# unconfirmed:flags.0?true hash:long date:flags.0?int device:flags.0?string location:flags.0?string = Update;
updateNewEncryptedMessage#12bcbd9a message:EncryptedMessage qts:int = Update;
updateEncryptedChatTyping#1710f156 chat_id:int = Update;
updateEncryption#b4a2e88d chat:EncryptedChat date:int = Update;
updateEncryptedMessagesRead#38fe25b7 chat_id:int max_date:int date:int = Update;
updateChatParticipantAdd#3dda5451 chat_id:long user_id:long inviter_id:long date:int version:int = Update;
updateChatParticipantDelete#e32f3d77 chat_id:long user_id:long version:int = Update;
updateDcOptions#8e5e9873 dc_options:Vector<DcOption> = Update;
updateNotifySettings#bec268ef peer:NotifyPeer notify_settings:PeerNotifySettings = Update;
updateServiceNotification#ebe46819 flags:# popup:flags.0?true invert_media:flags.2?true inbox_date:flags.1?int type:string message:string media:MessageMedia entities:Vector<MessageEntity> = Update;
updatePrivacy#ee3b272a key:PrivacyKey rules:Vector<PrivacyRule> = Update;
updateUserPhone#5492a13 user_id:long phone:string = Update;
updateReadHistoryInbox#9c974fdf flags:# folder_id:flags.0?int peer:Peer max_id:int still_unread_count:int pts:int pts_count:int = Update;
updateReadHistoryOutbox#2f2f21bf peer:Peer max_id:int pts:int pts_count:int = Update;
updateWebPage#7f891213 webpage:WebPage pts:int pts_count:int = Update;
updateReadMessagesContents#f8227181 flags:# messages:Vector<int> pts:int pts_count:int date:flags.0?int = Update;
updateChannelTooLong#108d941f flags:# channel_id:long pts:flags.0?int = Update;
updateChannel#635b4c09 channel_id:long = Update;
updateNewChannelMessage#62ba04d9 message:Message pts:int pts_count:int = Update;
updateReadChannelInbox#922e6e10 flags:# folder_id:flags.0?int channel_id:long max_id:int still_unread_count:int pts:int = Update;
updateDeleteChannelMessages#c32d5b12 channel_id:long messages:Vector<int> pts:int pts_count:int = Update;
updateChannelMessageViews#f226ac08 channel_id:long id:int views:int = Update;
updateChatParticipantAdmin#d7ca61a2 chat_id:long user_id:long is_admin:Bool version:int = Update;
updateNewStickerSet#688a30aa stickerset:messages.StickerSet = Update;
updateStickerSetsOrder#bb2d201 flags:# masks:flags.0?true emojis:flags.1?true order:Vector<long> = Update;
updateStickerSets#31c24808 flags:# masks:flags.0?true emojis:flags.1?true = Update;
updateSavedGifs#9375341e = Update;
updateBotInlineQuery#496f379c flags:# query_id:long user_id:long query:string geo:flags.0?GeoPoint peer_type:flags.1?InlineQueryPeerType offset:string = Update;
updateBotInlineSend#12f12a07 flags:# user_id:long query:string geo:flags.0?GeoPoint id:string msg_id:flags.1?InputBotInlineMessageID = Update;
updateEditChannelMessage#1b3f4df7 message:Message pts:int pts_count:int = Update;
updateBotCallbackQuery#b9cfc48d flags:# query_id:long user_id:long peer:Peer msg_id:int chat_instance:long data:flags.0?bytes game_short_name:flags.1?string = Update;
updateEditMessage#e40370a3 message:Message pts:int pts_count:int = Update;
updateInlineBotCallbackQuery#691e9052 flags:# query_id:long user_id:long msg_id:InputBotInlineMessageID chat_instance:long data:flags.0?bytes game_short_name:flags.1?string = Update;
updateReadChannelOutbox#b75f99a9 channel_id:long max_id:int = Update;
updateDraftMessage#edfc111e flags:# peer:Peer top_msg_id:flags.0?int saved_peer_id:flags.1?Peer draft:DraftMessage = Update;
updateReadFeaturedStickers#571d2742 = Update;
updateRecentStickers#9a422c20 = Update;
updateConfig#a229dd06 = Update;
updatePtsChanged#3354678f = Update;
updateChannelWebPage#2f2ba99f channel_id:long webpage:WebPage pts:int pts_count:int = Update;
updateDialogPinned#6e6fe51c flags:# pinned:flags.0?true folder_id:flags.1?int peer:DialogPeer = Update;
updatePinnedDialogs#fa0f3ca2 flags:# folder_id:flags.1?int order:flags.0?Vector<DialogPeer> = Update;
updateBotWebhookJSON#8317c0c3 data:DataJSON = Update;
updateBotWebhookJSONQuery#9b9240a6 query_id:long data:DataJSON timeout:int = Update;
updateBotShippingQuery#b5aefd7d query_id:long user_id:long payload:bytes shipping_address:PostAddress = Update;
updateBotPrecheckoutQuery#8caa9a96 flags:# query_id:long user_id:long payload:bytes info:flags.0?PaymentRequestedInfo shipping_option_id:flags.1?string currency:string total_amount:long = Update;
updatePhoneCall#ab0f6b1e phone_call:PhoneCall = Update;
updateLangPackTooLong#46560264 lang_code:string = Update;
updateLangPack#56022f4d difference:LangPackDifference = Update;
updateFavedStickers#e511996d = Update;
updateChannelReadMessagesContents#25f324f7 flags:# channel_id:long top_msg_id:flags.0?int saved_peer_id:flags.1?Peer messages:Vector<int> = Update;
updateContactsReset#7084a7be = Update;
updateChannelAvailableMessages#b23fc698 channel_id:long available_min_id:int = Update;
updateDialogUnreadMark#b658f23e flags:# unread:flags.0?true peer:DialogPeer saved_peer_id:flags.1?Peer = Update;
updateMessagePoll#aca1657b flags:# poll_id:long poll:flags.0?Poll results:PollResults = Update;
updateChatDefaultBannedRights#54c01850 peer:Peer default_banned_rights:ChatBannedRights version:int = Update;
updateFolderPeers#19360dc0 folder_peers:Vector<FolderPeer> pts:int pts_count:int = Update;
updatePeerSettings#6a7e7366 peer:Peer settings:PeerSettings = Update;
updatePeerLocated#b4afcfb0 peers:Vector<PeerLocated> = Update;
updateNewScheduledMessage#39a51dfb message:Message = Update;
updateDeleteScheduledMessages#f2a71983 flags:# peer:Peer messages:Vector<int> sent_messages:flags.0?Vector<int> = Update;
updateTheme#8216fba3 theme:Theme = Update;
updateGeoLiveViewed#871fb939 peer:Peer msg_id:int = Update;
updateLoginToken#564fe691 = Update;
updateMessagePollVote#24f40e77 poll_id:long peer:Peer options:Vector<bytes> qts:int = Update;
updateDialogFilter#26ffde7d flags:# id:int filter:flags.0?DialogFilter = Update;
updateDialogFilterOrder#a5d72105 order:Vector<int> = Update;
updateDialogFilters#3504914f = Update;
updatePhoneCallSignalingData#2661bf09 phone_call_id:long data:bytes = Update;
updateChannelMessageForwards#d29a27f4 channel_id:long id:int forwards:int = Update;
updateReadChannelDiscussionInbox#d6b19546 flags:# channel_id:long top_msg_id:int read_max_id:int broadcast_id:flags.0?long broadcast_post:flags.0?int = Update;
updateReadChannelDiscussionOutbox#695c9e7c channel_id:long top_msg_id:int read_max_id:int = Update;
updatePeerBlocked#ebe07752 flags:# blocked:flags.0?true blocked_my_stories_from:flags.1?true peer_id:Peer = Update;
updateChannelUserTyping#8c88c923 flags:# channel_id:long top_msg_id:flags.0?int from_id:Peer action:SendMessageAction = Update;
updatePinnedMessages#ed85eab5 flags:# pinned:flags.0?true peer:Peer messages:Vector<int> pts:int pts_count:int = Update;
updatePinnedChannelMessages#5bb98608 flags:# pinned:flags.0?true channel_id:long messages:Vector<int> pts:int pts_count:int = Update;
updateChat#f89a6a4e chat_id:long = Update;
updateGroupCallParticipants#f2ebdb4e call:InputGroupCall participants:Vector<GroupCallParticipant> version:int = Update;
updateGroupCall#97d64341 flags:# chat_id:flags.0?long call:GroupCall = Update;
updatePeerHistoryTTL#bb9bb9a5 flags:# peer:Peer ttl_period:flags.0?int = Update;
updateChatParticipant#d087663a flags:# chat_id:long date:int actor_id:long user_id:long prev_participant:flags.0?ChatParticipant new_participant:flags.1?ChatParticipant invite:flags.2?ExportedChatInvite qts:int = Update;
updateChannelParticipant#985d3abb flags:# via_chatlist:flags.3?true channel_id:long date:int actor_id:long user_id:long prev_participant:flags.0?ChannelParticipant new_participant:flags.1?ChannelParticipant invite:flags.2?ExportedChatInvite qts:int = Update;
updateBotStopped#c4870a49 user_id:long date:int stopped:Bool qts:int = Update;
updateGroupCallConnection#b783982 flags:# presentation:flags.0?true params:DataJSON = Update;
updateBotCommands#4d712f2e peer:Peer bot_id:long commands:Vector<BotCommand> = Update;
updatePendingJoinRequests#7063c3db peer:Peer requests_pending:int recent_requesters:Vector<long> = Update;
updateBotChatInviteRequester#11dfa986 peer:Peer date:int user_id:long about:string invite:ExportedChatInvite qts:int = Update;
updateMessageReactions#1e297bfa flags:# peer:Peer msg_id:int top_msg_id:flags.0?int saved_peer_id:flags.1?Peer reactions:MessageReactions = Update;
updateAttachMenuBots#17b7a20b = Update;
updateWebViewResultSent#1592b79d query_id:long = Update;
updateBotMenuButton#14b85813 bot_id:long button:BotMenuButton = Update;
updateSavedRingtones#74d8be99 = Update;
updateTranscribedAudio#84cd5a flags:# pending:flags.0?true peer:Peer msg_id:int transcription_id:long text:string = Update;
updateReadFeaturedEmojiStickers#fb4c496c = Update;
updateUserEmojiStatus#28373599 user_id:long emoji_status:EmojiStatus = Update;
updateRecentEmojiStatuses#30f443db = Update;
updateRecentReactions#6f7863f4 = Update;
updateMoveStickerSetToTop#86fccf85 flags:# masks:flags.0?true emojis:flags.1?true stickerset:long = Update;
updateMessageExtendedMedia#d5a41724 peer:Peer msg_id:int extended_media:Vector<MessageExtendedMedia> = Update;
updateChannelPinnedTopic#192efbe3 flags:# pinned:flags.0?true channel_id:long topic_id:int = Update;
updateChannelPinnedTopics#fe198602 flags:# channel_id:long order:flags.0?Vector<int> = Update;
updateUser#20529438 user_id:long = Update;
updateAutoSaveSettings#ec05b097 = Update;
updateStory#75b3b798 peer:Peer story:StoryItem = Update;
updateReadStories#f74e932b peer:Peer max_id:int = Update;
updateStoryID#1bf335b9 id:int random_id:long = Update;
updateStoriesStealthMode#2c084dc1 stealth_mode:StoriesStealthMode = Update;
updateSentStoryReaction#7d627683 peer:Peer story_id:int reaction:Reaction = Update;
updateBotChatBoost#904dd49c peer:Peer boost:Boost qts:int = Update;
updateChannelViewForumAsMessages#7b68920 channel_id:long enabled:Bool = Update;
updatePeerWallpaper#ae3f101d flags:# wallpaper_overridden:flags.1?true peer:Peer wallpaper:flags.0?WallPaper = Update;
updateBotMessageReaction#ac21d3ce peer:Peer msg_id:int date:int actor:Peer old_reactions:Vector<Reaction> new_reactions:Vector<Reaction> qts:int = Update;
updateBotMessageReactions#9cb7759 peer:Peer msg_id:int date:int reactions:Vector<ReactionCount> qts:int = Update;
updateSavedDialogPinned#aeaf9e74 flags:# pinned:flags.0?true peer:DialogPeer = Update;
updatePinnedSavedDialogs#686c85a6 flags:# order:flags.0?Vector<DialogPeer> = Update;
updateSavedReactionTags#39c67432 = Update;
updateSmsJob#f16269d4 job_id:string = Update;
updateQuickReplies#f9470ab2 quick_replies:Vector<QuickReply> = Update;
updateNewQuickReply#f53da717 quick_reply:QuickReply = Update;
updateDeleteQuickReply#53e6f1ec shortcut_id:int = Update;
updateQuickReplyMessage#3e050d0f message:Message = Update;
updateDeleteQuickReplyMessages#566fe7cd shortcut_id:int messages:Vector<int> = Update;
updateBotBusinessConnect#8ae5c97a connection:BotBusinessConnection qts:int = Update;
updateBotNewBusinessMessage#9ddb347c flags:# connection_id:string message:Message reply_to_message:flags.0?Message qts:int = Update;
updateBotEditBusinessMessage#7df587c flags:# connection_id:string message:Message reply_to_message:flags.0?Message qts:int = Update;
updateBotDeleteBusinessMessage#a02a982e connection_id:string peer:Peer messages:Vector<int> qts:int = Update;
updateNewStoryReaction#1824e40b story_id:int peer:Peer reaction:Reaction = Update;
updateStarsBalance#4e80a379 balance:StarsAmount = Update;
updateBusinessBotCallbackQuery#1ea2fda7 flags:# query_id:long user_id:long connection_id:string message:Message reply_to_message:flags.2?Message chat_instance:long data:flags.0?bytes = Update;
updateStarsRevenueStatus#a584b019 peer:Peer status:StarsRevenueStatus = Update;
updateBotPurchasedPaidMedia#283bd312 user_id:long payload:string qts:int = Update;
updatePaidReactionPrivacy#8b725fce private:PaidReactionPrivacy = Update;
updateSentPhoneCode#504aa18f sent_code:auth.SentCode = Update;
updateGroupCallChainBlocks#a477288f call:InputGroupCall sub_chain_id:int blocks:Vector<bytes> next_offset:int = Update;
updateReadMonoForumInbox#77b0e372 channel_id:long saved_peer_id:Peer read_max_id:int = Update;
updateReadMonoForumOutbox#a4a79376 channel_id:long saved_peer_id:Peer read_max_id:int = Update;
updateMonoForumNoPaidException#9f812b08 flags:# exception:flags.0?true channel_id:long saved_peer_id:Peer = Update;
updates.state#a56c2a3e pts:int qts:int date:int seq:int unread_count:int = updates.State;
updates.differenceEmpty#5d75a138 date:int seq:int = updates.Difference;
updates.difference#f49ca0 new_messages:Vector<Message> new_encrypted_messages:Vector<EncryptedMessage> other_updates:Vector<Update> chats:Vector<Chat> users:Vector<User> state:updates.State = updates.Difference;
updates.differenceSlice#a8fb1981 new_messages:Vector<Message> new_encrypted_messages:Vector<EncryptedMessage> other_updates:Vector<Update> chats:Vector<Chat> users:Vector<User> intermediate_state:updates.State = updates.Difference;
updates.differenceTooLong#4afe8f6d pts:int = updates.Difference;
updatesTooLong#e317af7e = Updates;
updateShortMessage#313bc7f8 flags:# out:flags.1?true mentioned:flags.4?true media_unread:flags.5?true silent:flags.13?true id:int user_id:long message:string pts:int pts_count:int date:int fwd_from:flags.2?MessageFwdHeader via_bot_id:flags.11?long reply_to:flags.3?MessageReplyHeader entities:flags.7?Vector<MessageEntity> ttl_period:flags.25?int = Updates;
updateShortChatMessage#4d6deea5 flags:# out:flags.1?true mentioned:flags.4?true media_unread:flags.5?true silent:flags.13?true id:int from_id:long chat_id:long message:string pts:int pts_count:int date:int fwd_from:flags.2?MessageFwdHeader via_bot_id:flags.11?long reply_to:flags.3?MessageReplyHeader entities:flags.7?Vector<MessageEntity> ttl_period:flags.25?int = Updates;
updateShort#78d4dec1 update:Update date:int = Updates;
updatesCombined#725b04c3 updates:Vector<Update> users:Vector<User> chats:Vector<Chat> date:int seq_start:int seq:int = Updates;
updates#74ae4240 updates:Vector<Update> users:Vector<User> chats:Vector<Chat> date:int seq:int = Updates;
updateShortSentMessage#9015e101 flags:# out:flags.1?true id:int pts:int pts_count:int date:int media:flags.9?MessageMedia entities:flags.7?Vector<MessageEntity> ttl_period:flags.25?int = Updates;
photos.photos#8dca6aa5 photos:Vector<Photo> users:Vector<User> = photos.Photos;
photos.photosSlice#15051f54 count:int photos:Vector<Photo> users:Vector<User> = photos.Photos;
photos.photo#20212ca8 photo:Photo users:Vector<User> = photos.Photo;
upload.file#96a18d5 type:storage.FileType mtime:int bytes:bytes = upload.File;
upload.fileCdnRedirect#f18cda44 dc_id:int file_token:bytes encryption_key:bytes encryption_iv:bytes file_hashes:Vector<FileHash> = upload.File;
dcOption#18b7a10d flags:# ipv6:flags.0?true media_only:flags.1?true tcpo_only:flags.2?true cdn:flags.3?true static:flags.4?true this_port_only:flags.5?true id:int ip_address:string port:int secret:flags.10?bytes = DcOption;
config#cc1a241e flags:# default_p2p_contacts:flags.3?true preload_featured_stickers:flags.4?true revoke_pm_inbox:flags.6?true blocked_mode:flags.8?true force_try_ipv6:flags.14?true date:int expires:int test_mode:Bool this_dc:int dc_options:Vector<DcOption> dc_txt_domain_name:string chat_size_max:int megagroup_size_max:int forwarded_count_max:int online_update_period_ms:int offline_blur_timeout_ms:int offline_idle_timeout_ms:int online_cloud_timeout_ms:int notify_cloud_delay_ms:int notify_default_delay_ms:int push_chat_period_ms:int push_chat_limit:int edit_time_limit:int revoke_time_limit:int revoke_pm_time_limit:int rating_e_decay:int stickers_recent_limit:int channels_read_media_period:int tmp_sessions:flags.0?int call_receive_timeout_ms:int call_ring_timeout_ms:int call_connect_timeout_ms:int call_packet_timeout_ms:int me_url_prefix:string autoupdate_url_prefix:flags.7?string gif_search_username:flags.9?string venue_search_username:flags.10?string img_search_username:flags.11?string static_maps_provider:flags.12?string caption_length_max:int message_length_max:int webfile_dc_id:int suggested_lang_code:flags.2?string lang_pack_version:flags.2?int base_lang_pack_version:flags.2?int reactions_default:flags.15?Reaction autologin_token:flags.16?string = Config;
nearestDc#8e1a1775 country:string this_dc:int nearest_dc:int = NearestDc;
help.appUpdate#ccbbce30 flags:# can_not_skip:flags.0?true id:int version:string text:string entities:Vector<MessageEntity> document:flags.1?Document url:flags.2?string sticker:flags.3?Document = help.AppUpdate;
help.noAppUpdate#c45a6536 = help.AppUpdate;
help.inviteText#18cb9f78 message:string = help.InviteText;
encryptedChatEmpty#ab7ec0a0 id:int = EncryptedChat;
encryptedChatWaiting#66b25953 id:int access_hash:long date:int admin_id:long participant_id:long = EncryptedChat;
encryptedChatRequested#48f1d94c flags:# folder_id:flags.0?int id:int access_hash:long date:int admin_id:long participant_id:long g_a:bytes = EncryptedChat;
encryptedChat#61f0d4c7 id:int access_hash:long date:int admin_id:long participant_id:long g_a_or_b:bytes key_fingerprint:long = EncryptedChat;
encryptedChatDiscarded#1e1c7c45 flags:# history_deleted:flags.0?true id:int = EncryptedChat;
inputEncryptedChat#f141b5e1 chat_id:int access_hash:long = InputEncryptedChat;
encryptedFileEmpty#c21f497e = EncryptedFile;
encryptedFile#a8008cd8 id:long access_hash:long size:long dc_id:int key_fingerprint:int = EncryptedFile;
inputEncryptedFileEmpty#1837c364 = InputEncryptedFile;
inputEncryptedFileUploaded#64bd0306 id:long parts:int md5_checksum:string key_fingerprint:int = InputEncryptedFile;
inputEncryptedFile#5a17b5e5 id:long access_hash:long = InputEncryptedFile;
inputEncryptedFileBigUploaded#2dc173c8 id:long parts:int key_fingerprint:int = InputEncryptedFile;
encryptedMessage#ed18c118 random_id:long chat_id:int date:int bytes:bytes file:EncryptedFile = EncryptedMessage;
encryptedMessageService#23734b06 random_id:long chat_id:int date:int bytes:bytes = EncryptedMessage;
messages.dhConfigNotModified#c0e24635 random:bytes = messages.DhConfig;
messages.dhConfig#2c221edd g:int p:bytes version:int random:bytes = messages.DhConfig;
messages.sentEncryptedMessage#560f8935 date:int = messages.SentEncryptedMessage;
messages.sentEncryptedFile#9493ff32 date:int file:EncryptedFile = messages.SentEncryptedMessage;
inputDocumentEmpty#72f0eaae = InputDocument;
inputDocument#1abfb575 id:long access_hash:long file_reference:bytes = InputDocument;
documentEmpty#36f8c871 id:long = Document;
document#8fd4c4d8 flags:# id:long access_hash:long file_reference:bytes date:int mime_type:string size:long thumbs:flags.0?Vector<PhotoSize> video_thumbs:flags.1?Vector<VideoSize> dc_id:int attributes:Vector<DocumentAttribute> = Document;
help.support#17c6b5f6 phone_number:string user:User = help.Support;
notifyPeer#9fd40bd8 peer:Peer = NotifyPeer;
notifyUsers#b4c83b4c = NotifyPeer;
notifyChats#c007cec3 = NotifyPeer;
notifyBroadcasts#d612e8ef = NotifyPeer;
notifyForumTopic#226e6308 peer:Peer top_msg_id:int = NotifyPeer;
sendMessageTypingAction#16bf744e = SendMessageAction;
sendMessageCancelAction#fd5ec8f5 = SendMessageAction;
sendMessageRecordVideoAction#a187d66f = SendMessageAction;
sendMessageUploadVideoAction#e9763aec progress:int = SendMessageAction;
sendMessageRecordAudioAction#d52f73f7 = SendMessageAction;
sendMessageUploadAudioAction#f351d7ab progress:int = SendMessageAction;
sendMessageUploadPhotoAction#d1d34a26 progress:int = SendMessageAction;
sendMessageUploadDocumentAction#aa0cd9e4 progress:int = SendMessageAction;
sendMessageGeoLocationAction#176f8ba1 = SendMessageAction;
sendMessageChooseContactAction#628cbc6f = SendMessageAction;
sendMessageGamePlayAction#dd6a8f48 = SendMessageAction;
sendMessageRecordRoundAction#88f27fbc = SendMessageAction;
sendMessageUploadRoundAction#243e1c66 progress:int = SendMessageAction;
speakingInGroupCallAction#d92c2285 = SendMessageAction;
sendMessageHistoryImportAction#dbda9246 progress:int = SendMessageAction;
sendMessageChooseStickerAction#b05ac6b1 = SendMessageAction;
sendMessageEmojiInteraction#25972bcb emoticon:string msg_id:int interaction:DataJSON = SendMessageAction;
sendMessageEmojiInteractionSeen#b665902e emoticon:string = SendMessageAction;
contacts.found#b3134d9d my_results:Vector<Peer> results:Vector<Peer> chats:Vector<Chat> users:Vector<User> = contacts.Found;
inputPrivacyKeyStatusTimestamp#4f96cb18 = InputPrivacyKey;
inputPrivacyKeyChatInvite#bdfb0426 = InputPrivacyKey;
inputPrivacyKeyPhoneCall#fabadc5f = InputPrivacyKey;
inputPrivacyKeyPhoneP2P#db9e70d2 = InputPrivacyKey;
inputPrivacyKeyForwards#a4dd4c08 = InputPrivacyKey;
inputPrivacyKeyProfilePhoto#5719bacc = InputPrivacyKey;
inputPrivacyKeyPhoneNumber#352dafa = InputPrivacyKey;
inputPrivacyKeyAddedByPhone#d1219bdd = InputPrivacyKey;
inputPrivacyKeyVoiceMessages#aee69d68 = InputPrivacyKey;
inputPrivacyKeyAbout#3823cc40 = InputPrivacyKey;
inputPrivacyKeyBirthday#d65a11cc = InputPrivacyKey;
inputPrivacyKeyStarGiftsAutoSave#e1732341 = InputPrivacyKey;
inputPrivacyKeyNoPaidMessages#bdc597b4 = InputPrivacyKey;
privacyKeyStatusTimestamp#bc2eab30 = PrivacyKey;
privacyKeyChatInvite#500e6dfa = PrivacyKey;
privacyKeyPhoneCall#3d662b7b = PrivacyKey;
privacyKeyPhoneP2P#39491cc8 = PrivacyKey;
privacyKeyForwards#69ec56a3 = PrivacyKey;
privacyKeyProfilePhoto#96151fed = PrivacyKey;
privacyKeyPhoneNumber#d19ae46d = PrivacyKey;
privacyKeyAddedByPhone#42ffd42b = PrivacyKey;
privacyKeyVoiceMessages#697f414 = PrivacyKey;
privacyKeyAbout#a486b761 = PrivacyKey;
privacyKeyBirthday#2000a518 = PrivacyKey;
privacyKeyStarGiftsAutoSave#2ca4fdf8 = PrivacyKey;
privacyKeyNoPaidMessages#17d348d2 = PrivacyKey;
inputPrivacyValueAllowContacts#d09e07b = InputPrivacyRule;
inputPrivacyValueAllowAll#184b35ce = InputPrivacyRule;
inputPrivacyValueAllowUsers#131cc67f users:Vector<InputUser> = InputPrivacyRule;
inputPrivacyValueDisallowContacts#ba52007 = InputPrivacyRule;
inputPrivacyValueDisallowAll#d66b66c9 = InputPrivacyRule;
inputPrivacyValueDisallowUsers#90110467 users:Vector<InputUser> = InputPrivacyRule;
inputPrivacyValueAllowChatParticipants#840649cf chats:Vector<long> = InputPrivacyRule;
inputPrivacyValueDisallowChatParticipants#e94f0f86 chats:Vector<long> = InputPrivacyRule;
inputPrivacyValueAllowCloseFriends#2f453e49 = InputPrivacyRule;
inputPrivacyValueAllowPremium#77cdc9f1 = InputPrivacyRule;
inputPrivacyValueAllowBots#5a4fcce5 = InputPrivacyRule;
inputPrivacyValueDisallowBots#c4e57915 = InputPrivacyRule;
privacyValueAllowContacts#fffe1bac = PrivacyRule;
privacyValueAllowAll#65427b82 = PrivacyRule;
privacyValueAllowUsers#b8905fb2 users:Vector<long> = PrivacyRule;
privacyValueDisallowContacts#f888fa1a = PrivacyRule;
privacyValueDisallowAll#8b73e763 = PrivacyRule;
privacyValueDisallowUsers#e4621141 users:Vector<long> = PrivacyRule;
privacyValueAllowChatParticipants#6b134e8e chats:Vector<long> = PrivacyRule;
privacyValueDisallowChatParticipants#41c87565 chats:Vector<long> = PrivacyRule;
privacyValueAllowCloseFriends#f7e8d89b = PrivacyRule;
privacyValueAllowPremium#ece9814b = PrivacyRule;
privacyValueAllowBots#21461b5d = PrivacyRule;
privacyValueDisallowBots#f6a5f82f = PrivacyRule;
account.privacyRules#50a04e45 rules:Vector<PrivacyRule> chats:Vector<Chat> users:Vector<User> = account.PrivacyRules;
accountDaysTTL#b8d0afdf days:int = AccountDaysTTL;
documentAttributeImageSize#6c37c15c w:int h:int = DocumentAttribute;
documentAttributeAnimated#11b58939 = DocumentAttribute;
documentAttributeSticker#6319d612 flags:# mask:flags.1?true alt:string stickerset:InputStickerSet mask_coords:flags.0?MaskCoords = DocumentAttribute;
documentAttributeVideo#43c57c48 flags:# round_message:flags.0?true supports_streaming:flags.1?true nosound:flags.3?true duration:double w:int h:int preload_prefix_size:flags.2?int video_start_ts:flags.4?double video_codec:flags.5?string = DocumentAttribute;
documentAttributeAudio#9852f9c6 flags:# voice:flags.10?true duration:int title:flags.0?string performer:flags.1?string waveform:flags.2?bytes = DocumentAttribute;
documentAttributeFilename#15590068 file_name:string = DocumentAttribute;
documentAttributeHasStickers#9801d2f7 = DocumentAttribute;
documentAttributeCustomEmoji#fd149899 flags:# free:flags.0?true text_color:flags.1?true alt:string stickerset:InputStickerSet = DocumentAttribute;
messages.stickersNotModified#f1749a22 = messages.Stickers;
messages.stickers#30a6ec7e hash:long stickers:Vector<Document> = messages.Stickers;
stickerPack#12b299d4 emoticon:string documents:Vector<long> = StickerPack;
messages.allStickersNotModified#e86602c3 = messages.AllStickers;
messages.allStickers#cdbbcebb hash:long sets:Vector<StickerSet> = messages.AllStickers;
messages.affectedMessages#84d19185 pts:int pts_count:int = messages.AffectedMessages;
webPageEmpty#211a1788 flags:# id:long url:flags.0?string = WebPage;
webPagePending#b0d13e47 flags:# id:long url:flags.0?string date:int = WebPage;
webPage#e89c45b2 flags:# has_large_media:flags.13?true video_cover_photo:flags.14?true id:long url:string display_url:string hash:int type:flags.0?string site_name:flags.1?string title:flags.2?string description:flags.3?string photo:flags.4?Photo embed_url:flags.5?string embed_type:flags.5?string embed_width:flags.6?int embed_height:flags.6?int duration:flags.7?int author:flags.8?string document:flags.9?Document cached_page:flags.10?Page attributes:flags.12?Vector<WebPageAttribute> = WebPage;
webPageNotModified#7311ca11 flags:# cached_page_views:flags.0?int = WebPage;
authorization#ad01d61d flags:# current:flags.0?true official_app:flags.1?true password_pending:flags.2?true encrypted_requests_disabled:flags.3?true call_requests_disabled:flags.4?true unconfirmed:flags.5?true hash:long device_model:string platform:string system_version:string api_id:int app_name:string app_version:string date_created:int date_active:int ip:string country:string region:string = Authorization;
account.authorizations#4bff8ea0 authorization_ttl_days:int authorizations:Vector<Authorization> = account.Authorizations;
account.password#957b50fb flags:# has_recovery:flags.0?true has_secure_values:flags.1?true has_password:flags.2?true current_algo:flags.2?PasswordKdfAlgo srp_B:flags.2?bytes srp_id:flags.2?long hint:flags.3?string email_unconfirmed_pattern:flags.4?string new_algo:PasswordKdfAlgo new_secure_algo:SecurePasswordKdfAlgo secure_random:bytes pending_reset_date:flags.5?int login_email_pattern:flags.6?string = account.Password;
account.passwordSettings#9a5c33e5 flags:# email:flags.0?string secure_settings:flags.1?SecureSecretSettings = account.PasswordSettings;
account.passwordInputSettings#c23727c9 flags:# new_algo:flags.0?PasswordKdfAlgo new_password_hash:flags.0?bytes hint:flags.0?string email:flags.1?string new_secure_settings:flags.2?SecureSecretSettings = account.PasswordInputSettings;
auth.passwordRecovery#137948a5 email_pattern:string = auth.PasswordRecovery;
receivedNotifyMessage#a384b779 id:int flags:int = ReceivedNotifyMessage;
chatInviteExported#a22cbd96 flags:# revoked:flags.0?true permanent:flags.5?true request_needed:flags.6?true link:string admin_id:long date:int start_date:flags.4?int expire_date:flags.1?int usage_limit:flags.2?int usage:flags.3?int requested:flags.7?int subscription_expired:flags.10?int title:flags.8?string subscription_pricing:flags.9?StarsSubscriptionPricing = ExportedChatInvite;
chatInvitePublicJoinRequests#ed107ab7 = ExportedChatInvite;
chatInviteAlready#5a686d7c chat:Chat = ChatInvite;
chatInvite#5c9d3702 flags:# channel:flags.0?true broadcast:flags.1?true public:flags.2?true megagroup:flags.3?true request_needed:flags.6?true verified:flags.7?true scam:flags.8?true fake:flags.9?true can_refulfill_subscription:flags.11?true title:string about:flags.5?string photo:Photo participants_count:int participants:flags.4?Vector<User> color:int subscription_pricing:flags.10?StarsSubscriptionPricing subscription_form_id:flags.12?long bot_verification:flags.13?BotVerification = ChatInvite;
chatInvitePeek#61695cb0 chat:Chat expires:int = ChatInvite;
inputStickerSetEmpty#ffb62b95 = InputStickerSet;
inputStickerSetID#9de7a269 id:long access_hash:long = InputStickerSet;
inputStickerSetShortName#861cc8a0 short_name:string = InputStickerSet;
inputStickerSetAnimatedEmoji#28703c8 = InputStickerSet;
inputStickerSetDice#e67f520e emoticon:string = InputStickerSet;
inputStickerSetAnimatedEmojiAnimations#cde3739 = InputStickerSet;
inputStickerSetPremiumGifts#c88b3b02 = InputStickerSet;
inputStickerSetEmojiGenericAnimations#4c4d4ce = InputStickerSet;
inputStickerSetEmojiDefaultStatuses#29d0f5ee = InputStickerSet;
inputStickerSetEmojiDefaultTopicIcons#44c1f8e9 = InputStickerSet;
inputStickerSetEmojiChannelDefaultStatuses#49748553 = InputStickerSet;
inputStickerSetTonGifts#1cf671a0 = InputStickerSet;
stickerSet#2dd14edc flags:# archived:flags.1?true official:flags.2?true masks:flags.3?true emojis:flags.7?true text_color:flags.9?true channel_emoji_status:flags.10?true creator:flags.11?true installed_date:flags.0?int id:long access_hash:long title:string short_name:string thumbs:flags.4?Vector<PhotoSize> thumb_dc_id:flags.4?int thumb_version:flags.4?int thumb_document_id:flags.8?long count:int hash:int = StickerSet;
messages.stickerSet#6e153f16 set:StickerSet packs:Vector<StickerPack> keywords:Vector<StickerKeyword> documents:Vector<Document> = messages.StickerSet;
messages.stickerSetNotModified#d3f924eb = messages.StickerSet;
botCommand#c27ac8c7 command:string description:string = BotCommand;
botInfo#4d8a0299 flags:# has_preview_medias:flags.6?true user_id:flags.0?long description:flags.1?string description_photo:flags.4?Photo description_document:flags.5?Document commands:flags.2?Vector<BotCommand> menu_button:flags.3?BotMenuButton privacy_policy_url:flags.7?string app_settings:flags.8?BotAppSettings verifier_settings:flags.9?BotVerifierSettings = BotInfo;
keyboardButton#a2fa4880 text:string = KeyboardButton;
keyboardButtonUrl#258aff05 text:string url:string = KeyboardButton;
keyboardButtonCallback#35bbdb6b flags:# requires_password:flags.0?true text:string data:bytes = KeyboardButton;
keyboardButtonRequestPhone#b16a6c29 text:string = KeyboardButton;
keyboardButtonRequestGeoLocation#fc796b3f text:string = KeyboardButton;
keyboardButtonSwitchInline#93b9fbb5 flags:# same_peer:flags.0?true text:string query:string peer_types:flags.1?Vector<InlineQueryPeerType> = KeyboardButton;
keyboardButtonGame#50f41ccf text:string = KeyboardButton;
keyboardButtonBuy#afd93fbb text:string = KeyboardButton;
keyboardButtonUrlAuth#10b78d29 flags:# text:string fwd_text:flags.0?string url:string button_id:int = KeyboardButton;
inputKeyboardButtonUrlAuth#d02e7fd4 flags:# request_write_access:flags.0?true text:string fwd_text:flags.1?string url:string bot:InputUser = KeyboardButton;
keyboardButtonRequestPoll#bbc7515d flags:# quiz:flags.0?Bool text:string = KeyboardButton;
inputKeyboardButtonUserProfile#e988037b text:string user_id:InputUser = KeyboardButton;
keyboardButtonUserProfile#308660c1 text:string user_id:long = KeyboardButton;
keyboardButtonWebView#13767230 text:string url:string = KeyboardButton;
keyboardButtonSimpleWebView#a0c0505c text:string url:string = KeyboardButton;
keyboardButtonRequestPeer#53d7bfd8 text:string button_id:int peer_type:RequestPeerType max_quantity:int = KeyboardButton;
inputKeyboardButtonRequestPeer#c9662d05 flags:# name_requested:flags.0?true username_requested:flags.1?true photo_requested:flags.2?true text:string button_id:int peer_type:RequestPeerType max_quantity:int = KeyboardButton;
keyboardButtonCopy#75d2698e text:string copy_text:string = KeyboardButton;
keyboardButtonRow#77608b83 buttons:Vector<KeyboardButton> = KeyboardButtonRow;
replyKeyboardHide#a03e5b85 flags:# selective:flags.2?true = ReplyMarkup;
replyKeyboardForceReply#86b40b08 flags:# single_use:flags.1?true selective:flags.2?true placeholder:flags.3?string = ReplyMarkup;
replyKeyboardMarkup#85dd99d1 flags:# resize:flags.0?true single_use:flags.1?true selective:flags.2?true persistent:flags.4?true rows:Vector<KeyboardButtonRow> placeholder:flags.3?string = ReplyMarkup;
replyInlineMarkup#48a30254 rows:Vector<KeyboardButtonRow> = ReplyMarkup;
messageEntityUnknown#bb92ba95 offset:int length:int = MessageEntity;
messageEntityMention#fa04579d offset:int length:int = MessageEntity;
messageEntityHashtag#6f635b0d offset:int length:int = MessageEntity;
messageEntityBotCommand#6cef8ac7 offset:int length:int = MessageEntity;
messageEntityUrl#6ed02538 offset:int length:int = MessageEntity;
messageEntityEmail#64e475c2 offset:int length:int = MessageEntity;
messageEntityBold#bd610bc9 offset:int length:int = MessageEntity;
messageEntityItalic#826f8b60 offset:int length:int = MessageEntity;
messageEntityCode#28a20571 offset:int length:int = MessageEntity;
messageEntityPre#73924be0 offset:int length:int language:string = MessageEntity;
messageEntityTextUrl#76a6d327 offset:int length:int url:string = MessageEntity;
messageEntityMentionName#dc7b1140 offset:int length:int user_id:long = MessageEntity;
inputMessageEntityMentionName#208e68c9 offset:int length:int user_id:InputUser = MessageEntity;
messageEntityPhone#9b69e34b offset:int length:int = MessageEntity;
messageEntityCashtag#4c4e743f offset:int length:int = MessageEntity;
messageEntityUnderline#9c4e7e8b offset:int length:int = MessageEntity;
messageEntityStrike#bf0693d4 offset:int length:int = MessageEntity;
messageEntityBankCard#761e6af4 offset:int length:int = MessageEntity;
messageEntitySpoiler#32ca960f offset:int length:int = MessageEntity;
messageEntityCustomEmoji#c8cf05f8 offset:int length:int document_id:long = MessageEntity;
messageEntityBlockquote#f1ccaaac flags:# collapsed:flags.0?true offset:int length:int = MessageEntity;
inputChannelEmpty#ee8c1e86 = InputChannel;
inputChannel#f35aec28 channel_id:long access_hash:long = InputChannel;
inputChannelFromMessage#5b934f9d peer:InputPeer msg_id:int channel_id:long = InputChannel;
contacts.resolvedPeer#7f077ad9 peer:Peer chats:Vector<Chat> users:Vector<User> = contacts.ResolvedPeer;
messageRange#ae30253 min_id:int max_id:int = MessageRange;
updates.channelDifferenceEmpty#3e11affb flags:# final:flags.0?true pts:int timeout:flags.1?int = updates.ChannelDifference;
updates.channelDifferenceTooLong#a4bcc6fe flags:# final:flags.0?true timeout:flags.1?int dialog:Dialog messages:Vector<Message> chats:Vector<Chat> users:Vector<User> = updates.ChannelDifference;
updates.channelDifference#2064674e flags:# final:flags.0?true pts:int timeout:flags.1?int new_messages:Vector<Message> other_updates:Vector<Update> chats:Vector<Chat> users:Vector<User> = updates.ChannelDifference;
channelMessagesFilterEmpty#94d42ee7 = ChannelMessagesFilter;
channelMessagesFilter#cd77d957 flags:# exclude_new_messages:flags.1?true ranges:Vector<MessageRange> = ChannelMessagesFilter;
channelParticipant#cb397619 flags:# user_id:long date:int subscription_until_date:flags.0?int = ChannelParticipant;
channelParticipantSelf#4f607bef flags:# via_request:flags.0?true user_id:long inviter_id:long date:int subscription_until_date:flags.1?int = ChannelParticipant;
channelParticipantCreator#2fe601d3 flags:# user_id:long admin_rights:ChatAdminRights rank:flags.0?string = ChannelParticipant;
channelParticipantAdmin#34c3bb53 flags:# can_edit:flags.0?true self:flags.1?true user_id:long inviter_id:flags.1?long promoted_by:long date:int admin_rights:ChatAdminRights rank:flags.2?string = ChannelParticipant;
channelParticipantBanned#6df8014e flags:# left:flags.0?true peer:Peer kicked_by:long date:int banned_rights:ChatBannedRights = ChannelParticipant;
channelParticipantLeft#1b03f006 peer:Peer = ChannelParticipant;
channelParticipantsRecent#de3f3c79 = ChannelParticipantsFilter;
channelParticipantsAdmins#b4608969 = ChannelParticipantsFilter;
channelParticipantsKicked#a3b54985 q:string = ChannelParticipantsFilter;
channelParticipantsBots#b0d1865b = ChannelParticipantsFilter;
channelParticipantsBanned#1427a5e1 q:string = ChannelParticipantsFilter;
channelParticipantsSearch#656ac4b q:string = ChannelParticipantsFilter;
channelParticipantsContacts#bb6ae88d q:string = ChannelParticipantsFilter;
channelParticipantsMentions#e04b5ceb flags:# q:flags.0?string top_msg_id:flags.1?int = ChannelParticipantsFilter;
channels.channelParticipants#9ab0feaf count:int participants:Vector<ChannelParticipant> chats:Vector<Chat> users:Vector<User> = channels.ChannelParticipants;
channels.channelParticipantsNotModified#f0173fe9 = channels.ChannelParticipants;
channels.channelParticipant#dfb80317 participant:ChannelParticipant chats:Vector<Chat> users:Vector<User> = channels.ChannelParticipant;
help.termsOfService#780a0310 flags:# popup:flags.0?true id:DataJSON text:string entities:Vector<MessageEntity> min_age_confirm:flags.1?int = help.TermsOfService;
messages.savedGifsNotModified#e8025ca2 = messages.SavedGifs;
messages.savedGifs#84a02a0d hash:long gifs:Vector<Document> = messages.SavedGifs;
inputBotInlineMessageMediaAuto#3380c786 flags:# invert_media:flags.3?true message:string entities:flags.1?Vector<MessageEntity> reply_markup:flags.2?ReplyMarkup = InputBotInlineMessage;
inputBotInlineMessageText#3dcd7a87 flags:# no_webpage:flags.0?true invert_media:flags.3?true message:string entities:flags.1?Vector<MessageEntity> reply_markup:flags.2?ReplyMarkup = InputBotInlineMessage;
inputBotInlineMessageMediaGeo#96929a85 flags:# geo_point:InputGeoPoint heading:flags.0?int period:flags.1?int proximity_notification_radius:flags.3?int reply_markup:flags.2?ReplyMarkup = InputBotInlineMessage;
inputBotInlineMessageMediaVenue#417bbf11 flags:# geo_point:InputGeoPoint title:string address:string provider:string venue_id:string venue_type:string reply_markup:flags.2?ReplyMarkup = InputBotInlineMessage;
inputBotInlineMessageMediaContact#a6edbffd flags:# phone_number:string first_name:string last_name:string vcard:string reply_markup:flags.2?ReplyMarkup = InputBotInlineMessage;
inputBotInlineMessageGame#4b425864 flags:# reply_markup:flags.2?ReplyMarkup = InputBotInlineMessage;
inputBotInlineMessageMediaInvoice#d7e78225 flags:# title:string description:string photo:flags.0?InputWebDocument invoice:Invoice payload:bytes provider:string provider_data:DataJSON reply_markup:flags.2?ReplyMarkup = InputBotInlineMessage;
inputBotInlineMessageMediaWebPage#bddcc510 flags:# invert_media:flags.3?true force_large_media:flags.4?true force_small_media:flags.5?true optional:flags.6?true message:string entities:flags.1?Vector<MessageEntity> url:string reply_markup:flags.2?ReplyMarkup = InputBotInlineMessage;
inputBotInlineResult#88bf9319 flags:# id:string type:string title:flags.1?string description:flags.2?string url:flags.3?string thumb:flags.4?InputWebDocument content:flags.5?InputWebDocument send_message:InputBotInlineMessage = InputBotInlineResult;
inputBotInlineResultPhoto#a8d864a7 id:string type:string photo:InputPhoto send_message:InputBotInlineMessage = InputBotInlineResult;
inputBotInlineResultDocument#fff8fdc4 flags:# id:string type:string title:flags.1?string description:flags.2?string document:InputDocument send_message:InputBotInlineMessage = InputBotInlineResult;
inputBotInlineResultGame#4fa417f2 id:string short_name:string send_message:InputBotInlineMessage = InputBotInlineResult;
botInlineMessageMediaAuto#764cf810 flags:# invert_media:flags.3?true message:string entities:flags.1?Vector<MessageEntity> reply_markup:flags.2?ReplyMarkup = BotInlineMessage;
botInlineMessageText#8c7f65e2 flags:# no_webpage:flags.0?true invert_media:flags.3?true message:string entities:flags.1?Vector<MessageEntity> reply_markup:flags.2?ReplyMarkup = BotInlineMessage;
botInlineMessageMediaGeo#51846fd flags:# geo:GeoPoint heading:flags.0?int period:flags.1?int proximity_notification_radius:flags.3?int reply_markup:flags.2?ReplyMarkup = BotInlineMessage;
botInlineMessageMediaVenue#8a86659c flags:# geo:GeoPoint title:string address:string provider:string venue_id:string venue_type:string reply_markup:flags.2?ReplyMarkup = BotInlineMessage;
botInlineMessageMediaContact#18d1cdc2 flags:# phone_number:string first_name:string last_name:string vcard:string reply_markup:flags.2?ReplyMarkup = BotInlineMessage;
botInlineMessageMediaInvoice#354a9b09 flags:# shipping_address_requested:flags.1?true test:flags.3?true title:string description:string photo:flags.0?WebDocument currency:string total_amount:long reply_markup:flags.2?ReplyMarkup = BotInlineMessage;
botInlineMessageMediaWebPage#809ad9a6 flags:# invert_media:flags.3?true force_large_media:flags.4?true force_small_media:flags.5?true manual:flags.7?true safe:flags.8?true message:string entities:flags.1?Vector<MessageEntity> url:string reply_markup:flags.2?ReplyMarkup = BotInlineMessage;
botInlineResult#11965f3a flags:# id:string type:string title:flags.1?string description:flags.2?string url:flags.3?string thumb:flags.4?WebDocument content:flags.5?WebDocument send_message:BotInlineMessage = BotInlineResult;
botInlineMediaResult#17db940b flags:# id:string type:string photo:flags.0?Photo document:flags.1?Document title:flags.2?string description:flags.3?string send_message:BotInlineMessage = BotInlineResult;
messages.botResults#e021f2f6 flags:# gallery:flags.0?true query_id:long next_offset:flags.1?string switch_pm:flags.2?InlineBotSwitchPM switch_webview:flags.3?InlineBotWebView results:Vector<BotInlineResult> cache_time:int users:Vector<User> = messages.BotResults;
exportedMessageLink#5dab1af4 link:string html:string = ExportedMessageLink;
messageFwdHeader#4e4df4bb flags:# imported:flags.7?true saved_out:flags.11?true from_id:flags.0?Peer from_name:flags.5?string date:int channel_post:flags.2?int post_author:flags.3?string saved_from_peer:flags.4?Peer saved_from_msg_id:flags.4?int saved_from_id:flags.8?Peer saved_from_name:flags.9?string saved_date:flags.10?int psa_type:flags.6?string = MessageFwdHeader;
auth.codeTypeSms#72a3158c = auth.CodeType;
auth.codeTypeCall#741cd3e3 = auth.CodeType;
auth.codeTypeFlashCall#226ccefb = auth.CodeType;
auth.codeTypeMissedCall#d61ad6ee = auth.CodeType;
auth.codeTypeFragmentSms#6ed998c = auth.CodeType;
auth.sentCodeTypeApp#3dbb5986 length:int = auth.SentCodeType;
auth.sentCodeTypeSms#c000bba2 length:int = auth.SentCodeType;
auth.sentCodeTypeCall#5353e5a7 length:int = auth.SentCodeType;
auth.sentCodeTypeFlashCall#ab03c6d9 pattern:string = auth.SentCodeType;
auth.sentCodeTypeMissedCall#82006484 prefix:string length:int = auth.SentCodeType;
auth.sentCodeTypeEmailCode#f450f59b flags:# apple_signin_allowed:flags.0?true google_signin_allowed:flags.1?true email_pattern:string length:int reset_available_period:flags.3?int reset_pending_date:flags.4?int = auth.SentCodeType;
auth.sentCodeTypeSetUpEmailRequired#a5491dea flags:# apple_signin_allowed:flags.0?true google_signin_allowed:flags.1?true = auth.SentCodeType;
auth.sentCodeTypeFragmentSms#d9565c39 url:string length:int = auth.SentCodeType;
auth.sentCodeTypeFirebaseSms#9fd736 flags:# nonce:flags.0?bytes play_integrity_project_id:flags.2?long play_integrity_nonce:flags.2?bytes receipt:flags.1?string push_timeout:flags.1?int length:int = auth.SentCodeType;
auth.sentCodeTypeSmsWord#a416ac81 flags:# beginning:flags.0?string = auth.SentCodeType;
auth.sentCodeTypeSmsPhrase#b37794af flags:# beginning:flags.0?string = auth.SentCodeType;
messages.botCallbackAnswer#36585ea4 flags:# alert:flags.1?true has_url:flags.3?true native_ui:flags.4?true message:flags.0?string url:flags.2?string cache_time:int = messages.BotCallbackAnswer;
messages.messageEditData#26b5dde6 flags:# caption:flags.0?true = messages.MessageEditData;
inputBotInlineMessageID#890c3d89 dc_id:int id:long access_hash:long = InputBotInlineMessageID;
inputBotInlineMessageID64#b6d915d7 dc_id:int owner_id:long id:int access_hash:long = InputBotInlineMessageID;
inlineBotSwitchPM#3c20629f text:string start_param:string = InlineBotSwitchPM;
messages.peerDialogs#3371c354 dialogs:Vector<Dialog> messages:Vector<Message> chats:Vector<Chat> users:Vector<User> state:updates.State = messages.PeerDialogs;
topPeer#edcdc05b peer:Peer rating:double = TopPeer;
topPeerCategoryBotsPM#ab661b5b = TopPeerCategory;
topPeerCategoryBotsInline#148677e2 = TopPeerCategory;
topPeerCategoryCorrespondents#637b7ed = TopPeerCategory;
topPeerCategoryGroups#bd17a14a = TopPeerCategory;
topPeerCategoryChannels#161d9628 = TopPeerCategory;
topPeerCategoryPhoneCalls#1e76a78c = TopPeerCategory;
topPeerCategoryForwardUsers#a8406ca9 = TopPeerCategory;
topPeerCategoryForwardChats#fbeec0f0 = TopPeerCategory;
topPeerCategoryBotsApp#fd9e7bec = TopPeerCategory;
topPeerCategoryPeers#fb834291 category:TopPeerCategory count:int peers:Vector<TopPeer> = TopPeerCategoryPeers;
contacts.topPeersNotModified#de266ef5 = contacts.TopPeers;
contacts.topPeers#70b772a8 categories:Vector<TopPeerCategoryPeers> chats:Vector<Chat> users:Vector<User> = contacts.TopPeers;
contacts.topPeersDisabled#b52c939d = contacts.TopPeers;
draftMessageEmpty#1b0c841a flags:# date:flags.0?int = DraftMessage;
draftMessage#96eaa5eb flags:# no_webpage:flags.1?true invert_media:flags.6?true reply_to:flags.4?InputReplyTo message:string entities:flags.3?Vector<MessageEntity> media:flags.5?InputMedia date:int effect:flags.7?long suggested_post:flags.8?SuggestedPost = DraftMessage;
messages.featuredStickersNotModified#c6dc0c66 count:int = messages.FeaturedStickers;
messages.featuredStickers#be382906 flags:# premium:flags.0?true hash:long count:int sets:Vector<StickerSetCovered> unread:Vector<long> = messages.FeaturedStickers;
messages.recentStickersNotModified#b17f890 = messages.RecentStickers;
messages.recentStickers#88d37c56 hash:long packs:Vector<StickerPack> stickers:Vector<Document> dates:Vector<int> = messages.RecentStickers;
messages.archivedStickers#4fcba9c8 count:int sets:Vector<StickerSetCovered> = messages.ArchivedStickers;
messages.stickerSetInstallResultSuccess#38641628 = messages.StickerSetInstallResult;
messages.stickerSetInstallResultArchive#35e410a8 sets:Vector<StickerSetCovered> = messages.StickerSetInstallResult;
stickerSetCovered#6410a5d2 set:StickerSet cover:Document = StickerSetCovered;
stickerSetMultiCovered#3407e51b set:StickerSet covers:Vector<Document> = StickerSetCovered;
stickerSetFullCovered#40d13c0e set:StickerSet packs:Vector<StickerPack> keywords:Vector<StickerKeyword> documents:Vector<Document> = StickerSetCovered;
stickerSetNoCovered#77b15d1c set:StickerSet = StickerSetCovered;
maskCoords#aed6dbb2 n:int x:double y:double zoom:double = MaskCoords;
inputStickeredMediaPhoto#4a992157 id:InputPhoto = InputStickeredMedia;
inputStickeredMediaDocument#438865b id:InputDocument = InputStickeredMedia;
game#bdf9653b flags:# id:long access_hash:long short_name:string title:string description:string photo:Photo document:flags.0?Document = Game;
inputGameID#32c3e77 id:long access_hash:long = InputGame;
inputGameShortName#c331e80a bot_id:InputUser short_name:string = InputGame;
highScore#73a379eb pos:int user_id:long score:int = HighScore;
messages.highScores#9a3bfd99 scores:Vector<HighScore> users:Vector<User> = messages.HighScores;
textEmpty#dc3d824f = RichText;
textPlain#744694e0 text:string = RichText;
textBold#6724abc4 text:RichText = RichText;
textItalic#d912a59c text:RichText = RichText;
textUnderline#c12622c4 text:RichText = RichText;
textStrike#9bf8bb95 text:RichText = RichText;
textFixed#6c3f19b9 text:RichText = RichText;
textUrl#3c2884c1 text:RichText url:string webpage_id:long = RichText;
textEmail#de5a0dd6 text:RichText email:string = RichText;
textConcat#7e6260d7 texts:Vector<RichText> = RichText;
textSubscript#ed6a8504 text:RichText = RichText;
textSuperscript#c7fb5e01 text:RichText = RichText;
textMarked#34b8621 text:RichText = RichText;
textPhone#1ccb966a text:RichText phone:string = RichText;
textImage#81ccf4f document_id:long w:int h:int = RichText;
textAnchor#35553762 text:RichText name:string = RichText;
pageBlockUnsupported#13567e8a = PageBlock;
pageBlockTitle#70abc3fd text:RichText = PageBlock;
pageBlockSubtitle#8ffa9a1f text:RichText = PageBlock;
pageBlockAuthorDate#baafe5e0 author:RichText published_date:int = PageBlock;
pageBlockHeader#bfd064ec text:RichText = PageBlock;
pageBlockSubheader#f12bb6e1 text:RichText = PageBlock;
pageBlockParagraph#467a0766 text:RichText = PageBlock;
pageBlockPreformatted#c070d93e text:RichText language:string = PageBlock;
pageBlockFooter#48870999 text:RichText = PageBlock;
pageBlockDivider#db20b188 = PageBlock;
pageBlockAnchor#ce0d37b0 name:string = PageBlock;
pageBlockList#e4e88011 items:Vector<PageListItem> = PageBlock;
pageBlockBlockquote#263d7c26 text:RichText caption:RichText = PageBlock;
pageBlockPullquote#4f4456d3 text:RichText caption:RichText = PageBlock;
pageBlockPhoto#1759c560 flags:# photo_id:long caption:PageCaption url:flags.0?string webpage_id:flags.0?long = PageBlock;
pageBlockVideo#7c8fe7b6 flags:# autoplay:flags.0?true loop:flags.1?true video_id:long caption:PageCaption = PageBlock;
pageBlockCover#39f23300 cover:PageBlock = PageBlock;
pageBlockEmbed#a8718dc5 flags:# full_width:flags.0?true allow_scrolling:flags.3?true url:flags.1?string html:flags.2?string poster_photo_id:flags.4?long w:flags.5?int h:flags.5?int caption:PageCaption = PageBlock;
pageBlockEmbedPost#f259a80b url:string webpage_id:long author_photo_id:long author:string date:int blocks:Vector<PageBlock> caption:PageCaption = PageBlock;
pageBlockCollage#65a0fa4d items:Vector<PageBlock> caption:PageCaption = PageBlock;
pageBlockSlideshow#31f9590 items:Vector<PageBlock> caption:PageCaption = PageBlock;
pageBlockChannel#ef1751b5 channel:Chat = PageBlock;
pageBlockAudio#804361ea audio_id:long caption:PageCaption = PageBlock;
pageBlockKicker#1e148390 text:RichText = PageBlock;
pageBlockTable#bf4dea82 flags:# bordered:flags.0?true striped:flags.1?true title:RichText rows:Vector<PageTableRow> = PageBlock;
pageBlockOrderedList#9a8ae1e1 items:Vector<PageListOrderedItem> = PageBlock;
pageBlockDetails#76768bed flags:# open:flags.0?true blocks:Vector<PageBlock> title:RichText = PageBlock;
pageBlockRelatedArticles#16115a96 title:RichText articles:Vector<PageRelatedArticle> = PageBlock;
pageBlockMap#a44f3ef6 geo:GeoPoint zoom:int w:int h:int caption:PageCaption = PageBlock;
phoneCallDiscardReasonMissed#85e42301 = PhoneCallDiscardReason;
phoneCallDiscardReasonDisconnect#e095c1a0 = PhoneCallDiscardReason;
phoneCallDiscardReasonHangup#57adc690 = PhoneCallDiscardReason;
phoneCallDiscardReasonBusy#faf7e8c9 = PhoneCallDiscardReason;
phoneCallDiscardReasonMigrateConferenceCall#9fbbf1f7 slug:string = PhoneCallDiscardReason;
dataJSON#7d748d04 data:string = DataJSON;
labeledPrice#cb296bf8 label:string amount:long = LabeledPrice;
invoice#49ee584 flags:# test:flags.0?true name_requested:flags.1?true phone_requested:flags.2?true email_requested:flags.3?true shipping_address_requested:flags.4?true flexible:flags.5?true phone_to_provider:flags.6?true email_to_provider:flags.7?true recurring:flags.9?true currency:string prices:Vector<LabeledPrice> max_tip_amount:flags.8?long suggested_tip_amounts:flags.8?Vector<long> terms_url:flags.10?string subscription_period:flags.11?int = Invoice;
paymentCharge#ea02c27e id:string provider_charge_id:string = PaymentCharge;
postAddress#1e8caaeb street_line1:string street_line2:string city:string state:string country_iso2:string post_code:string = PostAddress;
paymentRequestedInfo#909c3f94 flags:# name:flags.0?string phone:flags.1?string email:flags.2?string shipping_address:flags.3?PostAddress = PaymentRequestedInfo;
paymentSavedCredentialsCard#cdc27a1f id:string title:string = PaymentSavedCredentials;
webDocument#1c570ed1 url:string access_hash:long size:int mime_type:string attributes:Vector<DocumentAttribute> = WebDocument;
webDocumentNoProxy#f9c8bcc6 url:string size:int mime_type:string attributes:Vector<DocumentAttribute> = WebDocument;
inputWebDocument#9bed434d url:string size:int mime_type:string attributes:Vector<DocumentAttribute> = InputWebDocument;
inputWebFileLocation#c239d686 url:string access_hash:long = InputWebFileLocation;
inputWebFileGeoPointLocation#9f2221c9 geo_point:InputGeoPoint access_hash:long w:int h:int zoom:int scale:int = InputWebFileLocation;
inputWebFileAudioAlbumThumbLocation#f46fe924 flags:# small:flags.2?true document:flags.0?InputDocument title:flags.1?string performer:flags.1?string = InputWebFileLocation;
upload.webFile#21e753bc size:int mime_type:string file_type:storage.FileType mtime:int bytes:bytes = upload.WebFile;
payments.paymentForm#a0058751 flags:# can_save_credentials:flags.2?true password_missing:flags.3?true form_id:long bot_id:long title:string description:string photo:flags.5?WebDocument invoice:Invoice provider_id:long url:string native_provider:flags.4?string native_params:flags.4?DataJSON additional_methods:flags.6?Vector<PaymentFormMethod> saved_info:flags.0?PaymentRequestedInfo saved_credentials:flags.1?Vector<PaymentSavedCredentials> users:Vector<User> = payments.PaymentForm;
payments.paymentFormStars#7bf6b15c flags:# form_id:long bot_id:long title:string description:string photo:flags.5?WebDocument invoice:Invoice users:Vector<User> = payments.PaymentForm;
payments.paymentFormStarGift#b425cfe1 form_id:long invoice:Invoice = payments.PaymentForm;
payments.validatedRequestedInfo#d1451883 flags:# id:flags.0?string shipping_options:flags.1?Vector<ShippingOption> = payments.ValidatedRequestedInfo;
payments.paymentResult#4e5f810d updates:Updates = payments.PaymentResult;
payments.paymentVerificationNeeded#d8411139 url:string = payments.PaymentResult;
payments.paymentReceipt#70c4fe03 flags:# date:int bot_id:long provider_id:long title:string description:string photo:flags.2?WebDocument invoice:Invoice info:flags.0?PaymentRequestedInfo shipping:flags.1?ShippingOption tip_amount:flags.3?long currency:string total_amount:long credentials_title:string users:Vector<User> = payments.PaymentReceipt;
payments.paymentReceiptStars#dabbf83a flags:# date:int bot_id:long title:string description:string photo:flags.2?WebDocument invoice:Invoice currency:string total_amount:long transaction_id:string users:Vector<User> = payments.PaymentReceipt;
payments.savedInfo#fb8fe43c flags:# has_saved_credentials:flags.1?true saved_info:flags.0?PaymentRequestedInfo = payments.SavedInfo;
inputPaymentCredentialsSaved#c10eb2cf id:string tmp_password:bytes = InputPaymentCredentials;
inputPaymentCredentials#3417d728 flags:# save:flags.0?true data:DataJSON = InputPaymentCredentials;
inputPaymentCredentialsApplePay#aa1c39f payment_data:DataJSON = InputPaymentCredentials;
inputPaymentCredentialsGooglePay#8ac32801 payment_token:DataJSON = InputPaymentCredentials;
account.tmpPassword#db64fd34 tmp_password:bytes valid_until:int = account.TmpPassword;
shippingOption#b6213cdf id:string title:string prices:Vector<LabeledPrice> = ShippingOption;
inputStickerSetItem#32da9e9c flags:# document:InputDocument emoji:string mask_coords:flags.0?MaskCoords keywords:flags.1?string = InputStickerSetItem;
inputPhoneCall#1e36fded id:long access_hash:long = InputPhoneCall;
phoneCallEmpty#5366c915 id:long = PhoneCall;
phoneCallWaiting#c5226f17 flags:# video:flags.6?true id:long access_hash:long date:int admin_id:long participant_id:long protocol:PhoneCallProtocol receive_date:flags.0?int = PhoneCall;
phoneCallRequested#14b0ed0c flags:# video:flags.6?true id:long access_hash:long date:int admin_id:long participant_id:long g_a_hash:bytes protocol:PhoneCallProtocol = PhoneCall;
phoneCallAccepted#3660c311 flags:# video:flags.6?true id:long access_hash:long date:int admin_id:long participant_id:long g_b:bytes protocol:PhoneCallProtocol = PhoneCall;
phoneCall#30535af5 flags:# p2p_allowed:flags.5?true video:flags.6?true conference_supported:flags.8?true id:long access_hash:long date:int admin_id:long participant_id:long g_a_or_b:bytes key_fingerprint:long protocol:PhoneCallProtocol connections:Vector<PhoneConnection> start_date:int custom_parameters:flags.7?DataJSON = PhoneCall;
phoneCallDiscarded#50ca4de1 flags:# need_rating:flags.2?true need_debug:flags.3?true video:flags.6?true id:long reason:flags.0?PhoneCallDiscardReason duration:flags.1?int = PhoneCall;
phoneConnection#9cc123c7 flags:# tcp:flags.0?true id:long ip:string ipv6:string port:int peer_tag:bytes = PhoneConnection;
phoneConnectionWebrtc#635fe375 flags:# turn:flags.0?true stun:flags.1?true id:long ip:string ipv6:string port:int username:string password:string = PhoneConnection;
phoneCallProtocol#fc878fc8 flags:# udp_p2p:flags.0?true udp_reflector:flags.1?true min_layer:int max_layer:int library_versions:Vector<string> = PhoneCallProtocol;
phone.phoneCall#ec82e140 phone_call:PhoneCall users:Vector<User> = phone.PhoneCall;
upload.cdnFileReuploadNeeded#eea8e46e request_token:bytes = upload.CdnFile;
upload.cdnFile#a99fca4f bytes:bytes = upload.CdnFile;
cdnPublicKey#c982eaba dc_id:int public_key:string = CdnPublicKey;
cdnConfig#5725e40a public_keys:Vector<CdnPublicKey> = CdnConfig;
langPackString#cad181f6 key:string value:string = LangPackString;
langPackStringPluralized#6c47ac9f flags:# key:string zero_value:flags.0?string one_value:flags.1?string two_value:flags.2?string few_value:flags.3?string many_value:flags.4?string other_value:string = LangPackString;
langPackStringDeleted#2979eeb2 key:string = LangPackString;
langPackDifference#f385c1f6 lang_code:string from_version:int version:int strings:Vector<LangPackString> = LangPackDifference;
langPackLanguage#eeca5ce3 flags:# official:flags.0?true rtl:flags.2?true beta:flags.3?true name:string native_name:string lang_code:string base_lang_code:flags.1?string plural_code:string strings_count:int translated_count:int translations_url:string = LangPackLanguage;
channelAdminLogEventActionChangeTitle#e6dfb825 prev_value:string new_value:string = ChannelAdminLogEventAction;
channelAdminLogEventActionChangeAbout#55188a2e prev_value:string new_value:string = ChannelAdminLogEventAction;
channelAdminLogEventActionChangeUsername#6a4afc38 prev_value:string new_value:string = ChannelAdminLogEventAction;
channelAdminLogEventActionChangePhoto#434bd2af prev_photo:Photo new_photo:Photo = ChannelAdminLogEventAction;
channelAdminLogEventActionToggleInvites#1b7907ae new_value:Bool = ChannelAdminLogEventAction;
channelAdminLogEventActionToggleSignatures#26ae0971 new_value:Bool = ChannelAdminLogEventAction;
channelAdminLogEventActionUpdatePinned#e9e82c18 message:Message = ChannelAdminLogEventAction;
channelAdminLogEventActionEditMessage#709b2405 prev_message:Message new_message:Message = ChannelAdminLogEventAction;
channelAdminLogEventActionDeleteMessage#42e047bb message:Message = ChannelAdminLogEventAction;
channelAdminLogEventActionParticipantJoin#183040d3 = ChannelAdminLogEventAction;
channelAdminLogEventActionParticipantLeave#f89777f2 = ChannelAdminLogEventAction;
channelAdminLogEventActionParticipantInvite#e31c34d8 participant:ChannelParticipant = ChannelAdminLogEventAction;
channelAdminLogEventActionParticipantToggleBan#e6d83d7e prev_participant:ChannelParticipant new_participant:ChannelParticipant = ChannelAdminLogEventAction;
channelAdminLogEventActionParticipantToggleAdmin#d5676710 prev_participant:ChannelParticipant new_participant:ChannelParticipant = ChannelAdminLogEventAction;
channelAdminLogEventActionChangeStickerSet#b1c3caa7 prev_stickerset:InputStickerSet new_stickerset:InputStickerSet = ChannelAdminLogEventAction;
channelAdminLogEventActionTogglePreHistoryHidden#5f5c95f1 new_value:Bool = ChannelAdminLogEventAction;
channelAdminLogEventActionDefaultBannedRights#2df5fc0a prev_banned_rights:ChatBannedRights new_banned_rights:ChatBannedRights = ChannelAdminLogEventAction;
channelAdminLogEventActionStopPoll#8f079643 message:Message = ChannelAdminLogEventAction;
channelAdminLogEventActionChangeLinkedChat#50c7ac8 prev_value:long new_value:long = ChannelAdminLogEventAction;
channelAdminLogEventActionChangeLocation#e6b76ae prev_value:ChannelLocation new_value:ChannelLocation = ChannelAdminLogEventAction;
channelAdminLogEventActionToggleSlowMode#53909779 prev_value:int new_value:int = ChannelAdminLogEventAction;
channelAdminLogEventActionStartGroupCall#23209745 call:InputGroupCall = ChannelAdminLogEventAction;
channelAdminLogEventActionDiscardGroupCall#db9f9140 call:InputGroupCall = ChannelAdminLogEventAction;
channelAdminLogEventActionParticipantMute#f92424d2 participant:GroupCallParticipant = ChannelAdminLogEventAction;
channelAdminLogEventActionParticipantUnmute#e64429c0 participant:GroupCallParticipant = ChannelAdminLogEventAction;
channelAdminLogEventActionToggleGroupCallSetting#56d6a247 join_muted:Bool = ChannelAdminLogEventAction;
channelAdminLogEventActionParticipantJoinByInvite#fe9fc158 flags:# via_chatlist:flags.0?true invite:ExportedChatInvite = ChannelAdminLogEventAction;
channelAdminLogEventActionExportedInviteDelete#5a50fca4 invite:ExportedChatInvite = ChannelAdminLogEventAction;
channelAdminLogEventActionExportedInviteRevoke#410a134e invite:ExportedChatInvite = ChannelAdminLogEventAction;
channelAdminLogEventActionExportedInviteEdit#e90ebb59 prev_invite:ExportedChatInvite new_invite:ExportedChatInvite = ChannelAdminLogEventAction;
channelAdminLogEventActionParticipantVolume#3e7f6847 participant:GroupCallParticipant = ChannelAdminLogEventAction;
channelAdminLogEventActionChangeHistoryTTL#6e941a38 prev_value:int new_value:int = ChannelAdminLogEventAction;
channelAdminLogEventActionParticipantJoinByRequest#afb6144a invite:ExportedChatInvite approved_by:long = ChannelAdminLogEventAction;
channelAdminLogEventActionToggleNoForwards#cb2ac766 new_value:Bool = ChannelAdminLogEventAction;
channelAdminLogEventActionSendMessage#278f2868 message:Message = ChannelAdminLogEventAction;
channelAdminLogEventActionChangeAvailableReactions#be4e0ef8 prev_value:ChatReactions new_value:ChatReactions = ChannelAdminLogEventAction;
channelAdminLogEventActionChangeUsernames#f04fb3a9 prev_value:Vector<string> new_value:Vector<string> = ChannelAdminLogEventAction;
channelAdminLogEventActionToggleForum#2cc6383 new_value:Bool = ChannelAdminLogEventAction;
channelAdminLogEventActionCreateTopic#58707d28 topic:ForumTopic = ChannelAdminLogEventAction;
channelAdminLogEventActionEditTopic#f06fe208 prev_topic:ForumTopic new_topic:ForumTopic = ChannelAdminLogEventAction;
channelAdminLogEventActionDeleteTopic#ae168909 topic:ForumTopic = ChannelAdminLogEventAction;
channelAdminLogEventActionPinTopic#5d8d353b flags:# prev_topic:flags.0?ForumTopic new_topic:flags.1?ForumTopic = ChannelAdminLogEventAction;
channelAdminLogEventActionToggleAntiSpam#64f36dfc new_value:Bool = ChannelAdminLogEventAction;
channelAdminLogEventActionChangePeerColor#5796e780 prev_value:PeerColor new_value:PeerColor = ChannelAdminLogEventAction;
channelAdminLogEventActionChangeProfilePeerColor#5e477b25 prev_value:PeerColor new_value:PeerColor = ChannelAdminLogEventAction;
channelAdminLogEventActionChangeWallpaper#31bb5d52 prev_value:WallPaper new_value:WallPaper = ChannelAdminLogEventAction;
channelAdminLogEventActionChangeEmojiStatus#3ea9feb1 prev_value:EmojiStatus new_value:EmojiStatus = ChannelAdminLogEventAction;
channelAdminLogEventActionChangeEmojiStickerSet#46d840ab prev_stickerset:InputStickerSet new_stickerset:InputStickerSet = ChannelAdminLogEventAction;
channelAdminLogEventActionToggleSignatureProfiles#60a79c79 new_value:Bool = ChannelAdminLogEventAction;
channelAdminLogEventActionParticipantSubExtend#64642db3 prev_participant:ChannelParticipant new_participant:ChannelParticipant = ChannelAdminLogEventAction;
channelAdminLogEventActionToggleAutotranslation#c517f77e new_value:Bool = ChannelAdminLogEventAction;
channelAdminLogEvent#1fad68cd id:long date:int user_id:long action:ChannelAdminLogEventAction = ChannelAdminLogEvent;
channels.adminLogResults#ed8af74d events:Vector<ChannelAdminLogEvent> chats:Vector<Chat> users:Vector<User> = channels.AdminLogResults;
channelAdminLogEventsFilter#ea107ae4 flags:# join:flags.0?true leave:flags.1?true invite:flags.2?true ban:flags.3?true unban:flags.4?true kick:flags.5?true unkick:flags.6?true promote:flags.7?true demote:flags.8?true info:flags.9?true settings:flags.10?true pinned:flags.11?true edit:flags.12?true delete:flags.13?true group_call:flags.14?true invites:flags.15?true send:flags.16?true forums:flags.17?true sub_extend:flags.18?true = ChannelAdminLogEventsFilter;
popularContact#5ce14175 client_id:long importers:int = PopularContact;
messages.favedStickersNotModified#9e8fa6d3 = messages.FavedStickers;
messages.favedStickers#2cb51097 hash:long packs:Vector<StickerPack> stickers:Vector<Document> = messages.FavedStickers;
recentMeUrlUnknown#46e1d13d url:string = RecentMeUrl;
recentMeUrlUser#b92c09e2 url:string user_id:long = RecentMeUrl;
recentMeUrlChat#b2da71d2 url:string chat_id:long = RecentMeUrl;
recentMeUrlChatInvite#eb49081d url:string chat_invite:ChatInvite = RecentMeUrl;
recentMeUrlStickerSet#bc0a57dc url:string set:StickerSetCovered = RecentMeUrl;
help.recentMeUrls#e0310d7 urls:Vector<RecentMeUrl> chats:Vector<Chat> users:Vector<User> = help.RecentMeUrls;
inputSingleMedia#1cc6e91f flags:# media:InputMedia random_id:long message:string entities:flags.0?Vector<MessageEntity> = InputSingleMedia;
webAuthorization#a6f8f452 hash:long bot_id:long domain:string browser:string platform:string date_created:int date_active:int ip:string region:string = WebAuthorization;
account.webAuthorizations#ed56c9fc authorizations:Vector<WebAuthorization> users:Vector<User> = account.WebAuthorizations;
inputMessageID#a676a322 id:int = InputMessage;
inputMessageReplyTo#bad88395 id:int = InputMessage;
inputMessagePinned#86872538 = InputMessage;
inputMessageCallbackQuery#acfa1a7e id:int query_id:long = InputMessage;
inputDialogPeer#fcaafeb7 peer:InputPeer = InputDialogPeer;
inputDialogPeerFolder#64600527 folder_id:int = InputDialogPeer;
dialogPeer#e56dbf05 peer:Peer = DialogPeer;
dialogPeerFolder#514519e2 folder_id:int = DialogPeer;
messages.foundStickerSetsNotModified#d54b65d = messages.FoundStickerSets;
messages.foundStickerSets#8af09dd2 hash:long sets:Vector<StickerSetCovered> = messages.FoundStickerSets;
fileHash#f39b035c offset:long limit:int hash:bytes = FileHash;
inputClientProxy#75588b3f address:string port:int = InputClientProxy;
help.termsOfServiceUpdateEmpty#e3309f7f expires:int = help.TermsOfServiceUpdate;
help.termsOfServiceUpdate#28ecf961 expires:int terms_of_service:help.TermsOfService = help.TermsOfServiceUpdate;
inputSecureFileUploaded#3334b0f0 id:long parts:int md5_checksum:string file_hash:bytes secret:bytes = InputSecureFile;
inputSecureFile#5367e5be id:long access_hash:long = InputSecureFile;
secureFileEmpty#64199744 = SecureFile;
secureFile#7d09c27e id:long access_hash:long size:long dc_id:int date:int file_hash:bytes secret:bytes = SecureFile;
secureData#8aeabec3 data:bytes data_hash:bytes secret:bytes = SecureData;
securePlainPhone#7d6099dd phone:string = SecurePlainData;
securePlainEmail#21ec5a5f email:string = SecurePlainData;
secureValueTypePersonalDetails#9d2a81e3 = SecureValueType;
secureValueTypePassport#3dac6a00 = SecureValueType;
secureValueTypeDriverLicense#6e425c4 = SecureValueType;
secureValueTypeIdentityCard#a0d0744b = SecureValueType;
secureValueTypeInternalPassport#99a48f23 = SecureValueType;
secureValueTypeAddress#cbe31e26 = SecureValueType;
secureValueTypeUtilityBill#fc36954e = SecureValueType;
secureValueTypeBankStatement#89137c0d = SecureValueType;
secureValueTypeRentalAgreement#8b883488 = SecureValueType;
secureValueTypePassportRegistration#99e3806a = SecureValueType;
secureValueTypeTemporaryRegistration#ea02ec33 = SecureValueType;
secureValueTypePhone#b320aadb = SecureValueType;
secureValueTypeEmail#8e3ca7ee = SecureValueType;
secureValue#187fa0ca flags:# type:SecureValueType data:flags.0?SecureData front_side:flags.1?SecureFile reverse_side:flags.2?SecureFile selfie:flags.3?SecureFile translation:flags.6?Vector<SecureFile> files:flags.4?Vector<SecureFile> plain_data:flags.5?SecurePlainData hash:bytes = SecureValue;
inputSecureValue#db21d0a7 flags:# type:SecureValueType data:flags.0?SecureData front_side:flags.1?InputSecureFile reverse_side:flags.2?InputSecureFile selfie:flags.3?InputSecureFile translation:flags.6?Vector<InputSecureFile> files:flags.4?Vector<InputSecureFile> plain_data:flags.5?SecurePlainData = InputSecureValue;
secureValueHash#ed1ecdb0 type:SecureValueType hash:bytes = SecureValueHash;
secureValueErrorData#e8a40bd9 type:SecureValueType data_hash:bytes field:string text:string = SecureValueError;
secureValueErrorFrontSide#be3dfa type:SecureValueType file_hash:bytes text:string = SecureValueError;
secureValueErrorReverseSide#868a2aa5 type:SecureValueType file_hash:bytes text:string = SecureValueError;
secureValueErrorSelfie#e537ced6 type:SecureValueType file_hash:bytes text:string = SecureValueError;
secureValueErrorFile#7a700873 type:SecureValueType file_hash:bytes text:string = SecureValueError;
secureValueErrorFiles#666220e9 type:SecureValueType file_hash:Vector<bytes> text:string = SecureValueError;
secureValueError#869d758f type:SecureValueType hash:bytes text:string = SecureValueError;
secureValueErrorTranslationFile#a1144770 type:SecureValueType file_hash:bytes text:string = SecureValueError;
secureValueErrorTranslationFiles#34636dd8 type:SecureValueType file_hash:Vector<bytes> text:string = SecureValueError;
secureCredentialsEncrypted#33f0ea47 data:bytes hash:bytes secret:bytes = SecureCredentialsEncrypted;
account.authorizationForm#ad2e1cd8 flags:# required_types:Vector<SecureRequiredType> values:Vector<SecureValue> errors:Vector<SecureValueError> users:Vector<User> privacy_policy_url:flags.0?string = account.AuthorizationForm;
account.sentEmailCode#811f854f email_pattern:string length:int = account.SentEmailCode;
help.deepLinkInfoEmpty#66afa166 = help.DeepLinkInfo;
help.deepLinkInfo#6a4ee832 flags:# update_app:flags.0?true message:string entities:flags.1?Vector<MessageEntity> = help.DeepLinkInfo;
savedPhoneContact#1142bd56 phone:string first_name:string last_name:string date:int = SavedContact;
account.takeout#4dba4501 id:long = account.Takeout;
passwordKdfAlgoUnknown#d45ab096 = PasswordKdfAlgo;
passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow#3a912d4a salt1:bytes salt2:bytes g:int p:bytes = PasswordKdfAlgo;
securePasswordKdfAlgoUnknown#4a8537 = SecurePasswordKdfAlgo;
securePasswordKdfAlgoPBKDF2HMACSHA512iter100000#bbf2dda0 salt:bytes = SecurePasswordKdfAlgo;
securePasswordKdfAlgoSHA512#86471d92 salt:bytes = SecurePasswordKdfAlgo;
secureSecretSettings#1527bcac secure_algo:SecurePasswordKdfAlgo secure_secret:bytes secure_secret_id:long = SecureSecretSettings;
inputCheckPasswordEmpty#9880f658 = InputCheckPasswordSRP;
inputCheckPasswordSRP#d27ff082 srp_id:long A:bytes M1:bytes = InputCheckPasswordSRP;
secureRequiredType#829d99da flags:# native_names:flags.0?true selfie_required:flags.1?true translation_required:flags.2?true type:SecureValueType = SecureRequiredType;
secureRequiredTypeOneOf#27477b4 types:Vector<SecureRequiredType> = SecureRequiredType;
help.passportConfigNotModified#bfb9f457 = help.PassportConfig;
help.passportConfig#a098d6af hash:int countries_langs:DataJSON = help.PassportConfig;
inputAppEvent#1d1b1245 time:double type:string peer:long data:JSONValue = InputAppEvent;
jsonObjectValue#c0de1bd9 key:string value:JSONValue = JSONObjectValue;
jsonNull#3f6d7b68 = JSONValue;
jsonBool#c7345e6a value:Bool = JSONValue;
jsonNumber#2be0dfa4 value:double = JSONValue;
jsonString#b71e767a value:string = JSONValue;
jsonArray#f7444763 value:Vector<JSONValue> = JSONValue;
jsonObject#99c1d49d value:Vector<JSONObjectValue> = JSONValue;
pageTableCell#34566b6a flags:# header:flags.0?true align_center:flags.3?true align_right:flags.4?true valign_middle:flags.5?true valign_bottom:flags.6?true text:flags.7?RichText colspan:flags.1?int rowspan:flags.2?int = PageTableCell;
pageTableRow#e0c0c5e5 cells:Vector<PageTableCell> = PageTableRow;
pageCaption#6f747657 text:RichText credit:RichText = PageCaption;
pageListItemText#b92fb6cd text:RichText = PageListItem;
pageListItemBlocks#25e073fc blocks:Vector<PageBlock> = PageListItem;
pageListOrderedItemText#5e068047 num:string text:RichText = PageListOrderedItem;
pageListOrderedItemBlocks#98dd8936 num:string blocks:Vector<PageBlock> = PageListOrderedItem;
pageRelatedArticle#b390dc08 flags:# url:string webpage_id:long title:flags.0?string description:flags.1?string photo_id:flags.2?long author:flags.3?string published_date:flags.4?int = PageRelatedArticle;
page#98657f0d flags:# part:flags.0?true rtl:flags.1?true v2:flags.2?true url:string blocks:Vector<PageBlock> photos:Vector<Photo> documents:Vector<Document> views:flags.3?int = Page;
help.supportName#8c05f1c9 name:string = help.SupportName;
help.userInfoEmpty#f3ae2eed = help.UserInfo;
help.userInfo#1eb3758 message:string entities:Vector<MessageEntity> author:string date:int = help.UserInfo;
pollAnswer#ff16e2ca text:TextWithEntities option:bytes = PollAnswer;
poll#58747131 id:long flags:# closed:flags.0?true public_voters:flags.1?true multiple_choice:flags.2?true quiz:flags.3?true question:TextWithEntities answers:Vector<PollAnswer> close_period:flags.4?int close_date:flags.5?int = Poll;
pollAnswerVoters#3b6ddad2 flags:# chosen:flags.0?true correct:flags.1?true option:bytes voters:int = PollAnswerVoters;
pollResults#7adf2420 flags:# min:flags.0?true results:flags.1?Vector<PollAnswerVoters> total_voters:flags.2?int recent_voters:flags.3?Vector<Peer> solution:flags.4?string solution_entities:flags.4?Vector<MessageEntity> = PollResults;
chatOnlines#f041e250 onlines:int = ChatOnlines;
statsURL#47a971e0 url:string = StatsURL;
chatAdminRights#5fb224d5 flags:# change_info:flags.0?true post_messages:flags.1?true edit_messages:flags.2?true delete_messages:flags.3?true ban_users:flags.4?true invite_users:flags.5?true pin_messages:flags.7?true add_admins:flags.9?true anonymous:flags.10?true manage_call:flags.11?true other:flags.12?true manage_topics:flags.13?true post_stories:flags.14?true edit_stories:flags.15?true delete_stories:flags.16?true manage_direct_messages:flags.17?true = ChatAdminRights;
chatBannedRights#9f120418 flags:# view_messages:flags.0?true send_messages:flags.1?true send_media:flags.2?true send_stickers:flags.3?true send_gifs:flags.4?true send_games:flags.5?true send_inline:flags.6?true embed_links:flags.7?true send_polls:flags.8?true change_info:flags.10?true invite_users:flags.15?true pin_messages:flags.17?true manage_topics:flags.18?true send_photos:flags.19?true send_videos:flags.20?true send_roundvideos:flags.21?true send_audios:flags.22?true send_voices:flags.23?true send_docs:flags.24?true send_plain:flags.25?true until_date:int = ChatBannedRights;
inputWallPaper#e630b979 id:long access_hash:long = InputWallPaper;
inputWallPaperSlug#72091c80 slug:string = InputWallPaper;
inputWallPaperNoFile#967a462e id:long = InputWallPaper;
account.wallPapersNotModified#1c199183 = account.WallPapers;
account.wallPapers#cdc3858c hash:long wallpapers:Vector<WallPaper> = account.WallPapers;
codeSettings#ad253d78 flags:# allow_flashcall:flags.0?true current_number:flags.1?true allow_app_hash:flags.4?true allow_missed_call:flags.5?true allow_firebase:flags.7?true unknown_number:flags.9?true logout_tokens:flags.6?Vector<bytes> token:flags.8?string app_sandbox:flags.8?Bool = CodeSettings;
wallPaperSettings#372efcd0 flags:# blur:flags.1?true motion:flags.2?true background_color:flags.0?int second_background_color:flags.4?int third_background_color:flags.5?int fourth_background_color:flags.6?int intensity:flags.3?int rotation:flags.4?int emoticon:flags.7?string = WallPaperSettings;
autoDownloadSettings#baa57628 flags:# disabled:flags.0?true video_preload_large:flags.1?true audio_preload_next:flags.2?true phonecalls_less_data:flags.3?true stories_preload:flags.4?true photo_size_max:int video_size_max:long file_size_max:long video_upload_maxbitrate:int small_queue_active_operations_max:int large_queue_active_operations_max:int = AutoDownloadSettings;
account.autoDownloadSettings#63cacf26 low:AutoDownloadSettings medium:AutoDownloadSettings high:AutoDownloadSettings = account.AutoDownloadSettings;
emojiKeyword#d5b3b9f9 keyword:string emoticons:Vector<string> = EmojiKeyword;
emojiKeywordDeleted#236df622 keyword:string emoticons:Vector<string> = EmojiKeyword;
emojiKeywordsDifference#5cc761bd lang_code:string from_version:int version:int keywords:Vector<EmojiKeyword> = EmojiKeywordsDifference;
emojiURL#a575739d url:string = EmojiURL;
emojiLanguage#b3fb5361 lang_code:string = EmojiLanguage;
folder#ff544e65 flags:# autofill_new_broadcasts:flags.0?true autofill_public_groups:flags.1?true autofill_new_correspondents:flags.2?true id:int title:string photo:flags.3?ChatPhoto = Folder;
inputFolderPeer#fbd2c296 peer:InputPeer folder_id:int = InputFolderPeer;
folderPeer#e9baa668 peer:Peer folder_id:int = FolderPeer;
messages.searchCounter#e844ebff flags:# inexact:flags.1?true filter:MessagesFilter count:int = messages.SearchCounter;
urlAuthResultRequest#92d33a0e flags:# request_write_access:flags.0?true bot:User domain:string = UrlAuthResult;
urlAuthResultAccepted#8f8c0e4e url:string = UrlAuthResult;
urlAuthResultDefault#a9d6db1f = UrlAuthResult;
channelLocationEmpty#bfb5ad8b = ChannelLocation;
channelLocation#209b82db geo_point:GeoPoint address:string = ChannelLocation;
peerLocated#ca461b5d peer:Peer expires:int distance:int = PeerLocated;
peerSelfLocated#f8ec284b expires:int = PeerLocated;
restrictionReason#d072acb4 platform:string reason:string text:string = RestrictionReason;
inputTheme#3c5693e9 id:long access_hash:long = InputTheme;
inputThemeSlug#f5890df1 slug:string = InputTheme;
theme#a00e67d6 flags:# creator:flags.0?true default:flags.1?true for_chat:flags.5?true id:long access_hash:long slug:string title:string document:flags.2?Document settings:flags.3?Vector<ThemeSettings> emoticon:flags.6?string installs_count:flags.4?int = Theme;
account.themesNotModified#f41eb622 = account.Themes;
account.themes#9a3d8c6d hash:long themes:Vector<Theme> = account.Themes;
auth.loginToken#629f1980 expires:int token:bytes = auth.LoginToken;
auth.loginTokenMigrateTo#68e9916 dc_id:int token:bytes = auth.LoginToken;
auth.loginTokenSuccess#390d5c5e authorization:auth.Authorization = auth.LoginToken;
account.contentSettings#57e28221 flags:# sensitive_enabled:flags.0?true sensitive_can_change:flags.1?true = account.ContentSettings;
messages.inactiveChats#a927fec5 dates:Vector<int> chats:Vector<Chat> users:Vector<User> = messages.InactiveChats;
baseThemeClassic#c3a12462 = BaseTheme;
baseThemeDay#fbd81688 = BaseTheme;
baseThemeNight#b7b31ea8 = BaseTheme;
baseThemeTinted#6d5f77ee = BaseTheme;
baseThemeArctic#5b11125a = BaseTheme;
inputThemeSettings#8fde504f flags:# message_colors_animated:flags.2?true base_theme:BaseTheme accent_color:int outbox_accent_color:flags.3?int message_colors:flags.0?Vector<int> wallpaper:flags.1?InputWallPaper wallpaper_settings:flags.1?WallPaperSettings = InputThemeSettings;
themeSettings#fa58b6d4 flags:# message_colors_animated:flags.2?true base_theme:BaseTheme accent_color:int outbox_accent_color:flags.3?int message_colors:flags.0?Vector<int> wallpaper:flags.1?WallPaper = ThemeSettings;
webPageAttributeTheme#54b56617 flags:# documents:flags.0?Vector<Document> settings:flags.1?ThemeSettings = WebPageAttribute;
webPageAttributeStory#2e94c3e7 flags:# peer:Peer id:int story:flags.0?StoryItem = WebPageAttribute;
webPageAttributeStickerSet#50cc03d3 flags:# emojis:flags.0?true text_color:flags.1?true stickers:Vector<Document> = WebPageAttribute;
webPageAttributeUniqueStarGift#cf6f6db8 gift:StarGift = WebPageAttribute;
webPageAttributeStarGiftCollection#31cad303 icons:Vector<Document> = WebPageAttribute;
messages.votesList#4899484e flags:# count:int votes:Vector<MessagePeerVote> chats:Vector<Chat> users:Vector<User> next_offset:flags.0?string = messages.VotesList;
bankCardOpenUrl#f568028a url:string name:string = BankCardOpenUrl;
payments.bankCardData#3e24e573 title:string open_urls:Vector<BankCardOpenUrl> = payments.BankCardData;
dialogFilter#aa472651 flags:# contacts:flags.0?true non_contacts:flags.1?true groups:flags.2?true broadcasts:flags.3?true bots:flags.4?true exclude_muted:flags.11?true exclude_read:flags.12?true exclude_archived:flags.13?true title_noanimate:flags.28?true id:int title:TextWithEntities emoticon:flags.25?string color:flags.27?int pinned_peers:Vector<InputPeer> include_peers:Vector<InputPeer> exclude_peers:Vector<InputPeer> = DialogFilter;
dialogFilterDefault#363293ae = DialogFilter;
dialogFilterChatlist#96537bd7 flags:# has_my_invites:flags.26?true title_noanimate:flags.28?true id:int title:TextWithEntities emoticon:flags.25?string color:flags.27?int pinned_peers:Vector<InputPeer> include_peers:Vector<InputPeer> = DialogFilter;
dialogFilterSuggested#77744d4a filter:DialogFilter description:string = DialogFilterSuggested;
statsDateRangeDays#b637edaf min_date:int max_date:int = StatsDateRangeDays;
statsAbsValueAndPrev#cb43acde current:double previous:double = StatsAbsValueAndPrev;
statsPercentValue#cbce2fe0 part:double total:double = StatsPercentValue;
statsGraphAsync#4a27eb2d token:string = StatsGraph;
statsGraphError#bedc9822 error:string = StatsGraph;
statsGraph#8ea464b6 flags:# json:DataJSON zoom_token:flags.0?string = StatsGraph;
stats.broadcastStats#396ca5fc period:StatsDateRangeDays followers:StatsAbsValueAndPrev views_per_post:StatsAbsValueAndPrev shares_per_post:StatsAbsValueAndPrev reactions_per_post:StatsAbsValueAndPrev views_per_story:StatsAbsValueAndPrev shares_per_story:StatsAbsValueAndPrev reactions_per_story:StatsAbsValueAndPrev enabled_notifications:StatsPercentValue growth_graph:StatsGraph followers_graph:StatsGraph mute_graph:StatsGraph top_hours_graph:StatsGraph interactions_graph:StatsGraph iv_interactions_graph:StatsGraph views_by_source_graph:StatsGraph new_followers_by_source_graph:StatsGraph languages_graph:StatsGraph reactions_by_emotion_graph:StatsGraph story_interactions_graph:StatsGraph story_reactions_by_emotion_graph:StatsGraph recent_posts_interactions:Vector<PostInteractionCounters> = stats.BroadcastStats;
help.promoDataEmpty#98f6ac75 expires:int = help.PromoData;
help.promoData#8a4d87a flags:# proxy:flags.0?true expires:int peer:flags.3?Peer psa_type:flags.1?string psa_message:flags.2?string pending_suggestions:Vector<string> dismissed_suggestions:Vector<string> custom_pending_suggestion:flags.4?PendingSuggestion chats:Vector<Chat> users:Vector<User> = help.PromoData;
videoSize#de33b094 flags:# type:string w:int h:int size:int video_start_ts:flags.0?double = VideoSize;
videoSizeEmojiMarkup#f85c413c emoji_id:long background_colors:Vector<int> = VideoSize;
videoSizeStickerMarkup#da082fe stickerset:InputStickerSet sticker_id:long background_colors:Vector<int> = VideoSize;
statsGroupTopPoster#9d04af9b user_id:long messages:int avg_chars:int = StatsGroupTopPoster;
statsGroupTopAdmin#d7584c87 user_id:long deleted:int kicked:int banned:int = StatsGroupTopAdmin;
statsGroupTopInviter#535f779d user_id:long invitations:int = StatsGroupTopInviter;
stats.megagroupStats#ef7ff916 period:StatsDateRangeDays members:StatsAbsValueAndPrev messages:StatsAbsValueAndPrev viewers:StatsAbsValueAndPrev posters:StatsAbsValueAndPrev growth_graph:StatsGraph members_graph:StatsGraph new_members_by_source_graph:StatsGraph languages_graph:StatsGraph messages_graph:StatsGraph actions_graph:StatsGraph top_hours_graph:StatsGraph weekdays_graph:StatsGraph top_posters:Vector<StatsGroupTopPoster> top_admins:Vector<StatsGroupTopAdmin> top_inviters:Vector<StatsGroupTopInviter> users:Vector<User> = stats.MegagroupStats;
globalPrivacySettings#fe41b34f flags:# archive_and_mute_new_noncontact_peers:flags.0?true keep_archived_unmuted:flags.1?true keep_archived_folders:flags.2?true hide_read_marks:flags.3?true new_noncontact_peers_require_premium:flags.4?true display_gifts_button:flags.7?true noncontact_peers_paid_stars:flags.5?long disallowed_gifts:flags.6?DisallowedGiftsSettings = GlobalPrivacySettings;
help.countryCode#4203c5ef flags:# country_code:string prefixes:flags.0?Vector<string> patterns:flags.1?Vector<string> = help.CountryCode;
help.country#c3878e23 flags:# hidden:flags.0?true iso2:string default_name:string name:flags.1?string country_codes:Vector<help.CountryCode> = help.Country;
help.countriesListNotModified#93cc1f32 = help.CountriesList;
help.countriesList#87d0759e countries:Vector<help.Country> hash:int = help.CountriesList;
messageViews#455b853d flags:# views:flags.0?int forwards:flags.1?int replies:flags.2?MessageReplies = MessageViews;
messages.messageViews#b6c4f543 views:Vector<MessageViews> chats:Vector<Chat> users:Vector<User> = messages.MessageViews;
messages.discussionMessage#a6341782 flags:# messages:Vector<Message> max_id:flags.0?int read_inbox_max_id:flags.1?int read_outbox_max_id:flags.2?int unread_count:int chats:Vector<Chat> users:Vector<User> = messages.DiscussionMessage;
messageReplyHeader#6917560b flags:# reply_to_scheduled:flags.2?true forum_topic:flags.3?true quote:flags.9?true reply_to_msg_id:flags.4?int reply_to_peer_id:flags.0?Peer reply_from:flags.5?MessageFwdHeader reply_media:flags.8?MessageMedia reply_to_top_id:flags.1?int quote_text:flags.6?string quote_entities:flags.7?Vector<MessageEntity> quote_offset:flags.10?int todo_item_id:flags.11?int = MessageReplyHeader;
messageReplyStoryHeader#e5af939 peer:Peer story_id:int = MessageReplyHeader;
messageReplies#83d60fc2 flags:# comments:flags.0?true replies:int replies_pts:int recent_repliers:flags.1?Vector<Peer> channel_id:flags.0?long max_id:flags.2?int read_max_id:flags.3?int = MessageReplies;
peerBlocked#e8fd8014 peer_id:Peer date:int = PeerBlocked;
stats.messageStats#7fe91c14 views_graph:StatsGraph reactions_by_emotion_graph:StatsGraph = stats.MessageStats;
groupCallDiscarded#7780bcb4 id:long access_hash:long duration:int = GroupCall;
groupCall#553b0ba1 flags:# join_muted:flags.1?true can_change_join_muted:flags.2?true join_date_asc:flags.6?true schedule_start_subscribed:flags.8?true can_start_video:flags.9?true record_video_active:flags.11?true rtmp_stream:flags.12?true listeners_hidden:flags.13?true conference:flags.14?true creator:flags.15?true id:long access_hash:long participants_count:int title:flags.3?string stream_dc_id:flags.4?int record_start_date:flags.5?int schedule_date:flags.7?int unmuted_video_count:flags.10?int unmuted_video_limit:int version:int invite_link:flags.16?string = GroupCall;
inputGroupCall#d8aa840f id:long access_hash:long = InputGroupCall;
inputGroupCallSlug#fe06823f slug:string = InputGroupCall;
inputGroupCallInviteMessage#8c10603f msg_id:int = InputGroupCall;
groupCallParticipant#eba636fe flags:# muted:flags.0?true left:flags.1?true can_self_unmute:flags.2?true just_joined:flags.4?true versioned:flags.5?true min:flags.8?true muted_by_you:flags.9?true volume_by_admin:flags.10?true self:flags.12?true video_joined:flags.15?true peer:Peer date:int active_date:flags.3?int source:int volume:flags.7?int about:flags.11?string raise_hand_rating:flags.13?long video:flags.6?GroupCallParticipantVideo presentation:flags.14?GroupCallParticipantVideo = GroupCallParticipant;
phone.groupCall#9e727aad call:GroupCall participants:Vector<GroupCallParticipant> participants_next_offset:string chats:Vector<Chat> users:Vector<User> = phone.GroupCall;
phone.groupParticipants#f47751b6 count:int participants:Vector<GroupCallParticipant> next_offset:string chats:Vector<Chat> users:Vector<User> version:int = phone.GroupParticipants;
inlineQueryPeerTypeSameBotPM#3081ed9d = InlineQueryPeerType;
inlineQueryPeerTypePM#833c0fac = InlineQueryPeerType;
inlineQueryPeerTypeChat#d766c50a = InlineQueryPeerType;
inlineQueryPeerTypeMegagroup#5ec4be43 = InlineQueryPeerType;
inlineQueryPeerTypeBroadcast#6334ee9a = InlineQueryPeerType;
inlineQueryPeerTypeBotPM#e3b2d0c = InlineQueryPeerType;
messages.historyImport#1662af0b id:long = messages.HistoryImport;
messages.historyImportParsed#5e0fb7b9 flags:# pm:flags.0?true group:flags.1?true title:flags.2?string = messages.HistoryImportParsed;
messages.affectedFoundMessages#ef8d3e6c pts:int pts_count:int offset:int messages:Vector<int> = messages.AffectedFoundMessages;
chatInviteImporter#8c5adfd9 flags:# requested:flags.0?true via_chatlist:flags.3?true user_id:long date:int about:flags.2?string approved_by:flags.1?long = ChatInviteImporter;
messages.exportedChatInvites#bdc62dcc count:int invites:Vector<ExportedChatInvite> users:Vector<User> = messages.ExportedChatInvites;
messages.exportedChatInvite#1871be50 invite:ExportedChatInvite users:Vector<User> = messages.ExportedChatInvite;
messages.exportedChatInviteReplaced#222600ef invite:ExportedChatInvite new_invite:ExportedChatInvite users:Vector<User> = messages.ExportedChatInvite;
messages.chatInviteImporters#81b6b00a count:int importers:Vector<ChatInviteImporter> users:Vector<User> = messages.ChatInviteImporters;
chatAdminWithInvites#f2ecef23 admin_id:long invites_count:int revoked_invites_count:int = ChatAdminWithInvites;
messages.chatAdminsWithInvites#b69b72d7 admins:Vector<ChatAdminWithInvites> users:Vector<User> = messages.ChatAdminsWithInvites;
messages.checkedHistoryImportPeer#a24de717 confirm_text:string = messages.CheckedHistoryImportPeer;
phone.joinAsPeers#afe5623f peers:Vector<Peer> chats:Vector<Chat> users:Vector<User> = phone.JoinAsPeers;
phone.exportedGroupCallInvite#204bd158 link:string = phone.ExportedGroupCallInvite;
groupCallParticipantVideoSourceGroup#dcb118b7 semantics:string sources:Vector<int> = GroupCallParticipantVideoSourceGroup;
groupCallParticipantVideo#67753ac8 flags:# paused:flags.0?true endpoint:string source_groups:Vector<GroupCallParticipantVideoSourceGroup> audio_source:flags.1?int = GroupCallParticipantVideo;
stickers.suggestedShortName#85fea03f short_name:string = stickers.SuggestedShortName;
botCommandScopeDefault#2f6cb2ab = BotCommandScope;
botCommandScopeUsers#3c4f04d8 = BotCommandScope;
botCommandScopeChats#6fe1a881 = BotCommandScope;
botCommandScopeChatAdmins#b9aa606a = BotCommandScope;
botCommandScopePeer#db9d897d peer:InputPeer = BotCommandScope;
botCommandScopePeerAdmins#3fd863d1 peer:InputPeer = BotCommandScope;
botCommandScopePeerUser#a1321f3 peer:InputPeer user_id:InputUser = BotCommandScope;
account.resetPasswordFailedWait#e3779861 retry_date:int = account.ResetPasswordResult;
account.resetPasswordRequestedWait#e9effc7d until_date:int = account.ResetPasswordResult;
account.resetPasswordOk#e926d63e = account.ResetPasswordResult;
sponsoredMessage#7dbf8673 flags:# recommended:flags.5?true can_report:flags.12?true random_id:bytes url:string title:string message:string entities:flags.1?Vector<MessageEntity> photo:flags.6?Photo media:flags.14?MessageMedia color:flags.13?PeerColor button_text:string sponsor_info:flags.7?string additional_info:flags.8?string min_display_duration:flags.15?int max_display_duration:flags.15?int = SponsoredMessage;
messages.sponsoredMessages#ffda656d flags:# posts_between:flags.0?int start_delay:flags.1?int between_delay:flags.2?int messages:Vector<SponsoredMessage> chats:Vector<Chat> users:Vector<User> = messages.SponsoredMessages;
messages.sponsoredMessagesEmpty#1839490f = messages.SponsoredMessages;
searchResultsCalendarPeriod#c9b0539f date:int min_msg_id:int max_msg_id:int count:int = SearchResultsCalendarPeriod;
messages.searchResultsCalendar#147ee23c flags:# inexact:flags.0?true count:int min_date:int min_msg_id:int offset_id_offset:flags.1?int periods:Vector<SearchResultsCalendarPeriod> messages:Vector<Message> chats:Vector<Chat> users:Vector<User> = messages.SearchResultsCalendar;
searchResultPosition#7f648b67 msg_id:int date:int offset:int = SearchResultsPosition;
messages.searchResultsPositions#53b22baf count:int positions:Vector<SearchResultsPosition> = messages.SearchResultsPositions;
channels.sendAsPeers#f496b0c6 peers:Vector<SendAsPeer> chats:Vector<Chat> users:Vector<User> = channels.SendAsPeers;
users.userFull#3b6d152e full_user:UserFull chats:Vector<Chat> users:Vector<User> = users.UserFull;
messages.peerSettings#6880b94d settings:PeerSettings chats:Vector<Chat> users:Vector<User> = messages.PeerSettings;
auth.loggedOut#c3a2835f flags:# future_auth_token:flags.0?bytes = auth.LoggedOut;
reactionCount#a3d1cb80 flags:# chosen_order:flags.0?int reaction:Reaction count:int = ReactionCount;
messageReactions#a339f0b flags:# min:flags.0?true can_see_list:flags.2?true reactions_as_tags:flags.3?true results:Vector<ReactionCount> recent_reactions:flags.1?Vector<MessagePeerReaction> top_reactors:flags.4?Vector<MessageReactor> = MessageReactions;
messages.messageReactionsList#31bd492d flags:# count:int reactions:Vector<MessagePeerReaction> chats:Vector<Chat> users:Vector<User> next_offset:flags.0?string = messages.MessageReactionsList;
availableReaction#c077ec01 flags:# inactive:flags.0?true premium:flags.2?true reaction:string title:string static_icon:Document appear_animation:Document select_animation:Document activate_animation:Document effect_animation:Document around_animation:flags.1?Document center_icon:flags.1?Document = AvailableReaction;
messages.availableReactionsNotModified#9f071957 = messages.AvailableReactions;
messages.availableReactions#768e3aad hash:int reactions:Vector<AvailableReaction> = messages.AvailableReactions;
messagePeerReaction#8c79b63c flags:# big:flags.0?true unread:flags.1?true my:flags.2?true peer_id:Peer date:int reaction:Reaction = MessagePeerReaction;
groupCallStreamChannel#80eb48af channel:int scale:int last_timestamp_ms:long = GroupCallStreamChannel;
phone.groupCallStreamChannels#d0e482b2 channels:Vector<GroupCallStreamChannel> = phone.GroupCallStreamChannels;
phone.groupCallStreamRtmpUrl#2dbf3432 url:string key:string = phone.GroupCallStreamRtmpUrl;
attachMenuBotIconColor#4576f3f0 name:string color:int = AttachMenuBotIconColor;
attachMenuBotIcon#b2a7386b flags:# name:string icon:Document colors:flags.0?Vector<AttachMenuBotIconColor> = AttachMenuBotIcon;
attachMenuBot#d90d8dfe flags:# inactive:flags.0?true has_settings:flags.1?true request_write_access:flags.2?true show_in_attach_menu:flags.3?true show_in_side_menu:flags.4?true side_menu_disclaimer_needed:flags.5?true bot_id:long short_name:string peer_types:flags.3?Vector<AttachMenuPeerType> icons:Vector<AttachMenuBotIcon> = AttachMenuBot;
attachMenuBotsNotModified#f1d88a5c = AttachMenuBots;
attachMenuBots#3c4301c0 hash:long bots:Vector<AttachMenuBot> users:Vector<User> = AttachMenuBots;
attachMenuBotsBot#93bf667f bot:AttachMenuBot users:Vector<User> = AttachMenuBotsBot;
webViewResultUrl#4d22ff98 flags:# fullsize:flags.1?true fullscreen:flags.2?true query_id:flags.0?long url:string = WebViewResult;
webViewMessageSent#c94511c flags:# msg_id:flags.0?InputBotInlineMessageID = WebViewMessageSent;
botMenuButtonDefault#7533a588 = BotMenuButton;
botMenuButtonCommands#4258c205 = BotMenuButton;
botMenuButton#c7b57ce6 text:string url:string = BotMenuButton;
account.savedRingtonesNotModified#fbf6e8b1 = account.SavedRingtones;
account.savedRingtones#c1e92cc5 hash:long ringtones:Vector<Document> = account.SavedRingtones;
notificationSoundDefault#97e8bebe = NotificationSound;
notificationSoundNone#6f0c34df = NotificationSound;
notificationSoundLocal#830b9ae4 title:string data:string = NotificationSound;
notificationSoundRingtone#ff6c8049 id:long = NotificationSound;
account.savedRingtone#b7263f6d = account.SavedRingtone;
account.savedRingtoneConverted#1f307eb7 document:Document = account.SavedRingtone;
attachMenuPeerTypeSameBotPM#7d6be90e = AttachMenuPeerType;
attachMenuPeerTypeBotPM#c32bfa1a = AttachMenuPeerType;
attachMenuPeerTypePM#f146d31f = AttachMenuPeerType;
attachMenuPeerTypeChat#509113f = AttachMenuPeerType;
attachMenuPeerTypeBroadcast#7bfbdefc = AttachMenuPeerType;
inputInvoiceMessage#c5b56859 peer:InputPeer msg_id:int = InputInvoice;
inputInvoiceSlug#c326caef slug:string = InputInvoice;
inputInvoicePremiumGiftCode#98986c0d purpose:InputStorePaymentPurpose option:PremiumGiftCodeOption = InputInvoice;
inputInvoiceStars#65f00ce3 purpose:InputStorePaymentPurpose = InputInvoice;
inputInvoiceChatInviteSubscription#34e793f1 hash:string = InputInvoice;
inputInvoiceStarGift#e8625e92 flags:# hide_name:flags.0?true include_upgrade:flags.2?true peer:InputPeer gift_id:long message:flags.1?TextWithEntities = InputInvoice;
inputInvoiceStarGiftUpgrade#4d818d5d flags:# keep_original_details:flags.0?true stargift:InputSavedStarGift = InputInvoice;
inputInvoiceStarGiftTransfer#4a5f5bd9 stargift:InputSavedStarGift to_id:InputPeer = InputInvoice;
inputInvoicePremiumGiftStars#dabab2ef flags:# user_id:InputUser months:int message:flags.0?TextWithEntities = InputInvoice;
inputInvoiceBusinessBotTransferStars#f4997e42 bot:InputUser stars:long = InputInvoice;
inputInvoiceStarGiftResale#c39f5324 flags:# ton:flags.0?true slug:string to_id:InputPeer = InputInvoice;
inputInvoiceStarGiftPrepaidUpgrade#9a0b48b8 peer:InputPeer hash:string = InputInvoice;
payments.exportedInvoice#aed0cbd9 url:string = payments.ExportedInvoice;
messages.transcribedAudio#cfb9d957 flags:# pending:flags.0?true transcription_id:long text:string trial_remains_num:flags.1?int trial_remains_until_date:flags.1?int = messages.TranscribedAudio;
help.premiumPromo#5334759c status_text:string status_entities:Vector<MessageEntity> video_sections:Vector<string> videos:Vector<Document> period_options:Vector<PremiumSubscriptionOption> users:Vector<User> = help.PremiumPromo;
inputStorePaymentPremiumSubscription#a6751e66 flags:# restore:flags.0?true upgrade:flags.1?true = InputStorePaymentPurpose;
inputStorePaymentGiftPremium#616f7fe8 user_id:InputUser currency:string amount:long = InputStorePaymentPurpose;
inputStorePaymentPremiumGiftCode#fb790393 flags:# users:Vector<InputUser> boost_peer:flags.0?InputPeer currency:string amount:long message:flags.1?TextWithEntities = InputStorePaymentPurpose;
inputStorePaymentPremiumGiveaway#160544ca flags:# only_new_subscribers:flags.0?true winners_are_visible:flags.3?true boost_peer:InputPeer additional_peers:flags.1?Vector<InputPeer> countries_iso2:flags.2?Vector<string> prize_description:flags.4?string random_id:long until_date:int currency:string amount:long = InputStorePaymentPurpose;
inputStorePaymentStarsTopup#dddd0f56 stars:long currency:string amount:long = InputStorePaymentPurpose;
inputStorePaymentStarsGift#1d741ef7 user_id:InputUser stars:long currency:string amount:long = InputStorePaymentPurpose;
inputStorePaymentStarsGiveaway#751f08fa flags:# only_new_subscribers:flags.0?true winners_are_visible:flags.3?true stars:long boost_peer:InputPeer additional_peers:flags.1?Vector<InputPeer> countries_iso2:flags.2?Vector<string> prize_description:flags.4?string random_id:long until_date:int currency:string amount:long users:int = InputStorePaymentPurpose;
inputStorePaymentAuthCode#9bb2636d flags:# restore:flags.0?true phone_number:string phone_code_hash:string currency:string amount:long = InputStorePaymentPurpose;
paymentFormMethod#88f8f21b url:string title:string = PaymentFormMethod;
emojiStatusEmpty#2de11aae = EmojiStatus;
emojiStatus#e7ff068a flags:# document_id:long until:flags.0?int = EmojiStatus;
emojiStatusCollectible#7184603b flags:# collectible_id:long document_id:long title:string slug:string pattern_document_id:long center_color:int edge_color:int pattern_color:int text_color:int until:flags.0?int = EmojiStatus;
inputEmojiStatusCollectible#7141dbf flags:# collectible_id:long until:flags.0?int = EmojiStatus;
account.emojiStatusesNotModified#d08ce645 = account.EmojiStatuses;
account.emojiStatuses#90c467d1 hash:long statuses:Vector<EmojiStatus> = account.EmojiStatuses;
reactionEmpty#79f5d419 = Reaction;
reactionEmoji#1b2286b8 emoticon:string = Reaction;
reactionCustomEmoji#8935fc73 document_id:long = Reaction;
reactionPaid#523da4eb = Reaction;
chatReactionsNone#eafc32bc = ChatReactions;
chatReactionsAll#52928bca flags:# allow_custom:flags.0?true = ChatReactions;
chatReactionsSome#661d4037 reactions:Vector<Reaction> = ChatReactions;
messages.reactionsNotModified#b06fdbdf = messages.Reactions;
messages.reactions#eafdf716 hash:long reactions:Vector<Reaction> = messages.Reactions;
emailVerifyPurposeLoginSetup#4345be73 phone_number:string phone_code_hash:string = EmailVerifyPurpose;
emailVerifyPurposeLoginChange#527d22eb = EmailVerifyPurpose;
emailVerifyPurposePassport#bbf51685 = EmailVerifyPurpose;
emailVerificationCode#922e55a9 code:string = EmailVerification;
emailVerificationGoogle#db909ec2 token:string = EmailVerification;
emailVerificationApple#96d074fd token:string = EmailVerification;
account.emailVerified#2b96cd1b email:string = account.EmailVerified;
account.emailVerifiedLogin#e1bb0d61 email:string sent_code:auth.SentCode = account.EmailVerified;
premiumSubscriptionOption#5f2d1df2 flags:# current:flags.1?true can_purchase_upgrade:flags.2?true transaction:flags.3?string months:int currency:string amount:long bot_url:string store_product:flags.0?string = PremiumSubscriptionOption;
sendAsPeer#b81c7034 flags:# premium_required:flags.0?true peer:Peer = SendAsPeer;
messageExtendedMediaPreview#ad628cc8 flags:# w:flags.0?int h:flags.0?int thumb:flags.1?PhotoSize video_duration:flags.2?int = MessageExtendedMedia;
messageExtendedMedia#ee479c64 media:MessageMedia = MessageExtendedMedia;
stickerKeyword#fcfeb29c document_id:long keyword:Vector<string> = StickerKeyword;
username#b4073647 flags:# editable:flags.0?true active:flags.1?true username:string = Username;
forumTopicDeleted#23f109b id:int = ForumTopic;
forumTopic#71701da9 flags:# my:flags.1?true closed:flags.2?true pinned:flags.3?true short:flags.5?true hidden:flags.6?true id:int date:int title:string icon_color:int icon_emoji_id:flags.0?long top_message:int read_inbox_max_id:int read_outbox_max_id:int unread_count:int unread_mentions_count:int unread_reactions_count:int from_id:Peer notify_settings:PeerNotifySettings draft:flags.4?DraftMessage = ForumTopic;
messages.forumTopics#367617d3 flags:# order_by_create_date:flags.0?true count:int topics:Vector<ForumTopic> messages:Vector<Message> chats:Vector<Chat> users:Vector<User> pts:int = messages.ForumTopics;
defaultHistoryTTL#43b46b20 period:int = DefaultHistoryTTL;
exportedContactToken#41bf109b url:string expires:int = ExportedContactToken;
requestPeerTypeUser#5f3b8a00 flags:# bot:flags.0?Bool premium:flags.1?Bool = RequestPeerType;
requestPeerTypeChat#c9f06e1b flags:# creator:flags.0?true bot_participant:flags.5?true has_username:flags.3?Bool forum:flags.4?Bool user_admin_rights:flags.1?ChatAdminRights bot_admin_rights:flags.2?ChatAdminRights = RequestPeerType;
requestPeerTypeBroadcast#339bef6c flags:# creator:flags.0?true has_username:flags.3?Bool user_admin_rights:flags.1?ChatAdminRights bot_admin_rights:flags.2?ChatAdminRights = RequestPeerType;
emojiListNotModified#481eadfa = EmojiList;
emojiList#7a1e11d1 hash:long document_id:Vector<long> = EmojiList;
emojiGroup#7a9abda9 title:string icon_emoji_id:long emoticons:Vector<string> = EmojiGroup;
emojiGroupGreeting#80d26cc7 title:string icon_emoji_id:long emoticons:Vector<string> = EmojiGroup;
emojiGroupPremium#93bcf34 title:string icon_emoji_id:long = EmojiGroup;
messages.emojiGroupsNotModified#6fb4ad87 = messages.EmojiGroups;
messages.emojiGroups#881fb94b hash:int groups:Vector<EmojiGroup> = messages.EmojiGroups;
textWithEntities#751f3146 text:string entities:Vector<MessageEntity> = TextWithEntities;
messages.translateResult#33db32f8 result:Vector<TextWithEntities> = messages.TranslatedText;
autoSaveSettings#c84834ce flags:# photos:flags.0?true videos:flags.1?true video_max_size:flags.2?long = AutoSaveSettings;
autoSaveException#81602d47 peer:Peer settings:AutoSaveSettings = AutoSaveException;
account.autoSaveSettings#4c3e069d users_settings:AutoSaveSettings chats_settings:AutoSaveSettings broadcasts_settings:AutoSaveSettings exceptions:Vector<AutoSaveException> chats:Vector<Chat> users:Vector<User> = account.AutoSaveSettings;
help.appConfigNotModified#7cde641d = help.AppConfig;
help.appConfig#dd18782e hash:int config:JSONValue = help.AppConfig;
inputBotAppID#a920bd7a id:long access_hash:long = InputBotApp;
inputBotAppShortName#908c0407 bot_id:InputUser short_name:string = InputBotApp;
botAppNotModified#5da674b7 = BotApp;
botApp#95fcd1d6 flags:# id:long access_hash:long short_name:string title:string description:string photo:Photo document:flags.0?Document hash:long = BotApp;
messages.botApp#eb50adf5 flags:# inactive:flags.0?true request_write_access:flags.1?true has_settings:flags.2?true app:BotApp = messages.BotApp;
inlineBotWebView#b57295d5 text:string url:string = InlineBotWebView;
readParticipantDate#4a4ff172 user_id:long date:int = ReadParticipantDate;
inputChatlistDialogFilter#f3e0da33 filter_id:int = InputChatlist;
exportedChatlistInvite#c5181ac flags:# title:string url:string peers:Vector<Peer> = ExportedChatlistInvite;
chatlists.exportedChatlistInvite#10e6e3a6 filter:DialogFilter invite:ExportedChatlistInvite = chatlists.ExportedChatlistInvite;
chatlists.exportedInvites#10ab6dc7 invites:Vector<ExportedChatlistInvite> chats:Vector<Chat> users:Vector<User> = chatlists.ExportedInvites;
chatlists.chatlistInviteAlready#fa87f659 filter_id:int missing_peers:Vector<Peer> already_peers:Vector<Peer> chats:Vector<Chat> users:Vector<User> = chatlists.ChatlistInvite;
chatlists.chatlistInvite#f10ece2f flags:# title_noanimate:flags.1?true title:TextWithEntities emoticon:flags.0?string peers:Vector<Peer> chats:Vector<Chat> users:Vector<User> = chatlists.ChatlistInvite;
chatlists.chatlistUpdates#93bd878d missing_peers:Vector<Peer> chats:Vector<Chat> users:Vector<User> = chatlists.ChatlistUpdates;
bots.botInfo#e8a775b0 name:string about:string description:string = bots.BotInfo;
messagePeerVote#b6cc2d5c peer:Peer option:bytes date:int = MessagePeerVote;
messagePeerVoteInputOption#74cda504 peer:Peer date:int = MessagePeerVote;
messagePeerVoteMultiple#4628f6e6 peer:Peer options:Vector<bytes> date:int = MessagePeerVote;
storyViews#8d595cd6 flags:# has_viewers:flags.1?true views_count:int forwards_count:flags.2?int reactions:flags.3?Vector<ReactionCount> reactions_count:flags.4?int recent_viewers:flags.0?Vector<long> = StoryViews;
storyItemDeleted#51e6ee4f id:int = StoryItem;
storyItemSkipped#ffadc913 flags:# close_friends:flags.8?true id:int date:int expire_date:int = StoryItem;
storyItem#edf164f1 flags:# pinned:flags.5?true public:flags.7?true close_friends:flags.8?true min:flags.9?true noforwards:flags.10?true edited:flags.11?true contacts:flags.12?true selected_contacts:flags.13?true out:flags.16?true id:int date:int from_id:flags.18?Peer fwd_from:flags.17?StoryFwdHeader expire_date:int caption:flags.0?string entities:flags.1?Vector<MessageEntity> media:MessageMedia media_areas:flags.14?Vector<MediaArea> privacy:flags.2?Vector<PrivacyRule> views:flags.3?StoryViews sent_reaction:flags.15?Reaction albums:flags.19?Vector<int> = StoryItem;
stories.allStoriesNotModified#1158fe3e flags:# state:string stealth_mode:StoriesStealthMode = stories.AllStories;
stories.allStories#6efc5e81 flags:# has_more:flags.0?true count:int state:string peer_stories:Vector<PeerStories> chats:Vector<Chat> users:Vector<User> stealth_mode:StoriesStealthMode = stories.AllStories;
stories.stories#63c3dd0a flags:# count:int stories:Vector<StoryItem> pinned_to_top:flags.0?Vector<int> chats:Vector<Chat> users:Vector<User> = stories.Stories;
storyView#b0bdeac5 flags:# blocked:flags.0?true blocked_my_stories_from:flags.1?true user_id:long date:int reaction:flags.2?Reaction = StoryView;
storyViewPublicForward#9083670b flags:# blocked:flags.0?true blocked_my_stories_from:flags.1?true message:Message = StoryView;
storyViewPublicRepost#bd74cf49 flags:# blocked:flags.0?true blocked_my_stories_from:flags.1?true peer_id:Peer story:StoryItem = StoryView;
stories.storyViewsList#59d78fc5 flags:# count:int views_count:int forwards_count:int reactions_count:int views:Vector<StoryView> chats:Vector<Chat> users:Vector<User> next_offset:flags.0?string = stories.StoryViewsList;
stories.storyViews#de9eed1d views:Vector<StoryViews> users:Vector<User> = stories.StoryViews;
inputReplyToMessage#869fbe10 flags:# reply_to_msg_id:int top_msg_id:flags.0?int reply_to_peer_id:flags.1?InputPeer quote_text:flags.2?string quote_entities:flags.3?Vector<MessageEntity> quote_offset:flags.4?int monoforum_peer_id:flags.5?InputPeer todo_item_id:flags.6?int = InputReplyTo;
inputReplyToStory#5881323a peer:InputPeer story_id:int = InputReplyTo;
inputReplyToMonoForum#69d66c45 monoforum_peer_id:InputPeer = InputReplyTo;
exportedStoryLink#3fc9053b link:string = ExportedStoryLink;
storiesStealthMode#712e27fd flags:# active_until_date:flags.0?int cooldown_until_date:flags.1?int = StoriesStealthMode;
mediaAreaCoordinates#cfc9e002 flags:# x:double y:double w:double h:double rotation:double radius:flags.0?double = MediaAreaCoordinates;
mediaAreaVenue#be82db9c coordinates:MediaAreaCoordinates geo:GeoPoint title:string address:string provider:string venue_id:string venue_type:string = MediaArea;
inputMediaAreaVenue#b282217f coordinates:MediaAreaCoordinates query_id:long result_id:string = MediaArea;
mediaAreaGeoPoint#cad5452d flags:# coordinates:MediaAreaCoordinates geo:GeoPoint address:flags.0?GeoPointAddress = MediaArea;
mediaAreaSuggestedReaction#14455871 flags:# dark:flags.0?true flipped:flags.1?true coordinates:MediaAreaCoordinates reaction:Reaction = MediaArea;
mediaAreaChannelPost#770416af coordinates:MediaAreaCoordinates channel_id:long msg_id:int = MediaArea;
inputMediaAreaChannelPost#2271f2bf coordinates:MediaAreaCoordinates channel:InputChannel msg_id:int = MediaArea;
mediaAreaUrl#37381085 coordinates:MediaAreaCoordinates url:string = MediaArea;
mediaAreaWeather#49a6549c coordinates:MediaAreaCoordinates emoji:string temperature_c:double color:int = MediaArea;
mediaAreaStarGift#5787686d coordinates:MediaAreaCoordinates slug:string = MediaArea;
peerStories#9a35e999 flags:# peer:Peer max_read_id:flags.0?int stories:Vector<StoryItem> = PeerStories;
stories.peerStories#cae68768 stories:PeerStories chats:Vector<Chat> users:Vector<User> = stories.PeerStories;
messages.webPage#fd5e12bd webpage:WebPage chats:Vector<Chat> users:Vector<User> = messages.WebPage;
premiumGiftCodeOption#257e962b flags:# users:int months:int store_product:flags.0?string store_quantity:flags.1?int currency:string amount:long = PremiumGiftCodeOption;
payments.checkedGiftCode#284a1096 flags:# via_giveaway:flags.2?true from_id:flags.4?Peer giveaway_msg_id:flags.3?int to_id:flags.0?long date:int months:int used_date:flags.1?int chats:Vector<Chat> users:Vector<User> = payments.CheckedGiftCode;
payments.giveawayInfo#4367daa0 flags:# participating:flags.0?true preparing_results:flags.3?true start_date:int joined_too_early_date:flags.1?int admin_disallowed_chat_id:flags.2?long disallowed_country:flags.4?string = payments.GiveawayInfo;
payments.giveawayInfoResults#e175e66f flags:# winner:flags.0?true refunded:flags.1?true start_date:int gift_code_slug:flags.3?string stars_prize:flags.4?long finish_date:int winners_count:int activated_count:flags.2?int = payments.GiveawayInfo;
prepaidGiveaway#b2539d54 id:long months:int quantity:int date:int = PrepaidGiveaway;
prepaidStarsGiveaway#9a9d77e0 id:long stars:long quantity:int boosts:int date:int = PrepaidGiveaway;
boost#4b3e14d6 flags:# gift:flags.1?true giveaway:flags.2?true unclaimed:flags.3?true id:string user_id:flags.0?long giveaway_msg_id:flags.2?int date:int expires:int used_gift_slug:flags.4?string multiplier:flags.5?int stars:flags.6?long = Boost;
premium.boostsList#86f8613c flags:# count:int boosts:Vector<Boost> next_offset:flags.0?string users:Vector<User> = premium.BoostsList;
myBoost#c448415c flags:# slot:int peer:flags.0?Peer date:int expires:int cooldown_until_date:flags.1?int = MyBoost;
premium.myBoosts#9ae228e2 my_boosts:Vector<MyBoost> chats:Vector<Chat> users:Vector<User> = premium.MyBoosts;
premium.boostsStatus#4959427a flags:# my_boost:flags.2?true level:int current_level_boosts:int boosts:int gift_boosts:flags.4?int next_level_boosts:flags.0?int premium_audience:flags.1?StatsPercentValue boost_url:string prepaid_giveaways:flags.3?Vector<PrepaidGiveaway> my_boost_slots:flags.2?Vector<int> = premium.BoostsStatus;
storyFwdHeader#b826e150 flags:# modified:flags.3?true from:flags.0?Peer from_name:flags.1?string story_id:flags.2?int = StoryFwdHeader;
postInteractionCountersMessage#e7058e7f msg_id:int views:int forwards:int reactions:int = PostInteractionCounters;
postInteractionCountersStory#8a480e27 story_id:int views:int forwards:int reactions:int = PostInteractionCounters;
stats.storyStats#50cd067c views_graph:StatsGraph reactions_by_emotion_graph:StatsGraph = stats.StoryStats;
publicForwardMessage#1f2bf4a message:Message = PublicForward;
publicForwardStory#edf3add0 peer:Peer story:StoryItem = PublicForward;
stats.publicForwards#93037e20 flags:# count:int forwards:Vector<PublicForward> next_offset:flags.0?string chats:Vector<Chat> users:Vector<User> = stats.PublicForwards;
peerColor#b54b5acf flags:# color:flags.0?int background_emoji_id:flags.1?long = PeerColor;
help.peerColorSet#26219a58 colors:Vector<int> = help.PeerColorSet;
help.peerColorProfileSet#767d61eb palette_colors:Vector<int> bg_colors:Vector<int> story_colors:Vector<int> = help.PeerColorSet;
help.peerColorOption#adec6ebe flags:# hidden:flags.0?true color_id:int colors:flags.1?help.PeerColorSet dark_colors:flags.2?help.PeerColorSet channel_min_level:flags.3?int group_min_level:flags.4?int = help.PeerColorOption;
help.peerColorsNotModified#2ba1f5ce = help.PeerColors;
help.peerColors#f8ed08 hash:int colors:Vector<help.PeerColorOption> = help.PeerColors;
storyReaction#6090d6d5 peer_id:Peer date:int reaction:Reaction = StoryReaction;
storyReactionPublicForward#bbab2643 message:Message = StoryReaction;
storyReactionPublicRepost#cfcd0f13 peer_id:Peer story:StoryItem = StoryReaction;
stories.storyReactionsList#aa5f789c flags:# count:int reactions:Vector<StoryReaction> chats:Vector<Chat> users:Vector<User> next_offset:flags.0?string = stories.StoryReactionsList;
savedDialog#bd87cb6c flags:# pinned:flags.2?true peer:Peer top_message:int = SavedDialog;
monoForumDialog#64407ea7 flags:# unread_mark:flags.3?true nopaid_messages_exception:flags.4?true peer:Peer top_message:int read_inbox_max_id:int read_outbox_max_id:int unread_count:int unread_reactions_count:int draft:flags.1?DraftMessage = SavedDialog;
messages.savedDialogs#f83ae221 dialogs:Vector<SavedDialog> messages:Vector<Message> chats:Vector<Chat> users:Vector<User> = messages.SavedDialogs;
messages.savedDialogsSlice#44ba9dd9 count:int dialogs:Vector<SavedDialog> messages:Vector<Message> chats:Vector<Chat> users:Vector<User> = messages.SavedDialogs;
messages.savedDialogsNotModified#c01f6fe8 count:int = messages.SavedDialogs;
savedReactionTag#cb6ff828 flags:# reaction:Reaction title:flags.0?string count:int = SavedReactionTag;
messages.savedReactionTagsNotModified#889b59ef = messages.SavedReactionTags;
messages.savedReactionTags#3259950a tags:Vector<SavedReactionTag> hash:long = messages.SavedReactionTags;
outboxReadDate#3bb842ac date:int = OutboxReadDate;
smsjobs.eligibleToJoin#dc8b44cf terms_url:string monthly_sent_sms:int = smsjobs.EligibilityToJoin;
smsjobs.status#2aee9191 flags:# allow_international:flags.0?true recent_sent:int recent_since:int recent_remains:int total_sent:int total_since:int last_gift_slug:flags.1?string terms_url:string = smsjobs.Status;
smsJob#e6a1eeb8 job_id:string phone_number:string text:string = SmsJob;
businessWeeklyOpen#120b1ab9 start_minute:int end_minute:int = BusinessWeeklyOpen;
businessWorkHours#8c92b098 flags:# open_now:flags.0?true timezone_id:string weekly_open:Vector<BusinessWeeklyOpen> = BusinessWorkHours;
businessLocation#ac5c1af7 flags:# geo_point:flags.0?GeoPoint address:string = BusinessLocation;
inputBusinessRecipients#6f8b32aa flags:# existing_chats:flags.0?true new_chats:flags.1?true contacts:flags.2?true non_contacts:flags.3?true exclude_selected:flags.5?true users:flags.4?Vector<InputUser> = InputBusinessRecipients;
businessRecipients#21108ff7 flags:# existing_chats:flags.0?true new_chats:flags.1?true contacts:flags.2?true non_contacts:flags.3?true exclude_selected:flags.5?true users:flags.4?Vector<long> = BusinessRecipients;
businessAwayMessageScheduleAlways#c9b9e2b9 = BusinessAwayMessageSchedule;
businessAwayMessageScheduleOutsideWorkHours#c3f2f501 = BusinessAwayMessageSchedule;
businessAwayMessageScheduleCustom#cc4d9ecc start_date:int end_date:int = BusinessAwayMessageSchedule;
inputBusinessGreetingMessage#194cb3b shortcut_id:int recipients:InputBusinessRecipients no_activity_days:int = InputBusinessGreetingMessage;
businessGreetingMessage#e519abab shortcut_id:int recipients:BusinessRecipients no_activity_days:int = BusinessGreetingMessage;
inputBusinessAwayMessage#832175e0 flags:# offline_only:flags.0?true shortcut_id:int schedule:BusinessAwayMessageSchedule recipients:InputBusinessRecipients = InputBusinessAwayMessage;
businessAwayMessage#ef156a5c flags:# offline_only:flags.0?true shortcut_id:int schedule:BusinessAwayMessageSchedule recipients:BusinessRecipients = BusinessAwayMessage;
timezone#ff9289f5 id:string name:string utc_offset:int = Timezone;
help.timezonesListNotModified#970708cc = help.TimezonesList;
help.timezonesList#7b74ed71 timezones:Vector<Timezone> hash:int = help.TimezonesList;
quickReply#697102b shortcut_id:int shortcut:string top_message:int count:int = QuickReply;
inputQuickReplyShortcut#24596d41 shortcut:string = InputQuickReplyShortcut;
inputQuickReplyShortcutId#1190cf1 shortcut_id:int = InputQuickReplyShortcut;
messages.quickReplies#c68d6695 quick_replies:Vector<QuickReply> messages:Vector<Message> chats:Vector<Chat> users:Vector<User> = messages.QuickReplies;
messages.quickRepliesNotModified#5f91eb5b = messages.QuickReplies;
connectedBot#cd64636c flags:# bot_id:long recipients:BusinessBotRecipients rights:BusinessBotRights = ConnectedBot;
account.connectedBots#17d7f87b connected_bots:Vector<ConnectedBot> users:Vector<User> = account.ConnectedBots;
messages.dialogFilters#2ad93719 flags:# tags_enabled:flags.0?true filters:Vector<DialogFilter> = messages.DialogFilters;
birthday#6c8e1e06 flags:# day:int month:int year:flags.0?int = Birthday;
botBusinessConnection#8f34b2f5 flags:# disabled:flags.1?true connection_id:string user_id:long dc_id:int date:int rights:flags.2?BusinessBotRights = BotBusinessConnection;
inputBusinessIntro#9c469cd flags:# title:string description:string sticker:flags.0?InputDocument = InputBusinessIntro;
businessIntro#5a0a066d flags:# title:string description:string sticker:flags.0?Document = BusinessIntro;
messages.myStickers#faff629d count:int sets:Vector<StickerSetCovered> = messages.MyStickers;
inputCollectibleUsername#e39460a9 username:string = InputCollectible;
inputCollectiblePhone#a2e214a4 phone:string = InputCollectible;
fragment.collectibleInfo#6ebdff91 purchase_date:int currency:string amount:long crypto_currency:string crypto_amount:long url:string = fragment.CollectibleInfo;
inputBusinessBotRecipients#c4e5921e flags:# existing_chats:flags.0?true new_chats:flags.1?true contacts:flags.2?true non_contacts:flags.3?true exclude_selected:flags.5?true users:flags.4?Vector<InputUser> exclude_users:flags.6?Vector<InputUser> = InputBusinessBotRecipients;
businessBotRecipients#b88cf373 flags:# existing_chats:flags.0?true new_chats:flags.1?true contacts:flags.2?true non_contacts:flags.3?true exclude_selected:flags.5?true users:flags.4?Vector<long> exclude_users:flags.6?Vector<long> = BusinessBotRecipients;
contactBirthday#1d998733 contact_id:long birthday:Birthday = ContactBirthday;
contacts.contactBirthdays#114ff30d contacts:Vector<ContactBirthday> users:Vector<User> = contacts.ContactBirthdays;
missingInvitee#628c9224 flags:# premium_would_allow_invite:flags.0?true premium_required_for_pm:flags.1?true user_id:long = MissingInvitee;
messages.invitedUsers#7f5defa6 updates:Updates missing_invitees:Vector<MissingInvitee> = messages.InvitedUsers;
inputBusinessChatLink#11679fa7 flags:# message:string entities:flags.0?Vector<MessageEntity> title:flags.1?string = InputBusinessChatLink;
businessChatLink#b4ae666f flags:# link:string message:string entities:flags.0?Vector<MessageEntity> title:flags.1?string views:int = BusinessChatLink;
account.businessChatLinks#ec43a2d1 links:Vector<BusinessChatLink> chats:Vector<Chat> users:Vector<User> = account.BusinessChatLinks;
account.resolvedBusinessChatLinks#9a23af21 flags:# peer:Peer message:string entities:flags.0?Vector<MessageEntity> chats:Vector<Chat> users:Vector<User> = account.ResolvedBusinessChatLinks;
requestedPeerUser#d62ff46a flags:# user_id:long first_name:flags.0?string last_name:flags.0?string username:flags.1?string photo:flags.2?Photo = RequestedPeer;
requestedPeerChat#7307544f flags:# chat_id:long title:flags.0?string photo:flags.2?Photo = RequestedPeer;
requestedPeerChannel#8ba403e4 flags:# channel_id:long title:flags.0?string username:flags.1?string photo:flags.2?Photo = RequestedPeer;
sponsoredMessageReportOption#430d3150 text:string option:bytes = SponsoredMessageReportOption;
channels.sponsoredMessageReportResultChooseOption#846f9e42 title:string options:Vector<SponsoredMessageReportOption> = channels.SponsoredMessageReportResult;
channels.sponsoredMessageReportResultAdsHidden#3e3bcf2f = channels.SponsoredMessageReportResult;
channels.sponsoredMessageReportResultReported#ad798849 = channels.SponsoredMessageReportResult;
reactionNotificationsFromContacts#bac3a61a = ReactionNotificationsFrom;
reactionNotificationsFromAll#4b9e22a0 = ReactionNotificationsFrom;
reactionsNotifySettings#56e34970 flags:# messages_notify_from:flags.0?ReactionNotificationsFrom stories_notify_from:flags.1?ReactionNotificationsFrom sound:NotificationSound show_previews:Bool = ReactionsNotifySettings;
availableEffect#93c3e27e flags:# premium_required:flags.2?true id:long emoticon:string static_icon_id:flags.0?long effect_sticker_id:long effect_animation_id:flags.1?long = AvailableEffect;
messages.availableEffectsNotModified#d1ed9a5b = messages.AvailableEffects;
messages.availableEffects#bddb616e hash:int effects:Vector<AvailableEffect> documents:Vector<Document> = messages.AvailableEffects;
factCheck#b89bfccf flags:# need_check:flags.0?true country:flags.1?string text:flags.1?TextWithEntities hash:long = FactCheck;
starsTransactionPeerUnsupported#95f2bfe4 = StarsTransactionPeer;
starsTransactionPeerAppStore#b457b375 = StarsTransactionPeer;
starsTransactionPeerPlayMarket#7b560a0b = StarsTransactionPeer;
starsTransactionPeerPremiumBot#250dbaf8 = StarsTransactionPeer;
starsTransactionPeerFragment#e92fd902 = StarsTransactionPeer;
starsTransactionPeer#d80da15d peer:Peer = StarsTransactionPeer;
starsTransactionPeerAds#60682812 = StarsTransactionPeer;
starsTransactionPeerAPI#f9677aad = StarsTransactionPeer;
starsTopupOption#bd915c0 flags:# extended:flags.1?true stars:long store_product:flags.0?string currency:string amount:long = StarsTopupOption;
starsTransaction#13659eb0 flags:# refund:flags.3?true pending:flags.4?true failed:flags.6?true gift:flags.10?true reaction:flags.11?true stargift_upgrade:flags.18?true business_transfer:flags.21?true stargift_resale:flags.22?true posts_search:flags.24?true stargift_prepaid_upgrade:flags.25?true id:string amount:StarsAmount date:int peer:StarsTransactionPeer title:flags.0?string description:flags.1?string photo:flags.2?WebDocument transaction_date:flags.5?int transaction_url:flags.5?string bot_payload:flags.7?bytes msg_id:flags.8?int extended_media:flags.9?Vector<MessageMedia> subscription_period:flags.12?int giveaway_post_id:flags.13?int stargift:flags.14?StarGift floodskip_number:flags.15?int starref_commission_permille:flags.16?int starref_peer:flags.17?Peer starref_amount:flags.17?StarsAmount paid_messages:flags.19?int premium_gift_months:flags.20?int ads_proceeds_from_date:flags.23?int ads_proceeds_to_date:flags.23?int = StarsTransaction;
payments.starsStatus#6c9ce8ed flags:# balance:StarsAmount subscriptions:flags.1?Vector<StarsSubscription> subscriptions_next_offset:flags.2?string subscriptions_missing_balance:flags.4?long history:flags.3?Vector<StarsTransaction> next_offset:flags.0?string chats:Vector<Chat> users:Vector<User> = payments.StarsStatus;
foundStory#e87acbc0 peer:Peer story:StoryItem = FoundStory;
stories.foundStories#e2de7737 flags:# count:int stories:Vector<FoundStory> next_offset:flags.0?string chats:Vector<Chat> users:Vector<User> = stories.FoundStories;
geoPointAddress#de4c5d93 flags:# country_iso2:string state:flags.0?string city:flags.1?string street:flags.2?string = GeoPointAddress;
starsRevenueStatus#febe5491 flags:# withdrawal_enabled:flags.0?true current_balance:StarsAmount available_balance:StarsAmount overall_revenue:StarsAmount next_withdrawal_at:flags.1?int = StarsRevenueStatus;
payments.starsRevenueStats#6c207376 flags:# top_hours_graph:flags.0?StatsGraph revenue_graph:StatsGraph status:StarsRevenueStatus usd_rate:double = payments.StarsRevenueStats;
payments.starsRevenueWithdrawalUrl#1dab80b7 url:string = payments.StarsRevenueWithdrawalUrl;
payments.starsRevenueAdsAccountUrl#394e7f21 url:string = payments.StarsRevenueAdsAccountUrl;
inputStarsTransaction#206ae6d1 flags:# refund:flags.0?true id:string = InputStarsTransaction;
starsGiftOption#5e0589f1 flags:# extended:flags.1?true stars:long store_product:flags.0?string currency:string amount:long = StarsGiftOption;
bots.popularAppBots#1991b13b flags:# next_offset:flags.0?string users:Vector<User> = bots.PopularAppBots;
botPreviewMedia#23e91ba3 date:int media:MessageMedia = BotPreviewMedia;
bots.previewInfo#ca71d64 media:Vector<BotPreviewMedia> lang_codes:Vector<string> = bots.PreviewInfo;
starsSubscriptionPricing#5416d58 period:int amount:long = StarsSubscriptionPricing;
starsSubscription#2e6eab1a flags:# canceled:flags.0?true can_refulfill:flags.1?true missing_balance:flags.2?true bot_canceled:flags.7?true id:string peer:Peer until_date:int pricing:StarsSubscriptionPricing chat_invite_hash:flags.3?string title:flags.4?string photo:flags.5?WebDocument invoice_slug:flags.6?string = StarsSubscription;
messageReactor#4ba3a95a flags:# top:flags.0?true my:flags.1?true anonymous:flags.2?true peer_id:flags.3?Peer count:int = MessageReactor;
starsGiveawayOption#94ce852a flags:# extended:flags.0?true default:flags.1?true stars:long yearly_boosts:int store_product:flags.2?string currency:string amount:long winners:Vector<StarsGiveawayWinnersOption> = StarsGiveawayOption;
starsGiveawayWinnersOption#54236209 flags:# default:flags.0?true users:int per_user_stars:long = StarsGiveawayWinnersOption;
starGift#bcff5b flags:# limited:flags.0?true sold_out:flags.1?true birthday:flags.2?true require_premium:flags.7?true limited_per_user:flags.8?true id:long sticker:Document stars:long availability_remains:flags.0?int availability_total:flags.0?int availability_resale:flags.4?long convert_stars:long first_sale_date:flags.1?int last_sale_date:flags.1?int upgrade_stars:flags.3?long resell_min_stars:flags.4?long title:flags.5?string released_by:flags.6?Peer per_user_total:flags.8?int per_user_remains:flags.8?int = StarGift;
starGiftUnique#26a5553e flags:# require_premium:flags.6?true resale_ton_only:flags.7?true id:long gift_id:long title:string slug:string num:int owner_id:flags.0?Peer owner_name:flags.1?string owner_address:flags.2?string attributes:Vector<StarGiftAttribute> availability_issued:int availability_total:int gift_address:flags.3?string resell_amount:flags.4?Vector<StarsAmount> released_by:flags.5?Peer value_amount:flags.8?long value_currency:flags.8?string = StarGift;
payments.starGiftsNotModified#a388a368 = payments.StarGifts;
payments.starGifts#2ed82995 hash:int gifts:Vector<StarGift> chats:Vector<Chat> users:Vector<User> = payments.StarGifts;
messageReportOption#7903e3d9 text:string option:bytes = MessageReportOption;
reportResultChooseOption#f0e4e0b6 title:string options:Vector<MessageReportOption> = ReportResult;
reportResultAddComment#6f09ac31 flags:# optional:flags.0?true option:bytes = ReportResult;
reportResultReported#8db33c4b = ReportResult;
messages.botPreparedInlineMessage#8ecf0511 id:string expire_date:int = messages.BotPreparedInlineMessage;
messages.preparedInlineMessage#ff57708d query_id:long result:BotInlineResult peer_types:Vector<InlineQueryPeerType> cache_time:int users:Vector<User> = messages.PreparedInlineMessage;
botAppSettings#c99b1950 flags:# placeholder_path:flags.0?bytes background_color:flags.1?int background_dark_color:flags.2?int header_color:flags.3?int header_dark_color:flags.4?int = BotAppSettings;
starRefProgram#dd0c66f2 flags:# bot_id:long commission_permille:int duration_months:flags.0?int end_date:flags.1?int daily_revenue_per_user:flags.2?StarsAmount = StarRefProgram;
connectedBotStarRef#19a13f71 flags:# revoked:flags.1?true url:string date:int bot_id:long commission_permille:int duration_months:flags.0?int participants:long revenue:long = ConnectedBotStarRef;
payments.connectedStarRefBots#98d5ea1d count:int connected_bots:Vector<ConnectedBotStarRef> users:Vector<User> = payments.ConnectedStarRefBots;
payments.suggestedStarRefBots#b4d5d859 flags:# count:int suggested_bots:Vector<StarRefProgram> users:Vector<User> next_offset:flags.0?string = payments.SuggestedStarRefBots;
starsAmount#bbb6b4a3 amount:long nanos:int = StarsAmount;
starsTonAmount#74aee3e0 amount:long = StarsAmount;
messages.foundStickersNotModified#6010c534 flags:# next_offset:flags.0?int = messages.FoundStickers;
messages.foundStickers#82c9e290 flags:# next_offset:flags.0?int hash:long stickers:Vector<Document> = messages.FoundStickers;
botVerifierSettings#b0cd6617 flags:# can_modify_custom_description:flags.1?true icon:long company:string custom_description:flags.0?string = BotVerifierSettings;
botVerification#f93cd45c bot_id:long icon:long description:string = BotVerification;
starGiftAttributeModel#39d99013 name:string document:Document rarity_permille:int = StarGiftAttribute;
starGiftAttributePattern#13acff19 name:string document:Document rarity_permille:int = StarGiftAttribute;
starGiftAttributeBackdrop#d93d859c name:string backdrop_id:int center_color:int edge_color:int pattern_color:int text_color:int rarity_permille:int = StarGiftAttribute;
starGiftAttributeOriginalDetails#e0bff26c flags:# sender_id:flags.0?Peer recipient_id:Peer date:int message:flags.1?TextWithEntities = StarGiftAttribute;
payments.starGiftUpgradePreview#167bd90b sample_attributes:Vector<StarGiftAttribute> = payments.StarGiftUpgradePreview;
users.users#62d706b8 users:Vector<User> = users.Users;
users.usersSlice#315a4974 count:int users:Vector<User> = users.Users;
payments.uniqueStarGift#caa2f60b gift:StarGift users:Vector<User> = payments.UniqueStarGift;
messages.webPagePreview#b53e8b21 media:MessageMedia users:Vector<User> = messages.WebPagePreview;
savedStarGift#19a9b572 flags:# name_hidden:flags.0?true unsaved:flags.5?true refunded:flags.9?true can_upgrade:flags.10?true pinned_to_top:flags.12?true from_id:flags.1?Peer date:int gift:StarGift message:flags.2?TextWithEntities msg_id:flags.3?int saved_id:flags.11?long convert_stars:flags.4?long upgrade_stars:flags.6?long can_export_at:flags.7?int transfer_stars:flags.8?long can_transfer_at:flags.13?int can_resell_at:flags.14?int collection_id:flags.15?Vector<int> prepaid_upgrade_hash:flags.16?string = SavedStarGift;
payments.savedStarGifts#95f389b1 flags:# count:int chat_notifications_enabled:flags.1?Bool gifts:Vector<SavedStarGift> next_offset:flags.0?string chats:Vector<Chat> users:Vector<User> = payments.SavedStarGifts;
inputSavedStarGiftUser#69279795 msg_id:int = InputSavedStarGift;
inputSavedStarGiftChat#f101aa7f peer:InputPeer saved_id:long = InputSavedStarGift;
inputSavedStarGiftSlug#2085c238 slug:string = InputSavedStarGift;
payments.starGiftWithdrawalUrl#84aa3a9c url:string = payments.StarGiftWithdrawalUrl;
paidReactionPrivacyDefault#206ad49e = PaidReactionPrivacy;
paidReactionPrivacyAnonymous#1f0c1ad9 = PaidReactionPrivacy;
paidReactionPrivacyPeer#dc6cfcf0 peer:InputPeer = PaidReactionPrivacy;
account.paidMessagesRevenue#1e109708 stars_amount:long = account.PaidMessagesRevenue;
requirementToContactEmpty#50a9839 = RequirementToContact;
requirementToContactPremium#e581e4e9 = RequirementToContact;
requirementToContactPaidMessages#b4f67e93 stars_amount:long = RequirementToContact;
businessBotRights#a0624cf7 flags:# reply:flags.0?true read_messages:flags.1?true delete_sent_messages:flags.2?true delete_received_messages:flags.3?true edit_name:flags.4?true edit_bio:flags.5?true edit_profile_photo:flags.6?true edit_username:flags.7?true view_gifts:flags.8?true sell_gifts:flags.9?true change_gift_settings:flags.10?true transfer_and_upgrade_gifts:flags.11?true transfer_stars:flags.12?true manage_stories:flags.13?true = BusinessBotRights;
disallowedGiftsSettings#71f276c4 flags:# disallow_unlimited_stargifts:flags.0?true disallow_limited_stargifts:flags.1?true disallow_unique_stargifts:flags.2?true disallow_premium_gifts:flags.3?true = DisallowedGiftsSettings;
sponsoredPeer#c69708d3 flags:# random_id:bytes peer:Peer sponsor_info:flags.0?string additional_info:flags.1?string = SponsoredPeer;
contacts.sponsoredPeersEmpty#ea32b4b1 = contacts.SponsoredPeers;
contacts.sponsoredPeers#eb032884 peers:Vector<SponsoredPeer> chats:Vector<Chat> users:Vector<User> = contacts.SponsoredPeers;
starGiftAttributeIdModel#48aaae3c document_id:long = StarGiftAttributeId;
starGiftAttributeIdPattern#4a162433 document_id:long = StarGiftAttributeId;
starGiftAttributeIdBackdrop#1f01c757 backdrop_id:int = StarGiftAttributeId;
starGiftAttributeCounter#2eb1b658 attribute:StarGiftAttributeId count:int = StarGiftAttributeCounter;
payments.resaleStarGifts#947a12df flags:# count:int gifts:Vector<StarGift> next_offset:flags.0?string attributes:flags.1?Vector<StarGiftAttribute> attributes_hash:flags.1?long chats:Vector<Chat> counters:flags.2?Vector<StarGiftAttributeCounter> users:Vector<User> = payments.ResaleStarGifts;
stories.canSendStoryCount#c387c04e count_remains:int = stories.CanSendStoryCount;
pendingSuggestion#e7e82e12 suggestion:string title:TextWithEntities description:TextWithEntities url:string = PendingSuggestion;
todoItem#cba9a52f id:int title:TextWithEntities = TodoItem;
todoList#49b92a26 flags:# others_can_append:flags.0?true others_can_complete:flags.1?true title:TextWithEntities list:Vector<TodoItem> = TodoList;
todoCompletion#4cc120b7 id:int completed_by:long date:int = TodoCompletion;
suggestedPost#e8e37e5 flags:# accepted:flags.1?true rejected:flags.2?true price:flags.3?StarsAmount schedule_date:flags.0?int = SuggestedPost;
starsRating#1b0e4f07 flags:# level:int current_level_stars:long stars:long next_level_stars:flags.0?long = StarsRating;
starGiftCollection#9d6b13b0 flags:# collection_id:int title:string icon:flags.0?Document gifts_count:int hash:long = StarGiftCollection;
payments.starGiftCollectionsNotModified#a0ba4f17 = payments.StarGiftCollections;
payments.starGiftCollections#8a2932f3 collections:Vector<StarGiftCollection> = payments.StarGiftCollections;
storyAlbum#9325705a flags:# album_id:int title:string icon_photo:flags.0?Photo icon_video:flags.1?Document = StoryAlbum;
stories.albumsNotModified#564edaeb = stories.Albums;
stories.albums#c3987a3a hash:long albums:Vector<StoryAlbum> = stories.Albums;
searchPostsFlood#3e0b5b6a flags:# query_is_free:flags.0?true total_daily:int remains:int wait_till:flags.1?int stars_amount:long = SearchPostsFlood;
payments.uniqueStarGiftValueInfo#512fe446 flags:# last_sale_on_fragment:flags.1?true value_is_average:flags.6?true currency:string value:long initial_sale_date:int initial_sale_stars:long initial_sale_price:long last_sale_date:flags.0?int last_sale_price:flags.0?long floor_price:flags.2?long average_price:flags.3?long listed_count:flags.4?int fragment_listed_count:flags.5?int fragment_listed_url:flags.5?string = payments.UniqueStarGiftValueInfo;
---functions---
invokeAfterMsg#cb9f372d {X:Type} msg_id:long query:!X = X;
initConnection#c1cd5ea9 {X:Type} flags:# api_id:int device_model:string system_version:string app_version:string system_lang_code:string lang_pack:string lang_code:string proxy:flags.0?InputClientProxy params:flags.1?JSONValue query:!X = X;
invokeWithLayer#da9b0d0d {X:Type} layer:int query:!X = X;
auth.sendCode#a677244f phone_number:string api_id:int api_hash:string settings:CodeSettings = auth.SentCode;
auth.signUp#aac7b717 flags:# no_joined_notifications:flags.0?true phone_number:string phone_code_hash:string first_name:string last_name:string = auth.Authorization;
auth.signIn#8d52a951 flags:# phone_number:string phone_code_hash:string phone_code:flags.0?string email_verification:flags.1?EmailVerification = auth.Authorization;
auth.logOut#3e72ba19 = auth.LoggedOut;
auth.resetAuthorizations#9fab0d1a = Bool;
auth.exportAuthorization#e5bfffcd dc_id:int = auth.ExportedAuthorization;
auth.importAuthorization#a57a7dad id:long bytes:bytes = auth.Authorization;
auth.bindTempAuthKey#cdd42a05 perm_auth_key_id:long nonce:long expires_at:int encrypted_message:bytes = Bool;
auth.checkPassword#d18b4d16 password:InputCheckPasswordSRP = auth.Authorization;
auth.requestPasswordRecovery#d897bc66 = auth.PasswordRecovery;
auth.resendCode#cae47523 flags:# phone_number:string phone_code_hash:string reason:flags.0?string = auth.SentCode;
auth.cancelCode#1f040578 phone_number:string phone_code_hash:string = Bool;
auth.dropTempAuthKeys#8e48a188 except_auth_keys:Vector<long> = Bool;
auth.exportLoginToken#b7e085fe api_id:int api_hash:string except_ids:Vector<long> = auth.LoginToken;
auth.importLoginToken#95ac5ce4 token:bytes = auth.LoginToken;
auth.importWebTokenAuthorization#2db873a9 api_id:int api_hash:string web_auth_token:string = auth.Authorization;
account.registerDevice#ec86017a flags:# no_muted:flags.0?true token_type:int token:string app_sandbox:Bool secret:bytes other_uids:Vector<long> = Bool;
account.unregisterDevice#6a0d3206 token_type:int token:string other_uids:Vector<long> = Bool;
account.updateNotifySettings#84be5b93 peer:InputNotifyPeer settings:InputPeerNotifySettings = Bool;
account.getNotifySettings#12b3ad31 peer:InputNotifyPeer = PeerNotifySettings;
account.updateProfile#78515775 flags:# first_name:flags.0?string last_name:flags.1?string about:flags.2?string = User;
account.updateStatus#6628562c offline:Bool = Bool;
account.getWallPapers#7967d36 hash:long = account.WallPapers;
account.reportPeer#c5ba3d86 peer:InputPeer reason:ReportReason message:string = Bool;
account.checkUsername#2714d86c username:string = Bool;
account.updateUsername#3e0bdd7c username:string = User;
account.getPrivacy#dadbc950 key:InputPrivacyKey = account.PrivacyRules;
account.setPrivacy#c9f81ce8 key:InputPrivacyKey rules:Vector<InputPrivacyRule> = account.PrivacyRules;
account.getAccountTTL#8fc711d = AccountDaysTTL;
account.setAccountTTL#2442485e ttl:AccountDaysTTL = Bool;
account.getAuthorizations#e320c158 = account.Authorizations;
account.resetAuthorization#df77f3bc hash:long = Bool;
account.getPassword#548a30f5 = account.Password;
account.getPasswordSettings#9cd4eaf9 password:InputCheckPasswordSRP = account.PasswordSettings;
account.updatePasswordSettings#a59b102f password:InputCheckPasswordSRP new_settings:account.PasswordInputSettings = Bool;
account.sendConfirmPhoneCode#1b3faa88 hash:string settings:CodeSettings = auth.SentCode;
account.confirmPhone#5f2178c3 phone_code_hash:string phone_code:string = Bool;
account.getTmpPassword#449e0b51 password:InputCheckPasswordSRP period:int = account.TmpPassword;
account.getWebAuthorizations#182e6d6f = account.WebAuthorizations;
account.resetWebAuthorization#2d01b9ef hash:long = Bool;
account.resetWebAuthorizations#682d2594 = Bool;
account.sendVerifyPhoneCode#a5a356f9 phone_number:string settings:CodeSettings = auth.SentCode;
account.confirmPasswordEmail#8fdf1920 code:string = Bool;
account.getContactSignUpNotification#9f07c728 = Bool;
account.setContactSignUpNotification#cff43f61 silent:Bool = Bool;
account.getNotifyExceptions#53577479 flags:# compare_sound:flags.1?true compare_stories:flags.2?true peer:flags.0?InputNotifyPeer = Updates;
account.uploadWallPaper#e39a8f03 flags:# for_chat:flags.0?true file:InputFile mime_type:string settings:WallPaperSettings = WallPaper;
account.setContentSettings#b574b16b flags:# sensitive_enabled:flags.0?true = Bool;
account.getContentSettings#8b9b4dae = account.ContentSettings;
account.getGlobalPrivacySettings#eb2b4cf6 = GlobalPrivacySettings;
account.setGlobalPrivacySettings#1edaaac2 settings:GlobalPrivacySettings = GlobalPrivacySettings;
account.reportProfilePhoto#fa8cc6f5 peer:InputPeer photo_id:InputPhoto reason:ReportReason message:string = Bool;
account.setAuthorizationTTL#bf899aa0 authorization_ttl_days:int = Bool;
account.changeAuthorizationSettings#40f48462 flags:# confirmed:flags.3?true hash:long encrypted_requests_disabled:flags.0?Bool call_requests_disabled:flags.1?Bool = Bool;
account.updateEmojiStatus#fbd3de6b emoji_status:EmojiStatus = Bool;
account.getRecentEmojiStatuses#f578105 hash:long = account.EmojiStatuses;
account.reorderUsernames#ef500eab order:Vector<string> = Bool;
account.toggleUsername#58d6b376 username:string active:Bool = Bool;
account.resolveBusinessChatLink#5492e5ee slug:string = account.ResolvedBusinessChatLinks;
account.toggleSponsoredMessages#b9d9a38d enabled:Bool = Bool;
account.getCollectibleEmojiStatuses#2e7b4543 hash:long = account.EmojiStatuses;
account.getPaidMessagesRevenue#19ba4a67 flags:# parent_peer:flags.0?InputPeer user_id:InputUser = account.PaidMessagesRevenue;
account.toggleNoPaidMessagesException#fe2eda76 flags:# refund_charged:flags.0?true require_payment:flags.2?true parent_peer:flags.1?InputPeer user_id:InputUser = Bool;
users.getUsers#d91a548 id:Vector<InputUser> = Vector<User>;
users.getFullUser#b60f5918 id:InputUser = users.UserFull;
contacts.getContacts#5dd69e12 hash:long = contacts.Contacts;
contacts.importContacts#2c800be5 contacts:Vector<InputContact> = contacts.ImportedContacts;
contacts.deleteContacts#96a0e00 id:Vector<InputUser> = Updates;
contacts.block#2e2e8734 flags:# my_stories_from:flags.0?true id:InputPeer = Bool;
contacts.unblock#b550d328 flags:# my_stories_from:flags.0?true id:InputPeer = Bool;
contacts.getBlocked#9a868f80 flags:# my_stories_from:flags.0?true offset:int limit:int = contacts.Blocked;
contacts.search#11f812d8 q:string limit:int = contacts.Found;
contacts.resolveUsername#725afbbc flags:# username:string referer:flags.0?string = contacts.ResolvedPeer;
contacts.getTopPeers#973478b6 flags:# correspondents:flags.0?true bots_pm:flags.1?true bots_inline:flags.2?true phone_calls:flags.3?true forward_users:flags.4?true forward_chats:flags.5?true groups:flags.10?true channels:flags.15?true bots_app:flags.16?true offset:int limit:int hash:long = contacts.TopPeers;
contacts.addContact#e8f463d0 flags:# add_phone_privacy_exception:flags.0?true id:InputUser first_name:string last_name:string phone:string = Updates;
contacts.resolvePhone#8af94344 phone:string = contacts.ResolvedPeer;
contacts.editCloseFriends#ba6705f0 id:Vector<long> = Bool;
contacts.getSponsoredPeers#b6c8c393 q:string = contacts.SponsoredPeers;
messages.getMessages#63c66506 id:Vector<InputMessage> = messages.Messages;
messages.getDialogs#a0f4cb4f flags:# exclude_pinned:flags.0?true folder_id:flags.1?int offset_date:int offset_id:int offset_peer:InputPeer limit:int hash:long = messages.Dialogs;
messages.getHistory#4423e6c5 peer:InputPeer offset_id:int offset_date:int add_offset:int limit:int max_id:int min_id:int hash:long = messages.Messages;
messages.search#29ee847a flags:# peer:InputPeer q:string from_id:flags.0?InputPeer saved_peer_id:flags.2?InputPeer saved_reaction:flags.3?Vector<Reaction> top_msg_id:flags.1?int filter:MessagesFilter min_date:int max_date:int offset_id:int add_offset:int limit:int max_id:int min_id:int hash:long = messages.Messages;
messages.readHistory#e306d3a peer:InputPeer max_id:int = messages.AffectedMessages;
messages.deleteHistory#b08f922a flags:# just_clear:flags.0?true revoke:flags.1?true peer:InputPeer max_id:int min_date:flags.2?int max_date:flags.3?int = messages.AffectedHistory;
messages.deleteMessages#e58e95d2 flags:# revoke:flags.0?true id:Vector<int> = messages.AffectedMessages;
messages.receivedMessages#5a954c0 max_id:int = Vector<ReceivedNotifyMessage>;
messages.setTyping#58943ee2 flags:# peer:InputPeer top_msg_id:flags.0?int action:SendMessageAction = Bool;
messages.sendMessage#fe05dc9a flags:# no_webpage:flags.1?true silent:flags.5?true background:flags.6?true clear_draft:flags.7?true noforwards:flags.14?true update_stickersets_order:flags.15?true invert_media:flags.16?true allow_paid_floodskip:flags.19?true peer:InputPeer reply_to:flags.0?InputReplyTo message:string random_id:long reply_markup:flags.2?ReplyMarkup entities:flags.3?Vector<MessageEntity> schedule_date:flags.10?int send_as:flags.13?InputPeer quick_reply_shortcut:flags.17?InputQuickReplyShortcut effect:flags.18?long allow_paid_stars:flags.21?long suggested_post:flags.22?SuggestedPost = Updates;
messages.sendMedia#ac55d9c1 flags:# silent:flags.5?true background:flags.6?true clear_draft:flags.7?true noforwards:flags.14?true update_stickersets_order:flags.15?true invert_media:flags.16?true allow_paid_floodskip:flags.19?true peer:InputPeer reply_to:flags.0?InputReplyTo media:InputMedia message:string random_id:long reply_markup:flags.2?ReplyMarkup entities:flags.3?Vector<MessageEntity> schedule_date:flags.10?int send_as:flags.13?InputPeer quick_reply_shortcut:flags.17?InputQuickReplyShortcut effect:flags.18?long allow_paid_stars:flags.21?long suggested_post:flags.22?SuggestedPost = Updates;
messages.forwardMessages#978928ca flags:# silent:flags.5?true background:flags.6?true with_my_score:flags.8?true drop_author:flags.11?true drop_media_captions:flags.12?true noforwards:flags.14?true allow_paid_floodskip:flags.19?true from_peer:InputPeer id:Vector<int> random_id:Vector<long> to_peer:InputPeer top_msg_id:flags.9?int reply_to:flags.22?InputReplyTo schedule_date:flags.10?int send_as:flags.13?InputPeer quick_reply_shortcut:flags.17?InputQuickReplyShortcut video_timestamp:flags.20?int allow_paid_stars:flags.21?long suggested_post:flags.23?SuggestedPost = Updates;
messages.reportSpam#cf1592db peer:InputPeer = Bool;
messages.getPeerSettings#efd9a6a2 peer:InputPeer = messages.PeerSettings;
messages.report#fc78af9b peer:InputPeer id:Vector<int> option:bytes message:string = ReportResult;
messages.getChats#49e9528f id:Vector<long> = messages.Chats;
messages.getFullChat#aeb00b34 chat_id:long = messages.ChatFull;
messages.editChatTitle#73783ffd chat_id:long title:string = Updates;
messages.editChatPhoto#35ddd674 chat_id:long photo:InputChatPhoto = Updates;
messages.addChatUser#cbc6d107 chat_id:long user_id:InputUser fwd_limit:int = messages.InvitedUsers;
messages.deleteChatUser#a2185cab flags:# revoke_history:flags.0?true chat_id:long user_id:InputUser = Updates;
messages.createChat#92ceddd4 flags:# users:Vector<InputUser> title:string ttl_period:flags.0?int = messages.InvitedUsers;
messages.getDhConfig#26cf8950 version:int random_length:int = messages.DhConfig;
messages.readMessageContents#36a73f77 id:Vector<int> = messages.AffectedMessages;
messages.getStickers#d5a5d3a1 emoticon:string hash:long = messages.Stickers;
messages.getAllStickers#b8a0a1a8 hash:long = messages.AllStickers;
messages.getWebPagePreview#570d6f6f flags:# message:string entities:flags.3?Vector<MessageEntity> = messages.WebPagePreview;
messages.exportChatInvite#a455de90 flags:# legacy_revoke_permanent:flags.2?true request_needed:flags.3?true peer:InputPeer expire_date:flags.0?int usage_limit:flags.1?int title:flags.4?string subscription_pricing:flags.5?StarsSubscriptionPricing = ExportedChatInvite;
messages.checkChatInvite#3eadb1bb hash:string = ChatInvite;
messages.importChatInvite#6c50051c hash:string = Updates;
messages.getStickerSet#c8a0ec74 stickerset:InputStickerSet hash:int = messages.StickerSet;
messages.installStickerSet#c78fe460 stickerset:InputStickerSet archived:Bool = messages.StickerSetInstallResult;
messages.uninstallStickerSet#f96e55de stickerset:InputStickerSet = Bool;
messages.startBot#e6df7378 bot:InputUser peer:InputPeer random_id:long start_param:string = Updates;
messages.getMessagesViews#5784d3e1 peer:InputPeer id:Vector<int> increment:Bool = messages.MessageViews;
messages.migrateChat#a2875319 chat_id:long = Updates;
messages.searchGlobal#4bc6589a flags:# broadcasts_only:flags.1?true groups_only:flags.2?true users_only:flags.3?true folder_id:flags.0?int q:string filter:MessagesFilter min_date:int max_date:int offset_rate:int offset_peer:InputPeer offset_id:int limit:int = messages.Messages;
messages.getDocumentByHash#b1f2061f sha256:bytes size:long mime_type:string = Document;
messages.getSavedGifs#5cf09635 hash:long = messages.SavedGifs;
messages.saveGif#327a30cb id:InputDocument unsave:Bool = Bool;
messages.getInlineBotResults#514e999d flags:# bot:InputUser peer:InputPeer geo_point:flags.0?InputGeoPoint query:string offset:string = messages.BotResults;
messages.sendInlineBotResult#c0cf7646 flags:# silent:flags.5?true background:flags.6?true clear_draft:flags.7?true hide_via:flags.11?true peer:InputPeer reply_to:flags.0?InputReplyTo random_id:long query_id:long id:string schedule_date:flags.10?int send_as:flags.13?InputPeer quick_reply_shortcut:flags.17?InputQuickReplyShortcut allow_paid_stars:flags.21?long = Updates;
messages.editMessage#dfd14005 flags:# no_webpage:flags.1?true invert_media:flags.16?true peer:InputPeer id:int message:flags.11?string media:flags.14?InputMedia reply_markup:flags.2?ReplyMarkup entities:flags.3?Vector<MessageEntity> schedule_date:flags.15?int quick_reply_shortcut_id:flags.17?int = Updates;
messages.getBotCallbackAnswer#9342ca07 flags:# game:flags.1?true peer:InputPeer msg_id:int data:flags.0?bytes password:flags.2?InputCheckPasswordSRP = messages.BotCallbackAnswer;
messages.getPeerDialogs#e470bcfd peers:Vector<InputDialogPeer> = messages.PeerDialogs;
messages.saveDraft#54ae308e flags:# no_webpage:flags.1?true invert_media:flags.6?true reply_to:flags.4?InputReplyTo peer:InputPeer message:string entities:flags.3?Vector<MessageEntity> media:flags.5?InputMedia effect:flags.7?long suggested_post:flags.8?SuggestedPost = Bool;
messages.getFeaturedStickers#64780b14 hash:long = messages.FeaturedStickers;
messages.readFeaturedStickers#5b118126 id:Vector<long> = Bool;
messages.getRecentStickers#9da9403b flags:# attached:flags.0?true hash:long = messages.RecentStickers;
messages.saveRecentSticker#392718f8 flags:# attached:flags.0?true id:InputDocument unsave:Bool = Bool;
messages.clearRecentStickers#8999602d flags:# attached:flags.0?true = Bool;
messages.getCommonChats#e40ca104 user_id:InputUser max_id:long limit:int = messages.Chats;
messages.getWebPage#8d9692a3 url:string hash:int = messages.WebPage;
messages.toggleDialogPin#a731e257 flags:# pinned:flags.0?true peer:InputDialogPeer = Bool;
messages.getPinnedDialogs#d6b94df2 folder_id:int = messages.PeerDialogs;
messages.uploadMedia#14967978 flags:# business_connection_id:flags.0?string peer:InputPeer media:InputMedia = MessageMedia;
messages.getFavedStickers#4f1aaa9 hash:long = messages.FavedStickers;
messages.faveSticker#b9ffc55b id:InputDocument unfave:Bool = Bool;
messages.getUnreadMentions#f107e790 flags:# peer:InputPeer top_msg_id:flags.0?int offset_id:int add_offset:int limit:int max_id:int min_id:int = messages.Messages;
messages.readMentions#36e5bf4d flags:# peer:InputPeer top_msg_id:flags.0?int = messages.AffectedHistory;
messages.sendMultiMedia#1bf89d74 flags:# silent:flags.5?true background:flags.6?true clear_draft:flags.7?true noforwards:flags.14?true update_stickersets_order:flags.15?true invert_media:flags.16?true allow_paid_floodskip:flags.19?true peer:InputPeer reply_to:flags.0?InputReplyTo multi_media:Vector<InputSingleMedia> schedule_date:flags.10?int send_as:flags.13?InputPeer quick_reply_shortcut:flags.17?InputQuickReplyShortcut effect:flags.18?long allow_paid_stars:flags.21?long = Updates;
messages.searchStickerSets#35705b8a flags:# exclude_featured:flags.0?true q:string hash:long = messages.FoundStickerSets;
messages.markDialogUnread#8c5006f8 flags:# unread:flags.0?true parent_peer:flags.1?InputPeer peer:InputDialogPeer = Bool;
messages.updatePinnedMessage#d2aaf7ec flags:# silent:flags.0?true unpin:flags.1?true pm_oneside:flags.2?true peer:InputPeer id:int = Updates;
messages.sendVote#10ea6184 peer:InputPeer msg_id:int options:Vector<bytes> = Updates;
messages.getOnlines#6e2be050 peer:InputPeer = ChatOnlines;
messages.editChatAbout#def60797 peer:InputPeer about:string = Bool;
messages.editChatDefaultBannedRights#a5866b41 peer:InputPeer banned_rights:ChatBannedRights = Updates;
messages.getEmojiKeywordsDifference#1508b6af lang_code:string from_version:int = EmojiKeywordsDifference;
messages.requestUrlAuth#198fb446 flags:# peer:flags.1?InputPeer msg_id:flags.1?int button_id:flags.1?int url:flags.2?string = UrlAuthResult;
messages.acceptUrlAuth#b12c7125 flags:# write_allowed:flags.0?true peer:flags.1?InputPeer msg_id:flags.1?int button_id:flags.1?int url:flags.2?string = UrlAuthResult;
messages.hidePeerSettingsBar#4facb138 peer:InputPeer = Bool;
messages.getScheduledHistory#f516760b peer:InputPeer hash:long = messages.Messages;
messages.sendScheduledMessages#bd38850a peer:InputPeer id:Vector<int> = Updates;
messages.deleteScheduledMessages#59ae2b16 peer:InputPeer id:Vector<int> = Updates;
messages.getPollVotes#b86e380e flags:# peer:InputPeer id:int option:flags.0?bytes offset:flags.1?string limit:int = messages.VotesList;
messages.getDialogFilters#efd48c89 = messages.DialogFilters;
messages.getSuggestedDialogFilters#a29cd42c = Vector<DialogFilterSuggested>;
messages.updateDialogFilter#1ad4a04a flags:# id:int filter:flags.0?DialogFilter = Bool;
messages.updateDialogFiltersOrder#c563c1e4 order:Vector<int> = Bool;
messages.getReplies#22ddd30c peer:InputPeer msg_id:int offset_id:int offset_date:int add_offset:int limit:int max_id:int min_id:int hash:long = messages.Messages;
messages.getDiscussionMessage#446972fd peer:InputPeer msg_id:int = messages.DiscussionMessage;
messages.readDiscussion#f731a9f4 peer:InputPeer msg_id:int read_max_id:int = Bool;
messages.unpinAllMessages#62dd747 flags:# peer:InputPeer top_msg_id:flags.0?int saved_peer_id:flags.1?InputPeer = messages.AffectedHistory;
messages.deleteChat#5bd0ee50 chat_id:long = Bool;
messages.getExportedChatInvites#a2b5a3f6 flags:# revoked:flags.3?true peer:InputPeer admin_id:InputUser offset_date:flags.2?int offset_link:flags.2?string limit:int = messages.ExportedChatInvites;
messages.editExportedChatInvite#bdca2f75 flags:# revoked:flags.2?true peer:InputPeer link:string expire_date:flags.0?int usage_limit:flags.1?int request_needed:flags.3?Bool title:flags.4?string = messages.ExportedChatInvite;
messages.deleteRevokedExportedChatInvites#56987bd5 peer:InputPeer admin_id:InputUser = Bool;
messages.deleteExportedChatInvite#d464a42b peer:InputPeer link:string = Bool;
messages.getChatInviteImporters#df04dd4e flags:# requested:flags.0?true subscription_expired:flags.3?true peer:InputPeer link:flags.1?string q:flags.2?string offset_date:int offset_user:InputUser limit:int = messages.ChatInviteImporters;
messages.getMessageReadParticipants#31c1c44f peer:InputPeer msg_id:int = Vector<ReadParticipantDate>;
messages.hideChatJoinRequest#7fe7e815 flags:# approved:flags.0?true peer:InputPeer user_id:InputUser = Updates;
messages.hideAllChatJoinRequests#e085f4ea flags:# approved:flags.0?true peer:InputPeer link:flags.1?string = Updates;
messages.toggleNoForwards#b11eafa2 peer:InputPeer enabled:Bool = Updates;
messages.saveDefaultSendAs#ccfddf96 peer:InputPeer send_as:InputPeer = Bool;
messages.sendReaction#d30d78d4 flags:# big:flags.1?true add_to_recent:flags.2?true peer:InputPeer msg_id:int reaction:flags.0?Vector<Reaction> = Updates;
messages.getMessagesReactions#8bba90e6 peer:InputPeer id:Vector<int> = Updates;
messages.getMessageReactionsList#461b3f48 flags:# peer:InputPeer id:int reaction:flags.0?Reaction offset:flags.1?string limit:int = messages.MessageReactionsList;
messages.setChatAvailableReactions#864b2581 flags:# peer:InputPeer available_reactions:ChatReactions reactions_limit:flags.0?int paid_enabled:flags.1?Bool = Updates;
messages.getAvailableReactions#18dea0ac hash:int = messages.AvailableReactions;
messages.setDefaultReaction#4f47a016 reaction:Reaction = Bool;
messages.translateText#63183030 flags:# peer:flags.0?InputPeer id:flags.0?Vector<int> text:flags.1?Vector<TextWithEntities> to_lang:string = messages.TranslatedText;
messages.getUnreadReactions#bd7f90ac flags:# peer:InputPeer top_msg_id:flags.0?int saved_peer_id:flags.1?InputPeer offset_id:int add_offset:int limit:int max_id:int min_id:int = messages.Messages;
messages.readReactions#9ec44f93 flags:# peer:InputPeer top_msg_id:flags.0?int saved_peer_id:flags.1?InputPeer = messages.AffectedHistory;
messages.getAttachMenuBots#16fcc2cb hash:long = AttachMenuBots;
messages.getAttachMenuBot#77216192 bot:InputUser = AttachMenuBotsBot;
messages.toggleBotInAttachMenu#69f59d69 flags:# write_allowed:flags.0?true bot:InputUser enabled:Bool = Bool;
messages.requestWebView#269dc2c1 flags:# from_bot_menu:flags.4?true silent:flags.5?true compact:flags.7?true fullscreen:flags.8?true peer:InputPeer bot:InputUser url:flags.1?string start_param:flags.3?string theme_params:flags.2?DataJSON platform:string reply_to:flags.0?InputReplyTo send_as:flags.13?InputPeer = WebViewResult;
messages.prolongWebView#b0d81a83 flags:# silent:flags.5?true peer:InputPeer bot:InputUser query_id:long reply_to:flags.0?InputReplyTo send_as:flags.13?InputPeer = Bool;
messages.requestSimpleWebView#413a3e73 flags:# from_switch_webview:flags.1?true from_side_menu:flags.2?true compact:flags.7?true fullscreen:flags.8?true bot:InputUser url:flags.3?string start_param:flags.4?string theme_params:flags.0?DataJSON platform:string = WebViewResult;
messages.sendWebViewResultMessage#a4314f5 bot_query_id:string result:InputBotInlineResult = WebViewMessageSent;
messages.sendWebViewData#dc0242c8 bot:InputUser random_id:long button_text:string data:string = Updates;
messages.transcribeAudio#269e9a49 peer:InputPeer msg_id:int = messages.TranscribedAudio;
messages.getCustomEmojiDocuments#d9ab0f54 document_id:Vector<long> = Vector<Document>;
messages.getEmojiStickers#fbfca18f hash:long = messages.AllStickers;
messages.getFeaturedEmojiStickers#ecf6736 hash:long = messages.FeaturedStickers;
messages.getTopReactions#bb8125ba limit:int hash:long = messages.Reactions;
messages.getRecentReactions#39461db2 limit:int hash:long = messages.Reactions;
messages.clearRecentReactions#9dfeefb4 = Bool;
messages.getExtendedMedia#84f80814 peer:InputPeer id:Vector<int> = Updates;
messages.togglePeerTranslations#e47cb579 flags:# disabled:flags.0?true peer:InputPeer = Bool;
messages.getBotApp#34fdc5c3 app:InputBotApp hash:long = messages.BotApp;
messages.requestAppWebView#53618bce flags:# write_allowed:flags.0?true compact:flags.7?true fullscreen:flags.8?true peer:InputPeer app:InputBotApp start_param:flags.1?string theme_params:flags.2?DataJSON platform:string = WebViewResult;
messages.getSavedDialogs#1e91fc99 flags:# exclude_pinned:flags.0?true parent_peer:flags.1?InputPeer offset_date:int offset_id:int offset_peer:InputPeer limit:int hash:long = messages.SavedDialogs;
messages.getSavedHistory#998ab009 flags:# parent_peer:flags.0?InputPeer peer:InputPeer offset_id:int offset_date:int add_offset:int limit:int max_id:int min_id:int hash:long = messages.Messages;
messages.deleteSavedHistory#4dc5085f flags:# parent_peer:flags.0?InputPeer peer:InputPeer max_id:int min_date:flags.2?int max_date:flags.3?int = messages.AffectedHistory;
messages.getPinnedSavedDialogs#d63d94e0 = messages.SavedDialogs;
messages.toggleSavedDialogPin#ac81bbde flags:# pinned:flags.0?true peer:InputDialogPeer = Bool;
messages.getSavedReactionTags#3637e05b flags:# peer:flags.0?InputPeer hash:long = messages.SavedReactionTags;
messages.updateSavedReactionTag#60297dec flags:# reaction:Reaction title:flags.0?string = Bool;
messages.getDefaultTagReactions#bdf93428 hash:long = messages.Reactions;
messages.getOutboxReadDate#8c4bfe5d peer:InputPeer msg_id:int = OutboxReadDate;
messages.getQuickReplies#d483f2a8 hash:long = messages.QuickReplies;
messages.getQuickReplyMessages#94a495c3 flags:# shortcut_id:int id:flags.0?Vector<int> hash:long = messages.Messages;
messages.sendQuickReplyMessages#6c750de1 peer:InputPeer shortcut_id:int id:Vector<int> random_id:Vector<long> = Updates;
messages.toggleDialogFilterTags#fd2dda49 enabled:Bool = Bool;
messages.getAvailableEffects#dea20a39 hash:int = messages.AvailableEffects;
messages.getFactCheck#b9cdc5ee peer:InputPeer msg_id:Vector<int> = Vector<FactCheck>;
messages.requestMainWebView#c9e01e7b flags:# compact:flags.7?true fullscreen:flags.8?true peer:InputPeer bot:InputUser start_param:flags.1?string theme_params:flags.0?DataJSON platform:string = WebViewResult;
messages.sendPaidReaction#58bbcb50 flags:# peer:InputPeer msg_id:int count:int random_id:long private:flags.0?PaidReactionPrivacy = Updates;
messages.getPaidReactionPrivacy#472455aa = Updates;
messages.viewSponsoredMessage#269e3643 random_id:bytes = Bool;
messages.clickSponsoredMessage#8235057e flags:# media:flags.0?true fullscreen:flags.1?true random_id:bytes = Bool;
messages.reportSponsoredMessage#12cbf0c4 random_id:bytes option:bytes = channels.SponsoredMessageReportResult;
messages.getSponsoredMessages#3d6ce850 flags:# peer:InputPeer msg_id:flags.0?int = messages.SponsoredMessages;
messages.getPreparedInlineMessage#857ebdb8 bot:InputUser id:string = messages.PreparedInlineMessage;
messages.reportMessagesDelivery#5a6d7395 flags:# push:flags.0?true peer:InputPeer id:Vector<int> = Bool;
messages.toggleTodoCompleted#d3e03124 peer:InputPeer msg_id:int completed:Vector<int> incompleted:Vector<int> = Updates;
messages.appendTodoList#21a61057 peer:InputPeer msg_id:int list:Vector<TodoItem> = Updates;
messages.toggleSuggestedPostApproval#8107455c flags:# reject:flags.1?true peer:InputPeer msg_id:int schedule_date:flags.0?int reject_comment:flags.2?string = Updates;
updates.getState#edd4882a = updates.State;
updates.getDifference#19c2f763 flags:# pts:int pts_limit:flags.1?int pts_total_limit:flags.0?int date:int qts:int qts_limit:flags.2?int = updates.Difference;
updates.getChannelDifference#3173d78 flags:# force:flags.0?true channel:InputChannel filter:ChannelMessagesFilter pts:int limit:int = updates.ChannelDifference;
photos.updateProfilePhoto#9e82039 flags:# fallback:flags.0?true bot:flags.1?InputUser id:InputPhoto = photos.Photo;
photos.uploadProfilePhoto#388a3b5 flags:# fallback:flags.3?true bot:flags.5?InputUser file:flags.0?InputFile video:flags.1?InputFile video_start_ts:flags.2?double video_emoji_markup:flags.4?VideoSize = photos.Photo;
photos.deletePhotos#87cf7f2f id:Vector<InputPhoto> = Vector<long>;
photos.getUserPhotos#91cd32a8 user_id:InputUser offset:int max_id:long limit:int = photos.Photos;
photos.uploadContactProfilePhoto#e14c4a71 flags:# suggest:flags.3?true save:flags.4?true user_id:InputUser file:flags.0?InputFile video:flags.1?InputFile video_start_ts:flags.2?double video_emoji_markup:flags.5?VideoSize = photos.Photo;
upload.saveFilePart#b304a621 file_id:long file_part:int bytes:bytes = Bool;
upload.getFile#be5335be flags:# precise:flags.0?true cdn_supported:flags.1?true location:InputFileLocation offset:long limit:int = upload.File;
upload.saveBigFilePart#de7b673d file_id:long file_part:int file_total_parts:int bytes:bytes = Bool;
upload.getWebFile#24e6818d location:InputWebFileLocation offset:int limit:int = upload.WebFile;
help.getConfig#c4f9186b = Config;
help.getNearestDc#1fb33026 = NearestDc;
help.getSupport#9cdf08cd = help.Support;
help.acceptTermsOfService#ee72f79a id:DataJSON = Bool;
help.getAppConfig#61e3f854 hash:int = help.AppConfig;
help.getCountriesList#735787a8 lang_code:string hash:int = help.CountriesList;
help.getPremiumPromo#b81b93d4 = help.PremiumPromo;
help.getPeerColors#da80f42f hash:int = help.PeerColors;
help.getTimezonesList#49b30240 hash:int = help.TimezonesList;
channels.readHistory#cc104937 channel:InputChannel max_id:int = Bool;
channels.deleteMessages#84c1fd4e channel:InputChannel id:Vector<int> = messages.AffectedMessages;
channels.reportSpam#f44a8315 channel:InputChannel participant:InputPeer id:Vector<int> = Bool;
channels.getMessages#ad8c9a23 channel:InputChannel id:Vector<InputMessage> = messages.Messages;
channels.getParticipants#77ced9d0 channel:InputChannel filter:ChannelParticipantsFilter offset:int limit:int hash:long = channels.ChannelParticipants;
channels.getParticipant#a0ab6cc6 channel:InputChannel participant:InputPeer = channels.ChannelParticipant;
channels.getChannels#a7f6bbb id:Vector<InputChannel> = messages.Chats;
channels.getFullChannel#8736a09 channel:InputChannel = messages.ChatFull;
channels.createChannel#91006707 flags:# broadcast:flags.0?true megagroup:flags.1?true for_import:flags.3?true forum:flags.5?true title:string about:string geo_point:flags.2?InputGeoPoint address:flags.2?string ttl_period:flags.4?int = Updates;
channels.editAdmin#d33c8902 channel:InputChannel user_id:InputUser admin_rights:ChatAdminRights rank:string = Updates;
channels.editTitle#566decd0 channel:InputChannel title:string = Updates;
channels.editPhoto#f12e57c9 channel:InputChannel photo:InputChatPhoto = Updates;
channels.checkUsername#10e6bd2c channel:InputChannel username:string = Bool;
channels.updateUsername#3514b3de channel:InputChannel username:string = Bool;
channels.joinChannel#24b524c5 channel:InputChannel = Updates;
channels.leaveChannel#f836aa95 channel:InputChannel = Updates;
channels.inviteToChannel#c9e33d54 channel:InputChannel users:Vector<InputUser> = messages.InvitedUsers;
channels.deleteChannel#c0111fe3 channel:InputChannel = Updates;
channels.exportMessageLink#e63fadeb flags:# grouped:flags.0?true thread:flags.1?true channel:InputChannel id:int = ExportedMessageLink;
channels.toggleSignatures#418d549c flags:# signatures_enabled:flags.0?true profiles_enabled:flags.1?true channel:InputChannel = Updates;
channels.editBanned#96e6cd81 channel:InputChannel participant:InputPeer banned_rights:ChatBannedRights = Updates;
channels.readMessageContents#eab5dc38 channel:InputChannel id:Vector<int> = Bool;
channels.togglePreHistoryHidden#eabbb94c channel:InputChannel enabled:Bool = Updates;
channels.getGroupsForDiscussion#f5dad378 = messages.Chats;
channels.setDiscussionGroup#40582bb2 broadcast:InputChannel group:InputChannel = Bool;
channels.getSendAs#e785a43f flags:# for_paid_reactions:flags.0?true peer:InputPeer = channels.SendAsPeers;
channels.deleteParticipantHistory#367544db channel:InputChannel participant:InputPeer = messages.AffectedHistory;
channels.toggleJoinToSend#e4cb9580 channel:InputChannel enabled:Bool = Updates;
channels.toggleJoinRequest#4c2985b6 channel:InputChannel enabled:Bool = Updates;
channels.reorderUsernames#b45ced1d channel:InputChannel order:Vector<string> = Bool;
channels.toggleUsername#50f24105 channel:InputChannel username:string active:Bool = Bool;
channels.deactivateAllUsernames#a245dd3 channel:InputChannel = Bool;
channels.toggleForum#3ff75734 channel:InputChannel enabled:Bool tabs:Bool = Updates;
channels.createForumTopic#f40c0224 flags:# channel:InputChannel title:string icon_color:flags.0?int icon_emoji_id:flags.3?long random_id:long send_as:flags.2?InputPeer = Updates;
channels.getForumTopics#de560d1 flags:# channel:InputChannel q:flags.0?string offset_date:int offset_id:int offset_topic:int limit:int = messages.ForumTopics;
channels.getForumTopicsByID#b0831eb9 channel:InputChannel topics:Vector<int> = messages.ForumTopics;
channels.editForumTopic#f4dfa185 flags:# channel:InputChannel topic_id:int title:flags.0?string icon_emoji_id:flags.1?long closed:flags.2?Bool hidden:flags.3?Bool = Updates;
channels.updatePinnedForumTopic#6c2d9026 channel:InputChannel topic_id:int pinned:Bool = Updates;
channels.deleteTopicHistory#34435f2d channel:InputChannel top_msg_id:int = messages.AffectedHistory;
channels.toggleParticipantsHidden#6a6e7854 channel:InputChannel enabled:Bool = Updates;
channels.toggleViewForumAsMessages#9738bb15 channel:InputChannel enabled:Bool = Updates;
channels.getChannelRecommendations#25a71742 flags:# channel:flags.0?InputChannel = messages.Chats;
channels.searchPosts#f2c4f24d flags:# hashtag:flags.0?string query:flags.1?string offset_rate:int offset_peer:InputPeer offset_id:int limit:int allow_paid_stars:flags.2?long = messages.Messages;
channels.updatePaidMessagesPrice#4b12327b flags:# broadcast_messages_allowed:flags.0?true channel:InputChannel send_paid_messages_stars:long = Updates;
channels.toggleAutotranslation#167fc0a1 channel:InputChannel enabled:Bool = Updates;
channels.checkSearchPostsFlood#22567115 flags:# query:flags.0?string = SearchPostsFlood;
bots.setBotInfo#10cf3123 flags:# bot:flags.2?InputUser lang_code:string name:flags.3?string about:flags.0?string description:flags.1?string = Bool;
bots.canSendMessage#1359f4e6 bot:InputUser = Bool;
bots.allowSendMessage#f132e3ef bot:InputUser = Updates;
bots.invokeWebViewCustomMethod#87fc5e7 bot:InputUser custom_method:string params:DataJSON = DataJSON;
bots.getPopularAppBots#c2510192 offset:string limit:int = bots.PopularAppBots;
bots.getPreviewMedias#a2a5594d bot:InputUser = Vector<BotPreviewMedia>;
bots.toggleUserEmojiStatusPermission#6de6392 bot:InputUser enabled:Bool = Bool;
bots.checkDownloadFileParams#50077589 bot:InputUser file_name:string url:string = Bool;
bots.getBotRecommendations#a1b70815 bot:InputUser = users.Users;
payments.getPaymentForm#37148dbb flags:# invoice:InputInvoice theme_params:flags.0?DataJSON = payments.PaymentForm;
payments.getPaymentReceipt#2478d1cc peer:InputPeer msg_id:int = payments.PaymentReceipt;
payments.validateRequestedInfo#b6c8f12b flags:# save:flags.0?true invoice:InputInvoice info:PaymentRequestedInfo = payments.ValidatedRequestedInfo;
payments.sendPaymentForm#2d03522f flags:# form_id:long invoice:InputInvoice requested_info_id:flags.0?string shipping_option_id:flags.1?string credentials:InputPaymentCredentials tip_amount:flags.2?long = payments.PaymentResult;
payments.getSavedInfo#227d824b = payments.SavedInfo;
payments.getPremiumGiftCodeOptions#2757ba54 flags:# boost_peer:flags.0?InputPeer = Vector<PremiumGiftCodeOption>;
payments.checkGiftCode#8e51b4c1 slug:string = payments.CheckedGiftCode;
payments.applyGiftCode#f6e26854 slug:string = Updates;
payments.getGiveawayInfo#f4239425 peer:InputPeer msg_id:int = payments.GiveawayInfo;
payments.launchPrepaidGiveaway#5ff58f20 peer:InputPeer giveaway_id:long purpose:InputStorePaymentPurpose = Updates;
payments.getStarsTopupOptions#c00ec7d3 = Vector<StarsTopupOption>;
payments.getStarsStatus#4ea9b3bf flags:# ton:flags.0?true peer:InputPeer = payments.StarsStatus;
payments.getStarsTransactions#69da4557 flags:# inbound:flags.0?true outbound:flags.1?true ascending:flags.2?true ton:flags.4?true subscription_id:flags.3?string peer:InputPeer offset:string limit:int = payments.StarsStatus;
payments.sendStarsForm#7998c914 form_id:long invoice:InputInvoice = payments.PaymentResult;
payments.refundStarsCharge#25ae8f4a user_id:InputUser charge_id:string = Updates;
payments.getStarsTransactionsByID#2dca16b8 flags:# ton:flags.0?true peer:InputPeer id:Vector<InputStarsTransaction> = payments.StarsStatus;
payments.getStarsGiftOptions#d3c96bc8 flags:# user_id:flags.0?InputUser = Vector<StarsGiftOption>;
payments.getStarsSubscriptions#32512c5 flags:# missing_balance:flags.0?true peer:InputPeer offset:string = payments.StarsStatus;
payments.changeStarsSubscription#c7770878 flags:# peer:InputPeer subscription_id:string canceled:flags.0?Bool = Bool;
payments.fulfillStarsSubscription#cc5bebb3 peer:InputPeer subscription_id:string = Bool;
payments.getStarsGiveawayOptions#bd1efd3e = Vector<StarsGiveawayOption>;
payments.getStarGifts#c4563590 hash:int = payments.StarGifts;
payments.saveStarGift#2a2a697c flags:# unsave:flags.0?true stargift:InputSavedStarGift = Bool;
payments.convertStarGift#74bf076b stargift:InputSavedStarGift = Bool;
payments.getStarGiftUpgradePreview#9c9abcb1 gift_id:long = payments.StarGiftUpgradePreview;
payments.upgradeStarGift#aed6e4f5 flags:# keep_original_details:flags.0?true stargift:InputSavedStarGift = Updates;
payments.transferStarGift#7f18176a stargift:InputSavedStarGift to_id:InputPeer = Updates;
payments.getUniqueStarGift#a1974d72 slug:string = payments.UniqueStarGift;
payments.getSavedStarGifts#a319e569 flags:# exclude_unsaved:flags.0?true exclude_saved:flags.1?true exclude_unlimited:flags.2?true exclude_unique:flags.4?true sort_by_value:flags.5?true exclude_upgradable:flags.7?true exclude_unupgradable:flags.8?true peer:InputPeer collection_id:flags.6?int offset:string limit:int = payments.SavedStarGifts;
payments.getStarGiftWithdrawalUrl#d06e93a8 stargift:InputSavedStarGift password:InputCheckPasswordSRP = payments.StarGiftWithdrawalUrl;
payments.toggleStarGiftsPinnedToTop#1513e7b0 peer:InputPeer stargift:Vector<InputSavedStarGift> = Bool;
payments.getResaleStarGifts#7a5fa236 flags:# sort_by_price:flags.1?true sort_by_num:flags.2?true attributes_hash:flags.0?long gift_id:long attributes:flags.3?Vector<StarGiftAttributeId> offset:string limit:int = payments.ResaleStarGifts;
payments.updateStarGiftPrice#edbe6ccb stargift:InputSavedStarGift resell_amount:StarsAmount = Updates;
payments.getUniqueStarGiftValueInfo#4365af6b slug:string = payments.UniqueStarGiftValueInfo;
payments.getStarGiftCollections#981b91dd peer:InputPeer hash:long = payments.StarGiftCollections;
phone.requestCall#42ff96ed flags:# video:flags.0?true user_id:InputUser random_id:int g_a_hash:bytes protocol:PhoneCallProtocol = phone.PhoneCall;
phone.acceptCall#3bd2b4a0 peer:InputPhoneCall g_b:bytes protocol:PhoneCallProtocol = phone.PhoneCall;
phone.confirmCall#2efe1722 peer:InputPhoneCall g_a:bytes key_fingerprint:long protocol:PhoneCallProtocol = phone.PhoneCall;
phone.receivedCall#17d54f61 peer:InputPhoneCall = Bool;
phone.discardCall#b2cbc1c0 flags:# video:flags.0?true peer:InputPhoneCall duration:int reason:PhoneCallDiscardReason connection_id:long = Updates;
phone.setCallRating#59ead627 flags:# user_initiative:flags.0?true peer:InputPhoneCall rating:int comment:string = Updates;
phone.saveCallDebug#277add7e peer:InputPhoneCall debug:DataJSON = Bool;
phone.sendSignalingData#ff7a9383 peer:InputPhoneCall data:bytes = Bool;
phone.createGroupCall#48cdc6d8 flags:# rtmp_stream:flags.2?true peer:InputPeer random_id:int title:flags.0?string schedule_date:flags.1?int = Updates;
phone.joinGroupCall#8fb53057 flags:# muted:flags.0?true video_stopped:flags.2?true call:InputGroupCall join_as:InputPeer invite_hash:flags.1?string public_key:flags.3?int256 block:flags.3?bytes params:DataJSON = Updates;
phone.leaveGroupCall#500377f9 call:InputGroupCall source:int = Updates;
phone.discardGroupCall#7a777135 call:InputGroupCall = Updates;
phone.getGroupCall#41845db call:InputGroupCall limit:int = phone.GroupCall;
phone.getGroupParticipants#c558d8ab call:InputGroupCall ids:Vector<InputPeer> sources:Vector<int> offset:string limit:int = phone.GroupParticipants;
phone.editGroupCallParticipant#a5273abf flags:# call:InputGroupCall participant:InputPeer muted:flags.0?Bool volume:flags.1?int raise_hand:flags.2?Bool video_stopped:flags.3?Bool video_paused:flags.4?Bool presentation_paused:flags.5?Bool = Updates;
phone.exportGroupCallInvite#e6aa647f flags:# can_self_unmute:flags.0?true call:InputGroupCall = phone.ExportedGroupCallInvite;
phone.toggleGroupCallStartSubscription#219c34e6 call:InputGroupCall subscribed:Bool = Updates;
phone.joinGroupCallPresentation#cbea6bc4 call:InputGroupCall params:DataJSON = Updates;
phone.leaveGroupCallPresentation#1c50d144 call:InputGroupCall = Updates;
langpack.getLangPack#f2f2330a lang_pack:string lang_code:string = LangPackDifference;
langpack.getStrings#efea3803 lang_pack:string lang_code:string keys:Vector<string> = Vector<LangPackString>;
langpack.getDifference#cd984aa5 lang_pack:string lang_code:string from_version:int = LangPackDifference;
langpack.getLanguages#42c6978f lang_pack:string = Vector<LangPackLanguage>;
langpack.getLanguage#6a596502 lang_pack:string lang_code:string = LangPackLanguage;
folders.editPeerFolders#6847d0ab folder_peers:Vector<InputFolderPeer> = Updates;
stats.getBroadcastStats#ab42441a flags:# dark:flags.0?true channel:InputChannel = stats.BroadcastStats;
stats.loadAsyncGraph#621d5fa0 flags:# token:string x:flags.0?long = StatsGraph;
stats.getMegagroupStats#dcdf8607 flags:# dark:flags.0?true channel:InputChannel = stats.MegagroupStats;
stats.getMessagePublicForwards#5f150144 channel:InputChannel msg_id:int offset:string limit:int = stats.PublicForwards;
stats.getMessageStats#b6e0a3f5 flags:# dark:flags.0?true channel:InputChannel msg_id:int = stats.MessageStats;
stats.getStoryStats#374fef40 flags:# dark:flags.0?true peer:InputPeer id:int = stats.StoryStats;
stats.getStoryPublicForwards#a6437ef6 peer:InputPeer id:int offset:string limit:int = stats.PublicForwards;
chatlists.exportChatlistInvite#8472478e chatlist:InputChatlist title:string peers:Vector<InputPeer> = chatlists.ExportedChatlistInvite;
chatlists.deleteExportedInvite#719c5c5e chatlist:InputChatlist slug:string = Bool;
chatlists.editExportedInvite#653db63d flags:# chatlist:InputChatlist slug:string title:flags.1?string peers:flags.2?Vector<InputPeer> = ExportedChatlistInvite;
chatlists.getExportedInvites#ce03da83 chatlist:InputChatlist = chatlists.ExportedInvites;
chatlists.checkChatlistInvite#41c10fff slug:string = chatlists.ChatlistInvite;
chatlists.joinChatlistInvite#a6b1e39a slug:string peers:Vector<InputPeer> = Updates;
chatlists.getLeaveChatlistSuggestions#fdbcd714 chatlist:InputChatlist = Vector<Peer>;
chatlists.leaveChatlist#74fae13a chatlist:InputChatlist peers:Vector<InputPeer> = Updates;
stories.editStory#b583ba46 flags:# peer:InputPeer id:int media:flags.0?InputMedia media_areas:flags.3?Vector<MediaArea> caption:flags.1?string entities:flags.1?Vector<MessageEntity> privacy_rules:flags.2?Vector<InputPrivacyRule> = Updates;
stories.deleteStories#ae59db5f peer:InputPeer id:Vector<int> = Vector<int>;
stories.togglePinned#9a75a1ef peer:InputPeer id:Vector<int> pinned:Bool = Vector<int>;
stories.getAllStories#eeb0d625 flags:# next:flags.1?true hidden:flags.2?true state:flags.0?string = stories.AllStories;
stories.getPinnedStories#5821a5dc peer:InputPeer offset_id:int limit:int = stories.Stories;
stories.getStoriesArchive#b4352016 peer:InputPeer offset_id:int limit:int = stories.Stories;
stories.getStoriesByID#5774ca74 peer:InputPeer id:Vector<int> = stories.Stories;
stories.readStories#a556dac8 peer:InputPeer max_id:int = Vector<int>;
stories.incrementStoryViews#b2028afb peer:InputPeer id:Vector<int> = Bool;
stories.getStoryViewsList#7ed23c57 flags:# just_contacts:flags.0?true reactions_first:flags.2?true forwards_first:flags.3?true peer:InputPeer q:flags.1?string id:int offset:string limit:int = stories.StoryViewsList;
stories.getStoriesViews#28e16cc8 peer:InputPeer id:Vector<int> = stories.StoryViews;
stories.exportStoryLink#7b8def20 peer:InputPeer id:int = ExportedStoryLink;
stories.report#19d8eb45 peer:InputPeer id:Vector<int> option:bytes message:string = ReportResult;
stories.activateStealthMode#57bbd166 flags:# past:flags.0?true future:flags.1?true = Updates;
stories.sendReaction#7fd736b2 flags:# add_to_recent:flags.0?true peer:InputPeer story_id:int reaction:Reaction = Updates;
stories.getPeerStories#2c4ada50 peer:InputPeer = stories.PeerStories;
stories.getPeerMaxIDs#535983c3 id:Vector<InputPeer> = Vector<int>;
stories.togglePeerStoriesHidden#bd0415c4 peer:InputPeer hidden:Bool = Bool;
stories.togglePinnedToTop#b297e9b peer:InputPeer id:Vector<int> = Bool;
stories.getAlbums#25b3eac7 peer:InputPeer hash:long = stories.Albums;
stories.getAlbumStories#ac806d61 peer:InputPeer album_id:int offset:int limit:int = stories.Stories;
premium.getBoostsList#60f67660 flags:# gifts:flags.0?true peer:InputPeer offset:string limit:int = premium.BoostsList;
premium.getMyBoosts#be77b4a = premium.MyBoosts;
premium.applyBoost#6b7da746 flags:# slots:flags.0?Vector<int> peer:InputPeer = premium.MyBoosts;
premium.getBoostsStatus#42f1f61 peer:InputPeer = premium.BoostsStatus;
fragment.getCollectibleInfo#be1e85ba collectible:InputCollectible = fragment.CollectibleInfo;`);

/***/ }),

/***/ "./src/lib/gramjs/tl/core/GZIPPacked.ts":
/*!**********************************************!*\
  !*** ./src/lib/gramjs/tl/core/GZIPPacked.ts ***!
  \**********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ GZIPPacked)
/* harmony export */ });
/* harmony import */ var pako_dist_pako_inflate__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! pako/dist/pako_inflate */ "./node_modules/pako/dist/pako_inflate.js");
/* harmony import */ var pako_dist_pako_inflate__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(pako_dist_pako_inflate__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var ___WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! .. */ "./src/lib/gramjs/tl/index.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];


class GZIPPacked {
  static CONSTRUCTOR_ID = 0x3072cfa1;
  static classType = 'constructor';
  constructor(data) {
    this.data = data;
    this.CONSTRUCTOR_ID = 0x3072cfa1;
    this.classType = 'constructor';
  }
  static async gzipIfSmaller(contentRelated, data) {
    if (contentRelated && data.length > 512) {
      const gzipped = await new GZIPPacked(data).toBytes();
      if (gzipped.length < data.length) {
        return gzipped;
      }
    }
    return data;
  }
  static gzip(input) {
    return Buffer.from(input);
    // TODO this usually makes it faster for large requests
    // return Buffer.from(deflate(input, { level: 9, gzip: true }))
  }
  static ungzip(input) {
    return Buffer.from((0,pako_dist_pako_inflate__WEBPACK_IMPORTED_MODULE_0__.inflate)(input));
  }
  async toBytes() {
    const g = Buffer.alloc(4);
    g.writeUInt32LE(GZIPPacked.CONSTRUCTOR_ID, 0);
    return Buffer.concat([g, (0,___WEBPACK_IMPORTED_MODULE_1__.serializeBytes)(await GZIPPacked.gzip(this.data))]);
  }
  static read(reader) {
    const constructor = reader.readInt(false);
    if (constructor !== GZIPPacked.CONSTRUCTOR_ID) {
      throw new Error('not equal');
    }
    return GZIPPacked.gzip(reader.tgReadBytes());
  }
  static async fromReader(reader) {
    const data = reader.tgReadBytes();
    return new GZIPPacked(await GZIPPacked.ungzip(data));
  }
}

/***/ }),

/***/ "./src/lib/gramjs/tl/core/MessageContainer.ts":
/*!****************************************************!*\
  !*** ./src/lib/gramjs/tl/core/MessageContainer.ts ***!
  \****************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ MessageContainer)
/* harmony export */ });
/* harmony import */ var _TLMessage__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./TLMessage */ "./src/lib/gramjs/tl/core/TLMessage.ts");

class MessageContainer {
  static CONSTRUCTOR_ID = 0x73f1f8dc;
  static classType = 'constructor';

  // Maximum size in bytes for the inner payload of the container.
  // Telegram will close the connection if the payload is bigger.
  // The overhead of the container itself is subtracted.
  static MAXIMUM_SIZE = 1044456 - 8;

  // Maximum amount of messages that can't be sent inside a single
  // container, inclusive. Beyond this limit Telegram will respond
  // with BAD_MESSAGE 64 (invalid container).
  //
  // This limit is not 100% accurate and may in some cases be higher.
  // However, sending up to 100 requests at once in a single container
  // is a reasonable conservative value, since it could also depend on
  // other factors like size per request, but we cannot know this.
  static MAXIMUM_LENGTH = 100;
  constructor(messages) {
    this.CONSTRUCTOR_ID = 0x73f1f8dc;
    this.messages = messages;
    this.classType = 'constructor';
  }
  static fromReader(reader) {
    const messages = [];
    const totalLength = reader.readInt();
    for (let x = 0; x < totalLength; x++) {
      const msgId = reader.readLong();
      const seqNo = reader.readInt();
      const length = reader.readInt();
      const before = reader.tellPosition();
      const obj = reader.tgReadObject();
      reader.setPosition(before + length);
      const tlMessage = new _TLMessage__WEBPACK_IMPORTED_MODULE_0__["default"](msgId, seqNo, obj);
      messages.push(tlMessage);
    }
    return new MessageContainer(messages);
  }
}

/***/ }),

/***/ "./src/lib/gramjs/tl/core/RPCResult.ts":
/*!*********************************************!*\
  !*** ./src/lib/gramjs/tl/core/RPCResult.ts ***!
  \*********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ RPCResult)
/* harmony export */ });
/* harmony import */ var _api__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../api */ "./src/lib/gramjs/tl/api.js");
/* harmony import */ var _GZIPPacked__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./GZIPPacked */ "./src/lib/gramjs/tl/core/GZIPPacked.ts");


class RPCResult {
  static CONSTRUCTOR_ID = 0xf35c6d01;
  static classType = 'constructor';
  constructor(reqMsgId, body, error) {
    this.CONSTRUCTOR_ID = 0xf35c6d01;
    this.reqMsgId = reqMsgId;
    this.body = body;
    this.error = error;
    this.classType = 'constructor';
  }
  static async fromReader(reader) {
    const msgId = reader.readLong();
    const innerCode = reader.readInt(false);
    if (innerCode === _api__WEBPACK_IMPORTED_MODULE_0__["default"].RpcError.CONSTRUCTOR_ID) {
      return new RPCResult(msgId, undefined, _api__WEBPACK_IMPORTED_MODULE_0__["default"].RpcError.fromReader(reader));
    }
    if (innerCode === _GZIPPacked__WEBPACK_IMPORTED_MODULE_1__["default"].CONSTRUCTOR_ID) {
      return new RPCResult(msgId, (await _GZIPPacked__WEBPACK_IMPORTED_MODULE_1__["default"].fromReader(reader)).data);
    }
    reader.seek(-4);
    // This reader.read() will read more than necessary, but it's okay.
    // We could make use of MessageContainer's length here, but since
    // it's not necessary we don't need to care about it.
    return new RPCResult(msgId, reader.read(), undefined);
  }
}

/***/ }),

/***/ "./src/lib/gramjs/tl/core/TLMessage.ts":
/*!*********************************************!*\
  !*** ./src/lib/gramjs/tl/core/TLMessage.ts ***!
  \*********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ TLMessage)
/* harmony export */ });
class TLMessage {
  static SIZE_OVERHEAD = 12;
  static classType = 'constructor';
  constructor(msgId, seqNo, obj) {
    this.msgId = msgId;
    this.seqNo = seqNo;
    this.obj = obj;
  }
}

/***/ }),

/***/ "./src/lib/gramjs/tl/core/index.ts":
/*!*****************************************!*\
  !*** ./src/lib/gramjs/tl/core/index.ts ***!
  \*****************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   GZIPPacked: () => (/* reexport safe */ _GZIPPacked__WEBPACK_IMPORTED_MODULE_0__["default"]),
/* harmony export */   MessageContainer: () => (/* reexport safe */ _MessageContainer__WEBPACK_IMPORTED_MODULE_1__["default"]),
/* harmony export */   RPCResult: () => (/* reexport safe */ _RPCResult__WEBPACK_IMPORTED_MODULE_2__["default"]),
/* harmony export */   TLMessage: () => (/* reexport safe */ _TLMessage__WEBPACK_IMPORTED_MODULE_3__["default"]),
/* harmony export */   coreObjects: () => (/* binding */ coreObjects)
/* harmony export */ });
/* harmony import */ var _GZIPPacked__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./GZIPPacked */ "./src/lib/gramjs/tl/core/GZIPPacked.ts");
/* harmony import */ var _MessageContainer__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./MessageContainer */ "./src/lib/gramjs/tl/core/MessageContainer.ts");
/* harmony import */ var _RPCResult__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./RPCResult */ "./src/lib/gramjs/tl/core/RPCResult.ts");
/* harmony import */ var _TLMessage__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./TLMessage */ "./src/lib/gramjs/tl/core/TLMessage.ts");




const coreObjects = new Map([[_RPCResult__WEBPACK_IMPORTED_MODULE_2__["default"].CONSTRUCTOR_ID, _RPCResult__WEBPACK_IMPORTED_MODULE_2__["default"]], [_GZIPPacked__WEBPACK_IMPORTED_MODULE_0__["default"].CONSTRUCTOR_ID, _GZIPPacked__WEBPACK_IMPORTED_MODULE_0__["default"]], [_MessageContainer__WEBPACK_IMPORTED_MODULE_1__["default"].CONSTRUCTOR_ID, _MessageContainer__WEBPACK_IMPORTED_MODULE_1__["default"]]]);


/***/ }),

/***/ "./src/lib/gramjs/tl/generationHelpers.ts":
/*!************************************************!*\
  !*** ./src/lib/gramjs/tl/generationHelpers.ts ***!
  \************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   parseTl: () => (/* binding */ parseTl),
/* harmony export */   serializeBytes: () => (/* binding */ serializeBytes),
/* harmony export */   serializeDate: () => (/* binding */ serializeDate)
/* harmony export */ });
/* harmony import */ var _Helpers__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../Helpers */ "./src/lib/gramjs/Helpers.ts");
/* provided dependency */ var Buffer = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js")["Buffer"];

const snakeToCamelCase = name => {
  const result = name.replace(/(?:^|_)([a-z])/g, (_, g) => g.toUpperCase());
  return result.replace(/_/g, '');
};
const variableSnakeToCamelCase = str => str.replace(/([-_][a-z])/g, group => group.toUpperCase().replace('-', '').replace('_', ''));
const CORE_TYPES = new Set([0xbc799737,
// boolFalse#bc799737 = Bool;
0x997275b5,
// boolTrue#997275b5 = Bool;
0x3fedd339,
// true#3fedd339 = True;
0xc4b9f9bb,
// error#c4b9f9bb code:int text:string = Error;
0x56730bcc // null#56730bcc = Null;
]);
const AUTH_KEY_TYPES = new Set([0x05162463,
// resPQ,
0x83c95aec,
// p_q_inner_data
0xa9f55f95,
// p_q_inner_data_dc
0x3c6a84d4,
// p_q_inner_data_temp
0x56fddf88,
// p_q_inner_data_temp_dc
0xd0e8075c,
// server_DH_params_ok
0xb5890dba,
// server_DH_inner_data
0x6643b654,
// client_DH_inner_data
0xd712e4be,
// req_DH_params
0xf5045f1f,
// set_client_DH_params
0x3072cfa1 // gzip_packed
]);
const findAll = (regex, str, matches = []) => {
  if (!regex.flags.includes('g')) {
    regex = new RegExp(regex.source, 'g');
  }
  const res = regex.exec(str);
  if (res) {
    matches.push(res.slice(1));
    findAll(regex, str, matches);
  }
  return matches;
};
const fromLine = (line, isFunction) => {
  const match = line.match(/([\w.]+)(?:#([0-9a-fA-F]+))?(?:\s{?\w+:[\w\d<>#.?!]+}?)*\s=\s([\w\d<>#.?]+);$/);
  if (!match) {
    // Probably "vector#1cb5c415 {t:Type} # [ t ] = Vector t;"
    throw new Error(`Cannot parse TLObject ${line}`);
  }
  const argsMatch = findAll(/({)?(\w+):([\w\d<>#.?!]+)}?/, line);
  const currentConfig = {
    name: match[1],
    constructorId: parseInt(match[2], 16),
    argsConfig: {},
    subclassOfId: (0,_Helpers__WEBPACK_IMPORTED_MODULE_0__.crc32)(match[3]),
    result: match[3],
    isFunction,
    namespace: undefined
  };
  if (!currentConfig.constructorId) {
    const hexId = '';
    let args;
    if (Object.values(currentConfig.argsConfig).length) {
      args = ` ${Object.keys(currentConfig.argsConfig).map(arg => arg.toString()).join(' ')}`;
    } else {
      args = '';
    }
    const representation = `${currentConfig.name}${hexId}${args} = ${currentConfig.result}`.replace(/(:|\?)bytes /g, '$1string ').replace(/</g, ' ').replace(/>|{|}/g, '').replace(/ \w+:flags\d*\.\d+\?true/g, '');
    if (currentConfig.name === 'inputMediaInvoice') {
      // eslint-disable-next-line no-empty
      if (currentConfig.name === 'inputMediaInvoice') {}
    }
    currentConfig.constructorId = (0,_Helpers__WEBPACK_IMPORTED_MODULE_0__.crc32)(Buffer.from(representation, 'utf8'));
  }
  for (const [brace, name, argType] of argsMatch) {
    if (brace === undefined) {
      currentConfig.argsConfig[variableSnakeToCamelCase(name)] = buildArgConfig(name, argType);
    }
  }
  if (currentConfig.name.includes('.')) {
    [currentConfig.namespace, currentConfig.name] = currentConfig.name.split(/\.(.+)/);
  }
  currentConfig.name = snakeToCamelCase(currentConfig.name);
  /*
  for (const arg in currentConfig.argsConfig){
    if (currentConfig.argsConfig.hasOwnProperty(arg)){
      if (currentConfig.argsConfig[arg].flagIndicator){
        delete  currentConfig.argsConfig[arg]
      }
    }
  } */
  return currentConfig;
};
function buildArgConfig(name, argType) {
  name = name === 'self' ? 'is_self' : name;
  // Default values
  const currentConfig = {
    isVector: false,
    isFlag: false,
    skipConstructorId: false,
    flagGroup: 0,
    flagIndex: -1,
    flagIndicator: true,
    type: '',
    useVectorId: undefined
  };

  // The type can be an indicator that other arguments will be flags
  if (argType !== '#') {
    currentConfig.flagIndicator = false;
    // Strip the exclamation mark always to have only the name
    currentConfig.type = argType.replace(/^!+/, '');

    // The type may be a flag (flags[N].IDX?REAL_TYPE)
    // Note that 'flags' is NOT the flags name; this
    // is determined by a previous argument
    // However, we assume that the argument will always be called 'flags[N]'
    const flagMatch = currentConfig.type.match(/flags(\d*)\.(\d+)\?([\w<>.]+)/);
    if (flagMatch) {
      currentConfig.isFlag = true;
      currentConfig.flagGroup = Number(flagMatch[1] || 1);
      currentConfig.flagIndex = Number(flagMatch[2]);
      // Update the type to match the exact type, not the "flagged" one
      [,,, currentConfig.type] = flagMatch;
    }

    // Then check if the type is a Vector<REAL_TYPE>
    const vectorMatch = currentConfig.type.match(/[Vv]ector<([\w\d.]+)>/);
    if (vectorMatch) {
      currentConfig.isVector = true;

      // If the type's first letter is not uppercase, then
      // it is a constructor and we use (read/write) its ID.
      currentConfig.useVectorId = currentConfig.type.charAt(0) === 'V';

      // Update the type to match the one inside the vector
      [, currentConfig.type] = vectorMatch;
    }

    // See use_vector_id. An example of such case is ipPort in
    // help.configSpecial
    if (/^[a-z]$/.test(currentConfig.type.split('.').pop().charAt(0))) {
      currentConfig.skipConstructorId = true;
    }

    // The name may contain "date" in it, if this is the case and
    // the type is "int", we can safely assume that this should be
    // treated as a "date" object. Note that this is not a valid
    // Telegram object, but it's easier to work with
    // if (
    //     this.type === 'int' &&
    //     (/(\b|_)([dr]ate|until|since)(\b|_)/.test(name) ||
    //         ['expires', 'expires_at', 'was_online'].includes(name))
    // ) {
    //     this.type = 'date';
    // }
  }
  return currentConfig;
}
function* parseTl(content, methods = [], ignoreIds = CORE_TYPES) {
  (methods || []).reduce((o, m) => ({
    ...o,
    [m.name]: m
  }), {});
  const objAll = [];
  const objByName = {};
  const objByType = {};
  const file = content;
  let isFunction = false;
  for (let line of file.split('\n')) {
    const commentIndex = line.indexOf('//');
    if (commentIndex !== -1) {
      line = line.slice(0, commentIndex);
    }
    line = line.trim();
    if (!line) {
      continue;
    }
    const match = line.match(/---(\w+)---/);
    if (match) {
      const [, followingTypes] = match;
      isFunction = followingTypes === 'functions';
      continue;
    }
    try {
      const result = fromLine(line, isFunction);
      if (ignoreIds.has(result.constructorId)) {
        continue;
      }
      objAll.push(result);
      if (!result.isFunction) {
        if (!objByType[result.result]) {
          objByType[result.result] = [];
        }
        objByName[result.name] = result;
        objByType[result.result].push(result);
      }
    } catch (e) {
      if (!e.toString().includes('vector#1cb5c415')) {
        throw e;
      }
    }
  }

  // Once all objects have been parsed, replace the
  // string type from the arguments with references
  for (const obj of objAll) {
    // console.log(obj)
    if (AUTH_KEY_TYPES.has(obj.constructorId)) {
      for (const arg in obj.argsConfig) {
        if (obj.argsConfig[arg].type === 'string') {
          obj.argsConfig[arg].type = 'bytes';
        }
      }
    }
  }
  for (const obj of objAll) {
    yield obj;
  }
}
function serializeBytes(data) {
  if (!(data instanceof Buffer)) {
    if (typeof data === 'string') {
      data = Buffer.from(data);
    } else {
      throw Error(`Bytes or str expected, not ${data.constructor.name}`);
    }
  }
  const r = [];
  let padding;
  if (data.length < 254) {
    padding = (data.length + 1) % 4;
    if (padding !== 0) {
      padding = 4 - padding;
    }
    r.push(Buffer.from([data.length]));
    r.push(data);
  } else {
    padding = data.length % 4;
    if (padding !== 0) {
      padding = 4 - padding;
    }
    r.push(Buffer.from([254, data.length % 256, (data.length >> 8) % 256, (data.length >> 16) % 256]));
    r.push(data);
  }
  r.push(Buffer.alloc(padding).fill(0));
  return Buffer.concat(r);
}
function serializeDate(dt) {
  if (!dt) {
    return Buffer.alloc(4).fill(0);
  }
  if (dt instanceof Date) {
    dt = Math.floor((Date.now() - dt.getTime()) / 1000);
  }
  if (typeof dt === 'number') {
    const t = Buffer.alloc(4);
    t.writeInt32LE(dt, 0);
    return t;
  }
  throw Error(`Cannot interpret "${dt}" as a date`);
}

/***/ }),

/***/ "./src/lib/gramjs/tl/index.ts":
/*!************************************!*\
  !*** ./src/lib/gramjs/tl/index.ts ***!
  \************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Api: () => (/* reexport safe */ _api__WEBPACK_IMPORTED_MODULE_0__["default"]),
/* harmony export */   serializeBytes: () => (/* reexport safe */ _generationHelpers__WEBPACK_IMPORTED_MODULE_1__.serializeBytes),
/* harmony export */   serializeDate: () => (/* reexport safe */ _generationHelpers__WEBPACK_IMPORTED_MODULE_1__.serializeDate)
/* harmony export */ });
/* harmony import */ var _api__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./api */ "./src/lib/gramjs/tl/api.js");
/* harmony import */ var _generationHelpers__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./generationHelpers */ "./src/lib/gramjs/tl/generationHelpers.ts");




/***/ }),

/***/ "./src/lib/gramjs/tl/schemaTl.ts":
/*!***************************************!*\
  !*** ./src/lib/gramjs/tl/schemaTl.ts ***!
  \***************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (`resPQ#05162463 nonce:int128 server_nonce:int128 pq:string server_public_key_fingerprints:Vector<long> = ResPQ;
p_q_inner_data#83c95aec pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 = P_Q_inner_data;
p_q_inner_data_dc#a9f55f95 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 dc:int = P_Q_inner_data;
p_q_inner_data_temp#3c6a84d4 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 expires_in:int = P_Q_inner_data;
p_q_inner_data_temp_dc#56fddf88 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 dc:int expires_in:int = P_Q_inner_data;
server_DH_params_fail#79cb045d nonce:int128 server_nonce:int128 new_nonce_hash:int128 = Server_DH_Params;
server_DH_params_ok#d0e8075c nonce:int128 server_nonce:int128 encrypted_answer:string = Server_DH_Params;
server_DH_inner_data#b5890dba nonce:int128 server_nonce:int128 g:int dh_prime:string g_a:string server_time:int = Server_DH_inner_data;
client_DH_inner_data#6643b654 nonce:int128 server_nonce:int128 retry_id:long g_b:string = Client_DH_Inner_Data;
dh_gen_ok#3bcbf734 nonce:int128 server_nonce:int128 new_nonce_hash1:int128 = Set_client_DH_params_answer;
dh_gen_retry#46dc1fb9 nonce:int128 server_nonce:int128 new_nonce_hash2:int128 = Set_client_DH_params_answer;
dh_gen_fail#a69dae02 nonce:int128 server_nonce:int128 new_nonce_hash3:int128 = Set_client_DH_params_answer;
destroy_auth_key_ok#f660e1d4 = DestroyAuthKeyRes;
destroy_auth_key_none#0a9f2259 = DestroyAuthKeyRes;
destroy_auth_key_fail#ea109b13 = DestroyAuthKeyRes;
---functions---
req_pq#60469778 nonce:int128 = ResPQ;
req_pq_multi#be7e8ef1 nonce:int128 = ResPQ;
req_pq_multi_new#51b410fd nonce:int128 = ResPQ;
req_DH_params#d712e4be nonce:int128 server_nonce:int128 p:string q:string public_key_fingerprint:long encrypted_data:string = Server_DH_Params;
set_client_DH_params#f5045f1f nonce:int128 server_nonce:int128 encrypted_data:string = Set_client_DH_params_answer;
destroy_auth_key#d1435160 = DestroyAuthKeyRes;
---types---
msgs_ack#62d6b459 msg_ids:Vector<long> = MsgsAck;
bad_msg_notification#a7eff811 bad_msg_id:long bad_msg_seqno:int error_code:int = BadMsgNotification;
bad_server_salt#edab447b bad_msg_id:long bad_msg_seqno:int error_code:int new_server_salt:long = BadMsgNotification;
msgs_state_req#da69fb52 msg_ids:Vector<long> = MsgsStateReq;
msgs_state_info#04deb57d req_msg_id:long info:string = MsgsStateInfo;
msgs_all_info#8cc0d131 msg_ids:Vector<long> info:string = MsgsAllInfo;
msg_detailed_info#276d3ec6 msg_id:long answer_msg_id:long bytes:int status:int = MsgDetailedInfo;
msg_new_detailed_info#809db6df answer_msg_id:long bytes:int status:int = MsgDetailedInfo;
msg_resend_req#7d861a08 msg_ids:Vector<long> = MsgResendReq;
rpc_error#2144ca19 error_code:int error_message:string = RpcError;
rpc_answer_unknown#5e2ad36e = RpcDropAnswer;
rpc_answer_dropped_running#cd78e586 = RpcDropAnswer;
rpc_answer_dropped#a43ad8b7 msg_id:long seq_no:int bytes:int = RpcDropAnswer;
future_salt#0949d9dc valid_since:int valid_until:int salt:long = FutureSalt;
future_salts#ae500895 req_msg_id:long now:int salts:vector<FutureSalt> = FutureSalts;
pong#347773c5 msg_id:long ping_id:long = Pong;
destroy_session_ok#e22045fc session_id:long = DestroySessionRes;
destroy_session_none#62d350c9 session_id:long = DestroySessionRes;
new_session_created#9ec20908 first_msg_id:long unique_id:long server_salt:long = NewSession;
http_wait#9299359f max_delay:int wait_after:int max_wait:int = HttpWait;
ipPort#d433ad73 ipv4:int port:int = IpPort;
ipPortSecret#37982646 ipv4:int port:int secret:bytes = IpPort;
accessPointRule#4679b65f phone_prefix_rules:string dc_id:int ips:vector<IpPort> = AccessPointRule;
help.configSimple#5a592a6c date:int expires:int rules:vector<AccessPointRule> = help.ConfigSimple;
tlsClientHello blocks:vector<TlsBlock> = TlsClientHello;
tlsBlockString data:string = TlsBlock;
tlsBlockRandom length:int = TlsBlock;
tlsBlockZero length:int = TlsBlock;
tlsBlockDomain = TlsBlock;
tlsBlockGrease seed:int = TlsBlock;
tlsBlockScope entries:Vector<TlsBlock> = TlsBlock;
---functions---
ping#7abe77ec ping_id:long = Pong;
ping_delay_disconnect#f3427b8c ping_id:long disconnect_delay:int = Pong;`);

/***/ }),

/***/ "./src/util/Deferred.ts":
/*!******************************!*\
  !*** ./src/util/Deferred.ts ***!
  \******************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ Deferred)
/* harmony export */ });
class Deferred {
  constructor() {
    this.promise = new Promise((resolve, reject) => {
      this.reject = reject;
      this.resolve = resolve;
    });
  }
  static resolved(value) {
    const deferred = new Deferred();
    deferred.resolve(value);
    return deferred;
  }
}

/***/ }),

/***/ "./src/util/browser/globalEnvironment.ts":
/*!***********************************************!*\
  !*** ./src/util/browser/globalEnvironment.ts ***!
  \***********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ARE_WEBCODECS_SUPPORTED: () => (/* binding */ ARE_WEBCODECS_SUPPORTED),
/* harmony export */   IS_BAD_URL_PARSER: () => (/* binding */ IS_BAD_URL_PARSER),
/* harmony export */   IS_INTL_LIST_FORMAT_SUPPORTED: () => (/* binding */ IS_INTL_LIST_FORMAT_SUPPORTED),
/* harmony export */   IS_MULTIACCOUNT_SUPPORTED: () => (/* binding */ IS_MULTIACCOUNT_SUPPORTED)
/* harmony export */ });
const IS_MULTIACCOUNT_SUPPORTED = 'SharedWorker' in globalThis;
const IS_INTL_LIST_FORMAT_SUPPORTED = 'ListFormat' in Intl;
const IS_BAD_URL_PARSER = new URL('tg://host').host !== 'host';
const ARE_WEBCODECS_SUPPORTED = 'VideoDecoder' in globalThis;

/***/ }),

/***/ "./src/util/colors.ts":
/*!****************************!*\
  !*** ./src/util/colors.ts ***!
  \****************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   convertToRGBA: () => (/* binding */ convertToRGBA),
/* harmony export */   getAverageColor: () => (/* binding */ getAverageColor),
/* harmony export */   getColorLuma: () => (/* binding */ getColorLuma),
/* harmony export */   getPatternColor: () => (/* binding */ getPatternColor),
/* harmony export */   getTextColor: () => (/* binding */ getTextColor),
/* harmony export */   hex2rgb: () => (/* binding */ hex2rgb),
/* harmony export */   hsb2rgb: () => (/* binding */ hsb2rgb),
/* harmony export */   hsl2rgb: () => (/* binding */ hsl2rgb),
/* harmony export */   numberToHexColor: () => (/* binding */ numberToHexColor),
/* harmony export */   rgb2hex: () => (/* binding */ rgb2hex),
/* harmony export */   rgb2hsb: () => (/* binding */ rgb2hsb)
/* harmony export */ });
/* harmony import */ var _files__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./files */ "./src/util/files.ts");
/* eslint-disable prefer-const */


const LUMA_THRESHOLD = 128;

/**
 * HEX > RGB
 * input: 'xxxxxx' (ex. 'ed15fa') case-insensitive
 * output: [r, g, b] ([0-255, 0-255, 0-255])
 */
function hex2rgb(param) {
  return [parseInt(param.substring(0, 2), 16), parseInt(param.substring(2, 4), 16), parseInt(param.substring(4, 6), 16)];
}

/**
 * RGB > HEX
 * input: [r, g, b] ([0-255, 0-255, 0-255])
 * output: 'xxxxxx' (ex. 'ff0000')
 */
function rgb2hex(param) {
  const p0 = param[0].toString(16);
  const p1 = param[1].toString(16);
  const p2 = param[2].toString(16);
  return (p0.length === 1 ? '0' + p0 : p0) + (p1.length === 1 ? '0' + p1 : p1) + (p2.length === 1 ? '0' + p2 : p2);
}

/**
 * Converts an RGB color value to HSV. Conversion formula
 * adapted from http://en.wikipedia.org/wiki/HSV_color_space.
 * Assumes r, g, and b are contained in the set [0, 255] and
 * returns h, s, and v in the set [0, 1].
 *
 * @param   Number  r       The red color value
 * @param   Number  g       The green color value
 * @param   Number  b       The blue color value
 * @return  Array           The HSV representation
 */
function rgb2hsb([r, g, b]) {
  r /= 255;
  g /= 255;
  b /= 255;
  let max = Math.max(r, g, b),
    min = Math.min(r, g, b);
  let h,
    s,
    v = max;
  let d = max - min;
  s = max === 0 ? 0 : d / max;
  if (max === min) {
    h = 0; // achromatic
  } else {
    switch (max) {
      case r:
        h = (g - b) / d + (g < b ? 6 : 0);
        break;
      case g:
        h = (b - r) / d + 2;
        break;
      case b:
        h = (r - g) / d + 4;
        break;
    }
    h /= 6;
  }
  return [h, s, v];
}

/**
 * Converts an HSV color value to RGB. Conversion formula
 * adapted from http://en.wikipedia.org/wiki/HSV_color_space.
 * Assumes h, s, and v are contained in the set [0, 1] and
 * returns r, g, and b in the set [0, 255].
 *
 * @param   Number  h       The hue
 * @param   Number  s       The saturation
 * @param   Number  v       The value
 * @return  Array           The RGB representation
 */
function hsb2rgb([h, s, v]) {
  let r, g, b;
  let i = Math.floor(h * 6);
  let f = h * 6 - i;
  let p = v * (1 - s);
  let q = v * (1 - f * s);
  let t = v * (1 - (1 - f) * s);
  switch (i % 6) {
    case 0:
      r = v;
      g = t;
      b = p;
      break;
    case 1:
      r = q;
      g = v;
      b = p;
      break;
    case 2:
      r = p;
      g = v;
      b = t;
      break;
    case 3:
      r = p;
      g = q;
      b = v;
      break;
    case 4:
      r = t;
      g = p;
      b = v;
      break;
    case 5:
      r = v;
      g = p;
      b = q;
      break;
  }
  return [Math.round(r * 255), Math.round(g * 255), Math.round(b * 255)];
}
async function getAverageColor(url) {
  // Only visit every 5 pixels
  const blockSize = 5;
  const defaultRGB = [0, 0, 0];
  let data;
  let width;
  let height;
  let i = -4;
  let length;
  let rgb = [0, 0, 0];
  let count = 0;
  const canvas = document.createElement('canvas');
  const context = canvas.getContext && canvas.getContext('2d');
  if (!context) {
    return defaultRGB;
  }
  const image = await (0,_files__WEBPACK_IMPORTED_MODULE_0__.preloadImage)(url);
  height = image.naturalHeight || image.offsetHeight || image.height;
  width = image.naturalWidth || image.offsetWidth || image.width;
  canvas.height = height;
  canvas.width = width;
  context.drawImage(image, 0, 0);
  try {
    data = context.getImageData(0, 0, width, height);
  } catch (e) {
    return defaultRGB;
  }
  length = data.data.length;
  while ((i += blockSize * 4) < length) {
    if (data.data[i + 3] === 0) continue; // Ignore fully transparent pixels
    ++count;
    rgb[0] += data.data[i];
    rgb[1] += data.data[i + 1];
    rgb[2] += data.data[i + 2];
  }
  rgb[0] = Math.floor(rgb[0] / count);
  rgb[1] = Math.floor(rgb[1] / count);
  rgb[2] = Math.floor(rgb[2] / count);
  return rgb;
}
function getColorLuma(rgbColor) {
  const [r, g, b] = rgbColor;
  const luma = 0.2126 * r + 0.7152 * g + 0.0722 * b;
  return luma;
}
// https://stackoverflow.com/a/64090995
function hsl2rgb([h, s, l]) {
  let a = s * Math.min(l, 1 - l);
  let f = (n, k = (n + h / 30) % 12) => l - a * Math.max(Math.min(k - 3, 9 - k, 1), -1);
  return [f(0), f(8), f(4)];
}

// Function was adapted from https://github.com/telegramdesktop/tdesktop/blob/35ff621b5b52f7e3553fb0f990ea13ade7101b8e/Telegram/SourceFiles/data/data_wall_paper.cpp#L518
function getPatternColor(rgbColor) {
  let [hue, saturation, value] = rgb2hsb(rgbColor);
  saturation = Math.min(1, saturation + 0.05 + 0.1 * (1 - saturation));
  value = value > 0.5 ? Math.max(0, value * 0.65) : Math.max(0, Math.min(1, 1 - value * 0.65));
  const rgb = hsl2rgb([hue * 360, saturation, value]);
  const hex = rgb2hex(rgb.map(c => Math.floor(c * 255)));
  return `#${hex}66`;
}
const convertToRGBA = color => {
  const alpha = color >> 24 & 0xff;
  const red = color >> 16 & 0xff;
  const green = color >> 8 & 0xff;
  const blue = color & 0xff;
  const alphaFloat = alpha / 255;
  return `rgba(${red}, ${green}, ${blue}, ${alphaFloat})`;
};
const numberToHexColor = color => {
  return `#${color.toString(16).padStart(6, '0')}`;
};
const getTextColor = color => {
  const r = color >> 16 & 0xff;
  const g = color >> 8 & 0xff;
  const b = color & 0xff;
  const luma = getColorLuma([r, g, b]);
  return luma > LUMA_THRESHOLD ? 'black' : 'white';
};

/***/ }),

/***/ "./src/util/dates/units.ts":
/*!*********************************!*\
  !*** ./src/util/dates/units.ts ***!
  \*********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   DAY: () => (/* binding */ DAY),
/* harmony export */   HOUR: () => (/* binding */ HOUR),
/* harmony export */   MINUTE: () => (/* binding */ MINUTE),
/* harmony export */   getDays: () => (/* binding */ getDays),
/* harmony export */   getHours: () => (/* binding */ getHours),
/* harmony export */   getMinutes: () => (/* binding */ getMinutes),
/* harmony export */   getSeconds: () => (/* binding */ getSeconds)
/* harmony export */ });
/// In seconds
const MINUTE = 60;
const HOUR = 3600;
const DAY = 86400;
function getMinutes(seconds, roundDown) {
  const roundFunc = roundDown ? Math.floor : Math.ceil;
  return roundFunc(seconds / MINUTE);
}
function getHours(seconds, roundDown) {
  const roundFunc = roundDown ? Math.floor : Math.ceil;
  return roundFunc(seconds / HOUR);
}
function getDays(seconds, roundDown) {
  const roundFunc = roundDown ? Math.floor : Math.ceil;
  return roundFunc(seconds / DAY);
}
function getSeconds(hours, minutes, seconds) {
  return hours * HOUR + minutes * MINUTE + seconds;
}

/***/ }),

/***/ "./src/util/files.ts":
/*!***************************!*\
  !*** ./src/util/files.ts ***!
  \***************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   blobToDataUri: () => (/* binding */ blobToDataUri),
/* harmony export */   blobToFile: () => (/* binding */ blobToFile),
/* harmony export */   createPosterForVideo: () => (/* binding */ createPosterForVideo),
/* harmony export */   fetchBlob: () => (/* binding */ fetchBlob),
/* harmony export */   fetchFile: () => (/* binding */ fetchFile),
/* harmony export */   hasPreview: () => (/* binding */ hasPreview),
/* harmony export */   imgToCanvas: () => (/* binding */ imgToCanvas),
/* harmony export */   preloadImage: () => (/* binding */ preloadImage),
/* harmony export */   preloadVideo: () => (/* binding */ preloadVideo),
/* harmony export */   validateFiles: () => (/* binding */ validateFiles)
/* harmony export */ });
/* harmony import */ var _config__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../config */ "./src/config.ts");
/* harmony import */ var _schedulers__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./schedulers */ "./src/util/schedulers.ts");



// Polyfill for Safari: `File` is not available in web worker
if (typeof File === 'undefined') {
  self.File = class extends Blob {
    constructor(fileBits, fileName, options) {
      if (options) {
        const {
          type,
          ...rest
        } = options;
        super(fileBits, {
          type
        });
        Object.assign(this, rest);
      } else {
        super(fileBits);
      }
      this.name = fileName;
    }
  };
}
function blobToDataUri(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = e => {
      const {
        result
      } = e.target || {};
      if (typeof result === 'string') {
        resolve(result);
      }
      reject(new Error('Failed to read blob'));
    };
    reader.onerror = reject;
    reader.readAsDataURL(blob);
  });
}
function blobToFile(blob, fileName) {
  return new File([blob], fileName, {
    lastModified: Date.now(),
    type: blob.type
  });
}
function preloadImage(url) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = reject;
    img.src = url;
  });
}
function preloadVideo(url) {
  return new Promise((resolve, reject) => {
    const video = document.createElement('video');
    video.volume = 0;
    video.onloadedmetadata = () => resolve(video);
    video.onerror = reject;
    video.src = url;
  });
}
async function createPosterForVideo(url) {
  try {
    const video = await preloadVideo(url);
    return await Promise.race([(0,_schedulers__WEBPACK_IMPORTED_MODULE_1__.pause)(2000), new Promise((resolve, reject) => {
      video.onseeked = () => {
        if (!video.videoWidth || !video.videoHeight) {
          resolve(undefined);
        }
        const canvas = document.createElement('canvas');
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(video, 0, 0);
        canvas.toBlob(blob => {
          resolve(blob ? URL.createObjectURL(blob) : undefined);
        });
      };
      video.onerror = reject;
      video.currentTime = Math.min(video.duration, 1);
    })]);
  } catch (e) {
    return undefined;
  }
}
async function fetchBlob(blobUrl) {
  const response = await fetch(blobUrl);
  return response.blob();
}
async function fetchFile(blobUrl, fileName) {
  const blob = await fetchBlob(blobUrl);
  return blobToFile(blob, fileName);
}
function imgToCanvas(img) {
  const canvas = document.createElement('canvas');
  canvas.width = img.width;
  canvas.height = img.height;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0);
  return canvas;
}
function hasPreview(file) {
  return _config__WEBPACK_IMPORTED_MODULE_0__.CONTENT_TYPES_WITH_PREVIEW.has(file.type);
}
function validateFiles(files) {
  if (!files?.length) {
    return undefined;
  }
  return Array.from(files).map(fixMovMime).filter(file => file.size);
}

// .mov MIME type not reported sometimes https://developer.mozilla.org/en-US/docs/Web/API/File/type#sect1
function fixMovMime(file) {
  const ext = file.name.split('.').pop();
  if (!file.type && ext.toLowerCase() === 'mov') {
    return new File([file], file.name, {
      type: 'video/quicktime'
    });
  }
  return file;
}

/***/ }),

/***/ "./src/util/foreman.ts":
/*!*****************************!*\
  !*** ./src/util/foreman.ts ***!
  \*****************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Foreman: () => (/* binding */ Foreman)
/* harmony export */ });
/* harmony import */ var _Deferred__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./Deferred */ "./src/util/Deferred.ts");

class Foreman {
  deferreds = [];
  priorityDeferreds = [];
  activeWorkers = 0;
  constructor(maxWorkers) {
    this.maxWorkers = maxWorkers;
  }
  requestWorker(isPriority) {
    if (this.activeWorkers === this.maxWorkers) {
      const deferred = new _Deferred__WEBPACK_IMPORTED_MODULE_0__["default"]();
      if (isPriority) {
        this.priorityDeferreds.push(deferred);
      } else {
        this.deferreds.push(deferred);
      }
      return deferred.promise;
    }
    this.activeWorkers++;
    return Promise.resolve();
  }
  releaseWorker() {
    if (this.queueLength) {
      const deferred = this.priorityDeferreds.shift() || this.deferreds.shift();
      deferred.resolve();
    } else {
      this.activeWorkers--;
    }
  }
  get queueLength() {
    return this.deferreds.length + this.priorityDeferreds.length;
  }
}

/***/ }),

/***/ "./src/util/iteratees.ts":
/*!*******************************!*\
  !*** ./src/util/iteratees.ts ***!
  \*******************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   areSortedArraysEqual: () => (/* binding */ areSortedArraysEqual),
/* harmony export */   areSortedArraysIntersecting: () => (/* binding */ areSortedArraysIntersecting),
/* harmony export */   buildCollectionByCallback: () => (/* binding */ buildCollectionByCallback),
/* harmony export */   buildCollectionByKey: () => (/* binding */ buildCollectionByKey),
/* harmony export */   cloneDeep: () => (/* binding */ cloneDeep),
/* harmony export */   compact: () => (/* binding */ compact),
/* harmony export */   compareFields: () => (/* binding */ compareFields),
/* harmony export */   excludeSortedArray: () => (/* binding */ excludeSortedArray),
/* harmony export */   findIntersectionWithSet: () => (/* binding */ findIntersectionWithSet),
/* harmony export */   findLast: () => (/* binding */ findLast),
/* harmony export */   isInsideSortedArrayRange: () => (/* binding */ isInsideSortedArrayRange),
/* harmony export */   isLiteralObject: () => (/* binding */ isLiteralObject),
/* harmony export */   mapValues: () => (/* binding */ mapValues),
/* harmony export */   omit: () => (/* binding */ omit),
/* harmony export */   omitUndefined: () => (/* binding */ omitUndefined),
/* harmony export */   orderBy: () => (/* binding */ orderBy),
/* harmony export */   partition: () => (/* binding */ partition),
/* harmony export */   pick: () => (/* binding */ pick),
/* harmony export */   pickTruthy: () => (/* binding */ pickTruthy),
/* harmony export */   split: () => (/* binding */ split),
/* harmony export */   unique: () => (/* binding */ unique),
/* harmony export */   uniqueByField: () => (/* binding */ uniqueByField)
/* harmony export */ });
function buildCollectionByKey(collection, key) {
  return collection.reduce((byKey, member) => {
    byKey[member[key]] = member;
    return byKey;
  }, {});
}
function buildCollectionByCallback(collection, callback) {
  return collection.reduce((byKey, member) => {
    const [key, value] = callback(member);
    byKey[key] = value;
    return byKey;
  }, {});
}
function mapValues(byKey, callback) {
  return Object.keys(byKey).reduce((newByKey, key, index) => {
    newByKey[key] = callback(byKey[key], key, index, byKey);
    return newByKey;
  }, {});
}
function pick(object, keys) {
  return keys.reduce((result, key) => {
    result[key] = object[key];
    return result;
  }, {});
}
function pickTruthy(object, keys) {
  return keys.reduce((result, key) => {
    if (object[key]) {
      result[key] = object[key];
    }
    return result;
  }, {});
}
function omit(object, keys) {
  const stringKeys = new Set(keys.map(String));
  const savedKeys = Object.keys(object).filter(key => !stringKeys.has(key));
  return pick(object, savedKeys);
}
function omitUndefined(object) {
  return Object.keys(object).reduce((result, stringKey) => {
    const key = stringKey;
    if (object[key] !== undefined) {
      result[key] = object[key];
    }
    return result;
  }, {});
}
function orderBy(collection, orderRule, mode = 'asc') {
  function compareValues(a, b, currentOrderRule, isAsc) {
    const aValue = (typeof currentOrderRule === 'function' ? currentOrderRule(a) : a[currentOrderRule]) || 0;
    const bValue = (typeof currentOrderRule === 'function' ? currentOrderRule(b) : b[currentOrderRule]) || 0;

    // @ts-expect-error Rely on the JS to handle the comparison
    return isAsc ? aValue - bValue : bValue - aValue;
  }
  if (Array.isArray(orderRule)) {
    const [mode1, mode2] = Array.isArray(mode) ? mode : [mode, mode];
    const [orderRule1, orderRule2] = orderRule;
    const isAsc1 = mode1 === 'asc';
    const isAsc2 = mode2 === 'asc';
    return collection.sort((a, b) => {
      return compareValues(a, b, orderRule1, isAsc1) || compareValues(a, b, orderRule2, isAsc2);
    });
  }
  const isAsc = mode === 'asc';
  return collection.sort((a, b) => {
    return compareValues(a, b, orderRule, isAsc);
  });
}
function unique(array) {
  return Array.from(new Set(array));
}
function uniqueByField(array, field) {
  return [...new Map(array.map(item => [item[field], item])).values()];
}
function compact(array) {
  return array.filter(Boolean);
}
function areSortedArraysEqual(array1, array2) {
  if (array1.length !== array2.length) {
    return false;
  }
  return array1.every((item, i) => item === array2[i]);
}
function areSortedArraysIntersecting(array1, array2) {
  return array1[0] <= array2[array2.length - 1] && array1[array1.length - 1] >= array2[0];
}
function isInsideSortedArrayRange(value, array) {
  return array[0] <= value && value <= array[array.length - 1];
}
function findIntersectionWithSet(array, set) {
  return array.filter(a => set.has(a));
}
/**
 * Exlude elements from base array. Both arrays should be sorted in same order
 * @param base
 * @param toExclude
 * @returns New array without excluded elements
 */
function excludeSortedArray(base, toExclude) {
  if (!base?.length) return base;
  const result = [];
  let excludeIndex = 0;
  for (let i = 0; i < base.length; i++) {
    if (toExclude[excludeIndex] === base[i]) {
      excludeIndex += 1;
    } else {
      result.push(base[i]);
    }
  }
  return result;
}
function split(array, chunkSize) {
  const result = [];
  for (let i = 0; i < array.length; i += chunkSize) {
    result.push(array.slice(i, i + chunkSize));
  }
  return result;
}
function partition(array, filter) {
  const pass = [];
  const fail = [];
  array.forEach((e, idx, arr) => (filter(e, idx, arr) ? pass : fail).push(e));
  return [pass, fail];
}
function cloneDeep(value) {
  if (!isObject(value)) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(cloneDeep);
  }
  return Object.keys(value).reduce((acc, key) => {
    acc[key] = cloneDeep(value[key]);
    return acc;
  }, {});
}
function isLiteralObject(value) {
  return isObject(value) && !Array.isArray(value);
}
function isObject(value) {
  // eslint-disable-next-line no-null/no-null
  return typeof value === 'object' && value !== null;
}
function findLast(array, predicate) {
  let cursor = array.length;
  while (cursor--) {
    if (predicate(array[cursor], cursor, array)) {
      return array[cursor];
    }
  }
  return undefined;
}
function compareFields(a, b) {
  return Number(b) - Number(a);
}

/***/ }),

/***/ "./src/util/multiaccount.ts":
/*!**********************************!*\
  !*** ./src/util/multiaccount.ts ***!
  \**********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ACCOUNT_SLOT: () => (/* binding */ ACCOUNT_SLOT),
/* harmony export */   DATA_BROADCAST_CHANNEL_NAME: () => (/* binding */ DATA_BROADCAST_CHANNEL_NAME),
/* harmony export */   ESTABLISH_BROADCAST_CHANNEL_NAME: () => (/* binding */ ESTABLISH_BROADCAST_CHANNEL_NAME),
/* harmony export */   GLOBAL_STATE_CACHE_KEY: () => (/* binding */ GLOBAL_STATE_CACHE_KEY),
/* harmony export */   MULTITAB_STORAGE_KEY: () => (/* binding */ MULTITAB_STORAGE_KEY),
/* harmony export */   getAccountSlot: () => (/* binding */ getAccountSlot),
/* harmony export */   getAccountSlotUrl: () => (/* binding */ getAccountSlotUrl),
/* harmony export */   getAccountsInfo: () => (/* binding */ getAccountsInfo),
/* harmony export */   loadSlotSession: () => (/* binding */ loadSlotSession),
/* harmony export */   storeAccountData: () => (/* binding */ storeAccountData),
/* harmony export */   writeSlotSession: () => (/* binding */ writeSlotSession)
/* harmony export */ });
/* harmony import */ var _config__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../config */ "./src/config.ts");
/* harmony import */ var _browser_globalEnvironment__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./browser/globalEnvironment */ "./src/util/browser/globalEnvironment.ts");


const WORKER_NAME = typeof WorkerGlobalScope !== 'undefined' && globalThis.self instanceof WorkerGlobalScope ? globalThis.self.name : undefined;
const WORKER_ACCOUNT_SLOT = WORKER_NAME ? Number(new URLSearchParams(WORKER_NAME).get(_config__WEBPACK_IMPORTED_MODULE_0__.ACCOUNT_QUERY)) : undefined;
const ACCOUNT_SLOT = WORKER_ACCOUNT_SLOT || (_browser_globalEnvironment__WEBPACK_IMPORTED_MODULE_1__.IS_MULTIACCOUNT_SUPPORTED ? getAccountSlot(globalThis.location.href) : undefined);
const DATA_BROADCAST_CHANNEL_NAME = `${_config__WEBPACK_IMPORTED_MODULE_0__.DATA_BROADCAST_CHANNEL_PREFIX}_${ACCOUNT_SLOT || 1}`;
const ESTABLISH_BROADCAST_CHANNEL_NAME = `${_config__WEBPACK_IMPORTED_MODULE_0__.ESTABLISH_BROADCAST_CHANNEL_PREFIX}_${ACCOUNT_SLOT || 1}`;
const MULTITAB_STORAGE_KEY = `${_config__WEBPACK_IMPORTED_MODULE_0__.MULTITAB_LOCALSTORAGE_KEY_PREFIX}_${ACCOUNT_SLOT || 1}`;
const GLOBAL_STATE_CACHE_KEY = ACCOUNT_SLOT ? `${_config__WEBPACK_IMPORTED_MODULE_0__.GLOBAL_STATE_CACHE_PREFIX}_${ACCOUNT_SLOT}` : _config__WEBPACK_IMPORTED_MODULE_0__.GLOBAL_STATE_CACHE_PREFIX;
function getAccountSlot(url) {
  const params = new URL(url).searchParams;
  const slot = params.get(_config__WEBPACK_IMPORTED_MODULE_0__.ACCOUNT_QUERY);
  const slotNumber = slot ? Number(slot) : 1;
  if (!slotNumber || Number.isNaN(slotNumber) || slotNumber === 1) return undefined;
  return slotNumber;
}
function getAccountsInfo() {
  if (!_browser_globalEnvironment__WEBPACK_IMPORTED_MODULE_1__.IS_MULTIACCOUNT_SUPPORTED) return {};
  const accountInfo = {};
  for (let i = 1; i <= _config__WEBPACK_IMPORTED_MODULE_0__.MULTIACCOUNT_MAX_SLOTS; i++) {
    const info = getAccountInfo(i);
    if (info) {
      accountInfo[i] = info;
    }
  }
  return accountInfo;
}
function getAccountInfo(slot) {
  const sessionData = loadSlotSession(slot);
  const {
    userId,
    avatarUri,
    color,
    emojiStatusId,
    firstName,
    lastName,
    isPremium,
    isTest,
    phone
  } = sessionData || {};
  if (!userId) return undefined;
  return {
    userId,
    avatarUri,
    color,
    emojiStatusId,
    firstName,
    lastName,
    isPremium,
    isTest,
    phone
  };
}
function loadSlotSession(slot) {
  try {
    const data = JSON.parse(localStorage.getItem(`${_config__WEBPACK_IMPORTED_MODULE_0__.SESSION_ACCOUNT_PREFIX}${slot || 1}`) || '{}');
    if (!data.dcId) return undefined;
    return data;
  } catch (e) {
    return undefined;
  }
}
function storeAccountData(slot, data) {
  const currentSlotData = loadSlotSession(slot);
  if (!currentSlotData) return;
  const updatedSharedData = {
    ...currentSlotData,
    ...data
  };
  if (!updatedSharedData.userId) return;
  writeSlotSession(slot, updatedSharedData);
}
function writeSlotSession(slot, data) {
  localStorage.setItem(`${_config__WEBPACK_IMPORTED_MODULE_0__.SESSION_ACCOUNT_PREFIX}${slot || 1}`, JSON.stringify(data));
}
function getAccountSlotUrl(slot, forLogin) {
  const url = new URL(globalThis.location.href);
  if (slot !== 1) {
    url.searchParams.set(_config__WEBPACK_IMPORTED_MODULE_0__.ACCOUNT_QUERY, String(slot));
  } else {
    url.searchParams.delete(_config__WEBPACK_IMPORTED_MODULE_0__.ACCOUNT_QUERY);
  }
  url.hash = forLogin ? 'login' : '';
  return url.toString();
}

// Validate current version across all tabs to avoid conflicts
if (typeof window === 'object') {
  const versionChannel = new BroadcastChannel('tt-version');
  versionChannel.postMessage({
    version: "dev"
  });
  versionChannel.addEventListener('message', event => {
    const {
      version
    } = event.data;
    if (!version) return;
    if (semverCompare("dev", version) === -1) {
      window.location.reload();
    }

    // If incoming version is older, send back the current version
    if (semverCompare("dev", version) === 1) {
      versionChannel.postMessage({
        version: "dev"
      });
    }
  });
}
function semverCompare(a, b) {
  if (a.startsWith(`${b}-`)) return -1;
  if (b.startsWith(`${a}-`)) return 1;
  return a.localeCompare(b, undefined, {
    numeric: true,
    sensitivity: 'case',
    caseFirst: 'upper'
  });
}

/***/ }),

/***/ "./src/util/schedulers.ts":
/*!********************************!*\
  !*** ./src/util/schedulers.ts ***!
  \********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   debounce: () => (/* binding */ debounce),
/* harmony export */   fastRaf: () => (/* binding */ fastRaf),
/* harmony export */   onBeforeUnload: () => (/* binding */ onBeforeUnload),
/* harmony export */   onIdle: () => (/* binding */ onIdle),
/* harmony export */   onTickEnd: () => (/* binding */ onTickEnd),
/* harmony export */   pause: () => (/* binding */ pause),
/* harmony export */   rafPromise: () => (/* binding */ rafPromise),
/* harmony export */   throttle: () => (/* binding */ throttle),
/* harmony export */   throttleWith: () => (/* binding */ throttleWith),
/* harmony export */   throttleWithTickEnd: () => (/* binding */ throttleWithTickEnd)
/* harmony export */ });
function debounce(fn, ms, shouldRunFirst = true, shouldRunLast = true) {
  let waitingTimeout;
  return (...args) => {
    if (waitingTimeout) {
      clearTimeout(waitingTimeout);
      waitingTimeout = undefined;
    } else if (shouldRunFirst) {
      fn(...args);
    }
    waitingTimeout = self.setTimeout(() => {
      if (shouldRunLast) {
        fn(...args);
      }
      waitingTimeout = undefined;
    }, ms);
  };
}
function throttle(fn, ms, shouldRunFirst = true) {
  let interval;
  let isPending;
  let args;
  return (..._args) => {
    isPending = true;
    args = _args;
    if (!interval) {
      if (shouldRunFirst) {
        isPending = false;
        fn(...args);
      }
      interval = self.setInterval(() => {
        if (!isPending) {
          self.clearInterval(interval);
          interval = undefined;
          return;
        }
        isPending = false;
        fn(...args);
      }, ms);
    }
  };
}
function throttleWithTickEnd(fn) {
  return throttleWith(onTickEnd, fn);
}
function throttleWith(schedulerFn, fn) {
  let waiting = false;
  let args;
  return (..._args) => {
    args = _args;
    if (!waiting) {
      waiting = true;
      schedulerFn(() => {
        waiting = false;
        fn(...args);
      });
    }
  };
}
const pause = ms => new Promise(resolve => {
  setTimeout(() => resolve(), ms);
});
function rafPromise() {
  return new Promise(resolve => {
    fastRaf(resolve);
  });
}
const FAST_RAF_TIMEOUT_FALLBACK_MS = 35; // < 30 FPS

let fastRafCallbacks;
let fastRafFallbackCallbacks;
let fastRafFallbackTimeout;

// May result in an immediate execution if called from another RAF callback which was scheduled
// (and therefore is executed) earlier than RAF callback scheduled by `fastRaf`
function fastRaf(callback, withTimeoutFallback = false) {
  if (!fastRafCallbacks) {
    fastRafCallbacks = new Set([callback]);
    requestAnimationFrame(() => {
      const currentCallbacks = fastRafCallbacks;
      fastRafCallbacks = undefined;
      fastRafFallbackCallbacks = undefined;
      if (fastRafFallbackTimeout) {
        clearTimeout(fastRafFallbackTimeout);
        fastRafFallbackTimeout = undefined;
      }
      currentCallbacks.forEach(cb => cb());
    });
  } else {
    fastRafCallbacks.add(callback);
  }
  if (withTimeoutFallback) {
    if (!fastRafFallbackCallbacks) {
      fastRafFallbackCallbacks = new Set([callback]);
    } else {
      fastRafFallbackCallbacks.add(callback);
    }
    if (!fastRafFallbackTimeout) {
      fastRafFallbackTimeout = window.setTimeout(() => {
        const currentTimeoutCallbacks = fastRafFallbackCallbacks;
        if (fastRafCallbacks) {
          const currentCallbacks = fastRafCallbacks;
          currentTimeoutCallbacks.forEach(callback => currentCallbacks.delete(callback));
        }
        fastRafFallbackCallbacks = undefined;
        if (fastRafFallbackTimeout) {
          clearTimeout(fastRafFallbackTimeout);
          fastRafFallbackTimeout = undefined;
        }
        currentTimeoutCallbacks.forEach(cb => cb());
      }, FAST_RAF_TIMEOUT_FALLBACK_MS);
    }
  }
}
let onTickEndCallbacks;
function onTickEnd(callback) {
  if (!onTickEndCallbacks) {
    onTickEndCallbacks = [callback];
    Promise.resolve().then(() => {
      const currentCallbacks = onTickEndCallbacks;
      onTickEndCallbacks = undefined;
      currentCallbacks.forEach(cb => cb());
    });
  } else {
    onTickEndCallbacks.push(callback);
  }
}
const IDLE_TIMEOUT = 500;
let onIdleCallbacks;
function onIdle(callback) {
  if (!self.requestIdleCallback) {
    onTickEnd(callback);
    return;
  }
  if (!onIdleCallbacks) {
    onIdleCallbacks = [callback];
    requestIdleCallback(deadline => {
      const currentCallbacks = onIdleCallbacks;
      onIdleCallbacks = undefined;
      while (currentCallbacks.length) {
        const cb = currentCallbacks.shift();
        cb();
        if (!deadline.timeRemaining()) break;
      }
      if (currentCallbacks.length) {
        if (onIdleCallbacks) {
          // Prepend the remaining callbacks if the next pass is already planned
          onIdleCallbacks = currentCallbacks.concat(onIdleCallbacks);
        } else {
          currentCallbacks.forEach(onIdle);
        }
      }
    }, {
      timeout: IDLE_TIMEOUT
    });
  } else {
    onIdleCallbacks.push(callback);
  }
}
let beforeUnloadCallbacks;
function onBeforeUnload(callback, isLast = false) {
  if (!beforeUnloadCallbacks) {
    beforeUnloadCallbacks = [];
    self.addEventListener('beforeunload', () => {
      beforeUnloadCallbacks.forEach(cb => cb());
    });
  }
  if (isLast) {
    beforeUnloadCallbacks.push(callback);
  } else {
    beforeUnloadCallbacks.unshift(callback);
  }
  return () => {
    beforeUnloadCallbacks = beforeUnloadCallbacks.filter(cb => cb !== callback);
  };
}

/***/ }),

/***/ "./src/util/serverTime.ts":
/*!********************************!*\
  !*** ./src/util/serverTime.ts ***!
  \********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getServerTime: () => (/* binding */ getServerTime),
/* harmony export */   getServerTimeOffset: () => (/* binding */ getServerTimeOffset),
/* harmony export */   setServerTimeOffset: () => (/* binding */ setServerTimeOffset)
/* harmony export */ });
let serverTimeOffset = 0;
function setServerTimeOffset(_serverTimeOffset) {
  serverTimeOffset = _serverTimeOffset;
}
function getServerTimeOffset() {
  return serverTimeOffset;
}
function getServerTime() {
  return Math.floor(Date.now() / 1000) + serverTimeOffset;
}

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			id: moduleId,
/******/ 			loaded: false,
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat get default export */
/******/ 	(() => {
/******/ 		// getDefaultExport function for compatibility with non-harmony modules
/******/ 		__webpack_require__.n = (module) => {
/******/ 			var getter = module && module.__esModule ?
/******/ 				() => (module['default']) :
/******/ 				() => (module);
/******/ 			__webpack_require__.d(getter, { a: getter });
/******/ 			return getter;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/node module decorator */
/******/ 	(() => {
/******/ 		__webpack_require__.nmd = (module) => {
/******/ 			module.paths = [];
/******/ 			if (!module.children) module.children = [];
/******/ 			return module;
/******/ 		};
/******/ 	})();
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module is referenced by other modules so it can't be inlined
/******/ 	var __webpack_exports__ = __webpack_require__("./src/lib/gramjs/index.ts");
/******/ 	
/******/ 	return __webpack_exports__;
/******/ })()
;
});
//# sourceMappingURL=gramjs.js.map