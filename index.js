"use strict";

function sliceUint8(e, t, r) {
    return Uint8Array.prototype.slice ? e.slice(t, r) : new Uint8Array(Array.prototype.slice.call(e, t, r))
}

function removePadding(e) {
    var t = e.byteLength, r = t && new DataView(e.buffer).getUint8(t - 1);
    return r ? (0, sliceUint8)(e, 0, t - r) : e
}

class AesDecryptor {
    constructor() {
        this.rcon = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54],
            this.subMix = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)],
            this.invSubMix = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)],
            this.sBox = new Uint32Array(256),
            this.invSBox = new Uint32Array(256),
            this.key = new Uint32Array(0),
            this.ksRows = 0,
            this.keySize = 0,
            this.keySchedule = void 0,
            this.invKeySchedule = void 0,
            this.initTable();
    }

    uint8ArrayToUint32Array_(e) {
        for (var t = new DataView(e), r = new Uint32Array(4), n = 0; n < 4; n++)
            r[n] = t.getUint32(4 * n);
        return r
    }

    initTable() {
        var e = this.sBox
            , t = this.invSBox
            , r = this.subMix
            , n = r[0]
            , i = r[1]
            , o = r[2]
            , a = r[3]
            , s = this.invSubMix
            , A = s[0]
            , c = s[1]
            , l = s[2]
            , u = s[3]
            , d = new Uint32Array(256)
            , p = 0
            , f = 0
            , h = 0;
        for (h = 0; h < 256; h++)
            d[h] = h < 128 ? h << 1 : h << 1 ^ 283;
        for (h = 0; h < 256; h++) {
            var m = f ^ f << 1 ^ f << 2 ^ f << 3 ^ f << 4;
            m = m >>> 8 ^ 255 & m ^ 99,
                e[p] = m,
                t[m] = p;
            var g = d[p]
                , v = d[g]
                , y = d[v]
                , b = 257 * d[m] ^ 16843008 * m;
            n[p] = b << 24 | b >>> 8,
                i[p] = b << 16 | b >>> 16,
                o[p] = b << 8 | b >>> 24,
                a[p] = b,
                b = 16843009 * y ^ 65537 * v ^ 257 * g ^ 16843008 * p,
                A[m] = b << 24 | b >>> 8,
                c[m] = b << 16 | b >>> 16,
                l[m] = b << 8 | b >>> 24,
                u[m] = b,
                p ? (p = g ^ d[d[d[y ^ g]]],
                    f ^= d[d[f]]) : p = f = 1
        }
    }

    expandKey(e) {
        for (var t = this.uint8ArrayToUint32Array_(e), r = !0, n = 0; n < t.length && r;)
            r = t[n] === this.key[n],
                n++;
        if (!r) {
            this.key = t;
            var i = this.keySize = t.length;
            if (4 !== i && 6 !== i && 8 !== i)
                throw new Error("Invalid aes key size=" + i);
            var o, a, s, A, c = this.ksRows = 4 * (i + 6 + 1), l = this.keySchedule = new Uint32Array(c), u = this.invKeySchedule = new Uint32Array(c), d = this.sBox, p = this.rcon, f = this.invSubMix, h = f[0], m = f[1], g = f[2], v = f[3];
            for (o = 0; o < c; o++)
                o < i ? s = l[o] = t[o] : (A = s,
                    o % i == 0 ? (A = d[(A = A << 8 | A >>> 24) >>> 24] << 24 | d[A >>> 16 & 255] << 16 | d[A >>> 8 & 255] << 8 | d[255 & A],
                        A ^= p[o / i | 0] << 24) : i > 6 && o % i == 4 && (A = d[A >>> 24] << 24 | d[A >>> 16 & 255] << 16 | d[A >>> 8 & 255] << 8 | d[255 & A]),
                    l[o] = s = (l[o - i] ^ A) >>> 0);
            for (a = 0; a < c; a++)
                o = c - a,
                    A = 3 & a ? l[o] : l[o - 4],
                    u[a] = a < 4 || o <= 4 ? A : h[d[A >>> 24]] ^ m[d[A >>> 16 & 255]] ^ g[d[A >>> 8 & 255]] ^ v[d[255 & A]],
                    u[a] = u[a] >>> 0
        }
    }

    networkToHostOrderSwap(e) {
        return e << 24 | (65280 & e) << 8 | (16711680 & e) >> 8 | e >>> 24
    }

    decrypt(e, t, r) {
        for (var n, i, o, a, s, A, c, l, u, d, p, f, h, m, g = this.keySize + 6, v = this.invKeySchedule, y = this.invSBox, b = this.invSubMix, M = b[0], _ = b[1], w = b[2], B = b[3], L = this.uint8ArrayToUint32Array_(r), T = L[0], k = L[1], C = L[2], E = L[3], x = new Int32Array(e), S = new Int32Array(x.length), D = this.networkToHostOrderSwap; t < x.length;) {
            for (u = D(x[t]),
                d = D(x[t + 1]),
                p = D(x[t + 2]),
                f = D(x[t + 3]),
                s = u ^ v[0],
                A = f ^ v[1],
                c = p ^ v[2],
                l = d ^ v[3],
                h = 4,
                m = 1; m < g; m++)
                n = M[s >>> 24] ^ _[A >> 16 & 255] ^ w[c >> 8 & 255] ^ B[255 & l] ^ v[h],
                    i = M[A >>> 24] ^ _[c >> 16 & 255] ^ w[l >> 8 & 255] ^ B[255 & s] ^ v[h + 1],
                    o = M[c >>> 24] ^ _[l >> 16 & 255] ^ w[s >> 8 & 255] ^ B[255 & A] ^ v[h + 2],
                    a = M[l >>> 24] ^ _[s >> 16 & 255] ^ w[A >> 8 & 255] ^ B[255 & c] ^ v[h + 3],
                    s = n,
                    A = i,
                    c = o,
                    l = a,
                    h += 4;
            n = y[s >>> 24] << 24 ^ y[A >> 16 & 255] << 16 ^ y[c >> 8 & 255] << 8 ^ y[255 & l] ^ v[h],
                i = y[A >>> 24] << 24 ^ y[c >> 16 & 255] << 16 ^ y[l >> 8 & 255] << 8 ^ y[255 & s] ^ v[h + 1],
                o = y[c >>> 24] << 24 ^ y[l >> 16 & 255] << 16 ^ y[s >> 8 & 255] << 8 ^ y[255 & A] ^ v[h + 2],
                a = y[l >>> 24] << 24 ^ y[s >> 16 & 255] << 16 ^ y[A >> 8 & 255] << 8 ^ y[255 & c] ^ v[h + 3],
                S[t] = D(n ^ T),
                S[t + 1] = D(a ^ k),
                S[t + 2] = D(o ^ C),
                S[t + 3] = D(i ^ E),
                T = u,
                k = d,
                C = p,
                E = f,
                t += 4
        }
        return S.buffer
    }
}

class Decrypter {
    constructor(e, t) {
        var r = (void 0 === t ? {} : t).removePKCS7Padding, n = void 0 === r || r;
        if (this.logEnabled = !0,
            this.removePKCS7Padding = void 0,
            this.subtle = null,
            this.softwareDecrypter = null,
            this.key = null,
            this.fastAesKey = null,
            this.remainderData = null,
            this.currentIV = null,
            this.currentResult = null,
            this.useSoftware = void 0,
            this.useSoftware = e.enableSoftwareAES,
            this.removePKCS7Padding = n,
            n)
            try {
                var i = self.crypto;
                i && (this.subtle = i.subtle || i.webkitSubtle);
            } catch (e) { }
        null === this.subtle && (this.useSoftware = !0);
    }

    destroy() {
        this.subtle = null,
            this.softwareDecrypter = null,
            this.key = null,
            this.fastAesKey = null,
            this.remainderData = null,
            this.currentIV = null,
            this.currentResult = null
    }

    isSync() {
        return this.useSoftware
    }

    flush() {
        var e = this.currentResult, t = this.remainderData;
        if (!e || t)
            return this.reset(), null;
        var r = new Uint8Array(e);
        return this.reset(), this.removePKCS7Padding ? (0, removePadding)(r) : r
    }

    reset() {
        this.currentResult = null,
            this.currentIV = null,
            this.remainderData = null,
            this.softwareDecrypter && (this.softwareDecrypter = null)
    }

    decrypt(e, r, n) {
        var i = this;
        return this.useSoftware ? new t((function (t, o) {
            i.softwareDecrypt(new Uint8Array(e), r, n);
            var a = i.flush();
            a ? t(a.buffer) : o(new Error("[softwareDecrypt] Failed to decrypt data"))
        }
        )) : this.webCryptoDecrypt(new Uint8Array(e), r, n)
    }

    softwareDecrypt(/*Uint8Array*/ data, /*ArrayBuffer*/ keyBuffer, /*ArrayBuffer*/ ivBuffer) {
        var n = this.currentIV, i = this.currentResult, o = this.remainderData;
        o && (data = (0, A.appendUint8Array)(o, data), this.remainderData = null);
        var s = this.getValidChunk(data);
        if (!s.length)
            return null;
        n && (ivBuffer = n);
        var l = this.softwareDecrypter;
        l || (l = this.softwareDecrypter = new AesDecryptor), l.expandKey(keyBuffer);
        var u = i;
        return this.currentResult = l.decrypt(s.buffer, 0, ivBuffer),
            this.currentIV = (0, sliceUint8)(s, -16).buffer, u || null
    }

    webCryptoDecrypt(e, r, n) {
        var a = this, A = this.subtle;
        return this.key === r && this.fastAesKey || (this.key = r,
            this.fastAesKey = new o.default(A, r)),
            this.fastAesKey.expandKey().then((function (r) {
                return A ? (new i.default(A, new Uint8Array(n)).decrypt(e.buffer, r)) : t.reject(new Error("web crypto not initialized"))
            }
            )).catch((function (t) {
                return s.logger.warn("[decrypter]: WebCrypto Error, disable WebCrypto API, " + t.name + ": " + t.message),
                    a.onWebCryptoError(e, r, n)
            }))
    }

    onWebCryptoError(e, t, r) {
        this.useSoftware = !0,
            this.logEnabled = !0,
            this.softwareDecrypt(e, t, r);
        var n = this.flush();
        if (n)
            return n.buffer;
        throw new Error("WebCrypto and softwareDecrypt: failed to decrypt data")
    }

    getValidChunk(e) {
        var t = e, r = e.length - e.length % 16;
        return r !== e.length && (t = (0, sliceUint8)(e, 0, r), this.remainderData = (0, sliceUint8)(e, r)), t
    }
}

const fs = require('fs');
const request = require('sync-request');
const cliProgress = require('cli-progress');

function toBuffer(arrayBuffer) {
    const buffer = Buffer.alloc(arrayBuffer.byteLength);
    const view = new Uint8Array(arrayBuffer);
    for (let i = 0; i < buffer.length; ++i) {
        buffer[i] = view[i];
    }
    return buffer;
}

const urlFormat = 'media-{0}.ts';
const totalChunks = 5;
const keyHex = '706d6e725546546174484b745461414d';
const ivHex = '424f5752543679716f336c7464395272';
const resultFilePath = 'output.ts';

const key = Uint8Array.from(Buffer.from(keyHex, 'hex'));
const iv = Uint8Array.from(Buffer.from(ivHex, 'hex'));

let decrypter = new Decrypter({
    enableSoftwareAES: true
});
let decryptedChunks = [];

const progressBar = new cliProgress.SingleBar();
progressBar.start(totalChunks, 1);

for (let i = 1; i <= totalChunks; i++) {
    progressBar.update(i);

    const response = request('GET', urlFormat.replace('{0}', i));
    if (response.statusCode !== 200) {
        console.log("status code:", response.statusCode);
        break;
    }

    const encrypted = response.getBody();
    const decrypted = decrypter.softwareDecrypt(encrypted, key.buffer, iv.buffer);
    if (decrypted !== null) {
        decryptedChunks.push(toBuffer(decrypted));
    }
}

decryptedChunks.push(decrypter.flush());
fs.writeFileSync(resultFilePath, Buffer.concat(decryptedChunks));

progressBar.stop();
