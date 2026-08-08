import { fetchSecurityConfig } from "../utils/sysConfig";
import { purgeCFCache, purgeRandomFileListCache, purgePublicFileListCache } from "../utils/purgeCache";
import { addFileToIndex } from "../utils/indexManager.js";
import { getDatabase } from '../utils/databaseAdapter.js';

// 统一的响应创建函数
export function createResponse(body, options = {}) {
    const defaultHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, authCode',
        'Access-Control-Max-Age': '86400',
    };

    return new Response(body, {
        ...options,
        headers: {
            ...defaultHeaders,
            ...options.headers
        }
    });
}

// 生成短链接
export function generateShortId(length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

const UNKNOWN_IP_ADDRESS = '未知';

// 获取IP地址
export async function getIPAddress(env, ip, securityConfig = null) {
    if (!env || !ip) return UNKNOWN_IP_ADDRESS;

    try {
        const config = securityConfig || await fetchSecurityConfig(env);
        const ipQuery = config?.upload?.ipQuery;

        if (!ipQuery?.enabled || ipQuery.channel !== 'customApi') {
            return UNKNOWN_IP_ADDRESS;
        }

        const customApi = ipQuery.customApi || {};
        if (!customApi.url) {
            return UNKNOWN_IP_ADDRESS;
        }

        const responseFields = Array.isArray(customApi.responseFields)
            ? customApi.responseFields
                .map(field => typeof field === 'string' ? field : field?.path || '')
                .filter(Boolean)
            : [];
        if (responseFields.length === 0) {
            return UNKNOWN_IP_ADDRESS;
        }

        const replaceIpPlaceholder = value => String(value ?? '').replace(/\{ip\}/g, ip);
        const queryUrl = new URL(replaceIpPlaceholder(customApi.url));
        const paramList = Array.isArray(customApi.params) ? customApi.params : [];
        for (const param of paramList) {
            const key = replaceIpPlaceholder(param?.key || '');
            if (!key) continue;
            queryUrl.searchParams.append(key, replaceIpPlaceholder(param?.value || ''));
        }

        const response = await fetch(queryUrl.toString());
        if (!response.ok) {
            return UNKNOWN_IP_ADDRESS;
        }

        const data = JSON.parse((await response.text()).trim());
        const formatValue = value => {
            if (Array.isArray(value)) {
                return value.map(formatValue).filter(Boolean).join(', ');
            }
            if (typeof value === 'object' && value !== null) {
                return JSON.stringify(value);
            }
            return String(value ?? '').trim();
        };

        const address = responseFields
            .map(path => {
                const value = String(path)
                    .replace(/\[(\d+)\]/g, '.$1')
                    .split('.')
                    .map(segment => segment.trim())
                    .filter(Boolean)
                    .reduce((current, segment) => {
                        if (current === undefined || current === null) return undefined;
                        return current[segment];
                    }, data);

                if (value === undefined || value === null || value === '') return '';
                return formatValue(value);
            })
            .filter(Boolean)
            .join('，');

        return address || UNKNOWN_IP_ADDRESS;
    } catch (error) {
        console.error('Error fetching IP address:', error);
        return UNKNOWN_IP_ADDRESS;
    }
}

// 处理文件名中的特殊字符
export function sanitizeFileName(fileName) {
    fileName = decodeURIComponent(fileName);
    fileName = fileName.split('/').pop();

    const unsafeCharsRe = /[\\\/:*?"'<>\| \(\)\[\]\{\}#%\^`~;@&=\+\$,]/g;
    return fileName.replace(unsafeCharsRe, '_');
}

/**
 * 上传路径安全处理：防止路径穿越，标准化特殊字符
 * @param {string} folder - 原始上传路径
 * @returns {string} 安全处理后的路径
 */
export function sanitizeUploadFolder(folder) {
    if (!folder || folder.trim() === '') {
        return '';
    }

    if (/%[0-9a-fA-F]{2}/.test(folder)) {
        try {
            folder = decodeURIComponent(folder);
        } catch (e) {}
    }

    folder = folder.replace(/\\/g, '/');

    const segments = folder.split('/').filter(Boolean);
    const safeSegments = [];
    for (const segment of segments) {
        if (segment === '..' || segment === '.') {
            continue;
        }
        safeSegments.push(segment);
    }

    return safeSegments.join('/');
}

// 获取IP
export function getUploadIp(request) {
    const forwarded = request.headers.get('x-forwarded-for') || '';
    const realIp = request.headers.get('x-real-ip') || '';
    const cfConnectingIp = request.headers.get('cf-connecting-ip') || '';
    const requester = request.headers.get('requester') || '';
    const trueClientIp = request.headers.get('true-client-ip') || '';
    const clientIp = request.headers.get('client-ip') || '';
    const xRemoteIp = request.headers.get('x-remote-ip') || '';
    const xOriginatingIp = request.headers.get('x-originating-ip') || '';
    const fastlyClientIp = request.headers.get('fastly-client-ip') || '';
    const akamaiOriginHop = request.headers.get('akamai-origin-hop') || '';
    const xRemoteAddr = request.headers.get('x-remote-addr') || '';
    const xRemoteHost = request.headers.get('x-remote-host') || '';
    const xClientIps = request.headers.get('x-client-ips') || '';

    const ip = forwarded || realIp || cfConnectingIp || requester || trueClientIp || clientIp || xRemoteIp || xOriginatingIp || fastlyClientIp || akamaiOriginHop || xRemoteAddr || xRemoteHost || xClientIps;

    if (!ip) {
        return null;
    }

    const ips = ip.split(',').map(i => i.trim());
    return ips[0];
}

// 检查上传IP是否被封禁
export async function isBlockedUploadIp(env, uploadIp) {
    try {
        const db = getDatabase(env);

        let list = await db.get("manage@blockipList");
        if (list == null) {
            list = [];
        } else {
            list = list.split(",");
        }

        return list.includes(uploadIp);
    } catch (error) {
        console.error('Failed to check blocked IP:', error);
        return false;
    }
}

// 解析文件扩展名
export function resolveFileExt(fileName, fileType = 'application/octet-stream') {
    let fileExt = fileName.split('.').pop();
    if (fileExt && fileExt !== fileName && isExtValid(fileExt)) {
        return fileExt;
    }
    const typePart = fileType.split('/').pop();
    if (typePart && typePart !== fileType) {
        return typePart;
    }
    return 'bin';
}

function isExtValid(ext) {
    return /^[a-zA-Z0-9_+.-]+$/.test(ext);
}

// 构建唯一文件ID
export async function buildUniqueFileId(context, fileName, fileType = 'application/octet-stream') {
    const { env, url } = context;
    const db = getDatabase(env);

    const fileExt = resolveFileExt(fileName, fileType);

    const nameType = url.searchParams.get('uploadNameType') || 'default';
    const uploadFolder = url.searchParams.get('uploadFolder') || '';
    const normalizedFolder = sanitizeUploadFolder(uploadFolder);

    fileName = sanitizeFileName(fileName);

    const unique_index = Date.now() + Math.floor(Math.random() * 10000);
    let baseId = '';

    if (nameType === 'index') {
        baseId = normalizedFolder ? `${normalizedFolder}/${unique_index}.${fileExt}` : `${unique_index}.${fileExt}`;
    } else if (nameType === 'origin') {
        baseId = normalizedFolder ? `${normalizedFolder}/${fileName}` : fileName;
    } else if (nameType === 'short') {
        while (true) {
            const shortId = generateShortId(8);
            const testFullId = normalizedFolder ? `${normalizedFolder}/${shortId}.${fileExt}` : `${shortId}.${fileExt}`;
            if (await db.get(testFullId) === null) {
                return testFullId;
            }
        }
    } else if (nameType === 'hyphen') {
        const nameStem = fileName.substring(0, fileName.lastIndexOf('.'));
        const suffix = nameStem.includes('-') ? nameStem.substring(nameStem.indexOf('-') + 1) : '';
        baseId = normalizedFolder ?
            `${normalizedFolder}/${unique_index}${suffix ? '-' + suffix : ''}.${fileExt}` :
            `${unique_index}${suffix ? '-' + suffix : ''}.${fileExt}`;
    } else {
        baseId = normalizedFolder ? `${normalizedFolder}/${unique_index}_${fileName}` : `${unique_index}_${fileName}`;
    }

    if (await db.get(baseId) === null) {
        return baseId;
    }

    let counter = 1;
    while (true) {
        let duplicateId;

        if (nameType === 'index') {
            const baseName = unique_index;
            duplicateId = normalizedFolder ?
                `${normalizedFolder}/${baseName}(${counter}).${fileExt}` :
                `${baseName}(${counter}).${fileExt}`;
        } else if (nameType === 'origin') {
            const nameWithoutExt = fileName.substring(0, fileName.lastIndexOf('.'));
            const ext = fileName.substring(fileName.lastIndexOf('.'));
            duplicateId = normalizedFolder ?
                `${normalizedFolder}/${nameWithoutExt}(${counter})${ext}` :
                `${nameWithoutExt}(${counter})${ext}`;
        } else if (nameType === 'hyphen') {
            const baseName = `${unique_index}${suffix ? '-' + suffix : ''}`;
            duplicateId = normalizedFolder ?
                `${normalizedFolder}/${baseName}(${counter}).${fileExt}` :
                `${baseName}(${counter}).${fileExt}`;
        } else {
            const baseName = `${unique_index}_${fileName}`;
            const nameWithoutExt = baseName.substring(0, baseName.lastIndexOf('.'));
            const ext = baseName.substring(baseName.lastIndexOf('.'));
            duplicateId = normalizedFolder ?
                `${normalizedFolder}/${nameWithoutExt}(${counter})${ext}` :
                `${nameWithoutExt}(${counter})${ext}`;
        }

        if (await db.get(duplicateId) === null) {
            return duplicateId;
        }

        counter++;

        if (counter > 1000) {
            throw new Error('无法生成唯一的文件ID');
        }
    }
}

// 基于uploadId的一致性渠道选择
export function selectConsistentChannel(channels, uploadId, loadBalanceEnabled) {
    if (!loadBalanceEnabled || !channels || channels.length === 0) {
        return channels[0];
    }

    let hash = 0;
    for (let i = 0; i < uploadId.length; i++) {
        const char = uploadId.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }

    const index = Math.abs(hash) % channels.length;
    return channels[index];
}


// 结束上传：异步记录索引
export async function endUpload(context, fullId, metadata) {
    try {
        await addFileToIndex(context, fullId, metadata);
    } catch (error) {
        console.error('endUpload failed:', error);
    }
}

// 内容审核
export async function moderateContent(env, url) {
    try {
        const securityConfig = await fetchSecurityConfig(env);
        const moderateConfig = securityConfig.upload?.moderate;
        if (!moderateConfig?.enabled) {
            return "None";
        }
        const channel = moderateConfig.channel || "moderatecontent.com";
        const apiKey = moderateConfig.moderateContentApiKey || "";
        if (channel === "moderatecontent.com" && apiKey) {
            const response = await fetch(`https://api.moderatecontent.com/moderate/?key=${apiKey}&url=${encodeURIComponent(url)}`);
            if (response.ok) {
                const data = await response.json();
                return data.rating_label || "None";
            }
        } else if (channel === "nsfwjs" && moderateConfig.nsfwApiPath) {
            const response = await fetch(moderateConfig.nsfwApiPath + url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url })
            });
            if (response.ok) {
                const data = await response.json();
                return data.is_nsfw ? "nsfw" : "safe";
            }
        }
        return "None";
    } catch (error) {
        console.error('moderateContent failed:', error.message);
        return "None";
    }
}

// CDN 缓存清理
export async function purgeCDNCache(env, url, request) {
    try {
        const origin = request ? `https://${new URL(request.url).hostname}` : `https://${globalThis.location?.hostname || 'localhost'}`;
        await purgeCFCache(env, url);
        await purgeRandomFileListCache(origin);
        await purgePublicFileListCache(origin);
    } catch (error) {
        console.error('purgeCDNCache failed:', error.message);
    }
}

// 解析图片尺寸
export function getImageDimensions(buffer, fileType) {
    try {
        const view = new DataView(buffer);
        if (fileType === "image/jpeg") {
            let offset = 2;
            while (offset < buffer.byteLength) {
                const marker = view.getUint16(offset);
                offset += 2;
                if (marker === 0xC0 || marker === 0xC1 || marker === 0xC2) {
                    const height = view.getUint16(offset);
                    const width = view.getUint16(offset + 2);
                    return { width, height };
                }
                const segmentLength = view.getUint16(offset);
                offset += segmentLength;
            }
        } else if (fileType === "image/png") {
            const width = view.getUint32(16);
            const height = view.getUint32(20);
            if (width > 0 && height > 0) {
                return { width, height };
            }
        } else if (fileType === "image/gif") {
            const width = view.getUint16(6, true);
            const height = view.getUint16(8, true);
            if (width > 0 && height > 0) {
                return { width, height };
            }
        }
    } catch (error) {
        console.error('getImageDimensions failed:', error.message);
    }
    return null;
}
