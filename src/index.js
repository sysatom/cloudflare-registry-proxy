// Constants
const DEFAULT_REGISTRY = 'registry-1.docker.io';
const AUTH_URL = 'https://auth.docker.io';
const DEFAULT_WHITELIST = ["library/nginx", "subfuzion/netcat"];

// Preflight request configuration
/** @type {RequestInit} */
const PREFLIGHT_INIT = {
	headers: new Headers({
		'access-control-allow-origin': '*',
		'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS',
		'access-control-max-age': '1728000',
	}),
};

/**
 * Whitelist management module
 */
const WhitelistManager = {
	/**
	 * 解析白名单配置
	 * @param {string|object} whitelistConfig JSON格式的白名单配置字符串或对象
	 * @returns {string[]} 白名单数组
	 */
	parseWhitelist(whitelistConfig) {
		try {
			// 如果没有配置白名单，使用默认值
			if (whitelistConfig === undefined || whitelistConfig === null) {
				console.log('No whitelist configured, using default whitelist');
				return DEFAULT_WHITELIST;
			}
			
			// 如果是字符串，尝试解析JSON
			const config = typeof whitelistConfig === 'string' 
				? JSON.parse(whitelistConfig) 
				: whitelistConfig;

			// 确保配置是数组
			if (!Array.isArray(config)) {
				console.error('Whitelist must be an array, using default whitelist');
				return DEFAULT_WHITELIST;
			}

			// 确保所有元素都是字符串
			const validEntries = config.filter(entry => typeof entry === 'string');
			if (validEntries.length !== config.length) {
				console.error('All whitelist entries must be strings');
			}

			return validEntries.length > 0 ? validEntries : DEFAULT_WHITELIST;
		} catch (error) {
			console.error('Failed to parse whitelist:', error);
			return DEFAULT_WHITELIST;
		}
	},

	/**
	 * 检查镜像是否在白名单中
	 * @param {string} imageName 镜像名称 (例如: library/nginx)
	 * @param {string[]} whitelist 白名单数组
	 * @returns {boolean} 是否允许访问
	 */
	isImageAllowed(imageName, whitelist) {
		// 移除tag部分
		const baseImage = imageName.split(':')[0];
		
		// 如果白名单为空，允许所有访问
		if (!whitelist || whitelist.length === 0) {
			return true;
		}

		// 检查是否在白名单中
		return whitelist.some(allowed => {
			// 完全匹配
			if (baseImage === allowed) {
				return true;
			}
			// 前缀匹配（用于允许某个组织下的所有镜像）
			if (allowed.endsWith('/*') && baseImage.startsWith(allowed.slice(0, -2))) {
				return true;
			}
			return false;
		});
	},

	/**
	 * 从请求路径中提取镜像名称
	 * @param {string} pathname 请求路径
	 * @returns {string|null} 镜像名称或null
	 */
	extractImageName(pathname) {
		// 处理v2 API请求
		// 匹配 /v2/{name}/manifests/{reference} 或 /v2/{name}/blobs/{digest}
		const v2Match = pathname.match(/^\/v2\/([^/]+(?:\/[^/]+)*)\/(?:manifests|blobs)\/.+$/);
		if (v2Match) {
			return v2Match[1];
		}

		// 处理v1 API请求
		const v1Match = pathname.match(/^\/v1\/repositories\/([^/]+(?:\/[^/]+)*)\/(?:tags|images)/);
		if (v1Match) {
			return v1Match[1];
		}

		return null;
	}
};

/**
 * Response utilities
 */
const ResponseUtils = {
	/**
	 * 构造响应
	 * @param {any} body 响应体
	 * @param {number} status 响应状态码
	 * @param {Object<string, string>} headers 响应头
	 * @returns {Response} 响应对象
	 */
	makeResponse(body, status = 200, headers = {}) {
		headers['access-control-allow-origin'] = '*';
		return new Response(body, { status, headers });
	}
};

/**
 * URL utilities
 */
const UrlUtils = {
	/**
	 * 构造新的URL对象
	 * @param {string} urlStr URL字符串
	 * @param {string} base URL base
	 * @returns {URL|null} URL对象或null
	 */
	createUrl(urlStr, base) {
		try {
			console.log(`Constructing new URL object with path ${urlStr} and base ${base}`);
			return new URL(urlStr, base);
		} catch (err) {
			console.error(`Failed to create URL: ${err.message}`);
			return null;
		}
	}
};

/**
 * HTTP proxy module
 */
const ProxyService = {
	/**
	 * 处理HTTP请求
	 * @param {Request} req 请求对象
	 * @param {string} pathname 请求路径
	 * @param {string} baseHost 基地址
	 * @returns {Promise<Response>} 响应承诺
	 */
	async handleRequest(req, pathname, baseHost) {
		const reqHdrRaw = req.headers;

		// 处理预检请求
		if (req.method === 'OPTIONS' &&
			reqHdrRaw.has('access-control-request-headers')
		) {
			return new Response(null, PREFLIGHT_INIT);
		}

		let rawLen = '';

		const reqHdrNew = new Headers(reqHdrRaw);
		reqHdrNew.delete("Authorization"); // 修复s3错误

		const urlObj = UrlUtils.createUrl(pathname, 'https://' + baseHost);
		if (!urlObj) {
			return ResponseUtils.makeResponse('Invalid URL', 400, {
				'Content-Type': 'text/plain'
			});
		}

		/** @type {RequestInit} */
		const reqInit = {
			method: req.method,
			headers: reqHdrNew,
			redirect: 'follow',
			body: req.body
		};
		return this.proxyRequest(urlObj, reqInit, rawLen);
	},

	/**
	 * 代理请求
	 * @param {URL} urlObj URL对象
	 * @param {RequestInit} reqInit 请求初始化对象
	 * @param {string} rawLen 原始长度
	 * @returns {Promise<Response>} 响应承诺
	 */
	async proxyRequest(urlObj, reqInit, rawLen) {
		const res = await fetch(urlObj.href, reqInit);
		const resHdrOld = res.headers;
		const resHdrNew = new Headers(resHdrOld);

		// 验证长度
		if (rawLen) {
			const newLen = resHdrOld.get('content-length') || '';
			const badLen = (rawLen !== newLen);

			if (badLen) {
				return ResponseUtils.makeResponse(res.body, 400, {
					'--error': `bad len: ${newLen}, except: ${rawLen}`,
					'access-control-expose-headers': '--error',
				});
			}
		}
		
		const status = res.status;
		resHdrNew.set('access-control-expose-headers', '*');
		resHdrNew.set('access-control-allow-origin', '*');
		resHdrNew.set('Cache-Control', 'max-age=1500');

		// 删除不必要的头
		resHdrNew.delete('content-security-policy');
		resHdrNew.delete('content-security-policy-report-only');
		resHdrNew.delete('clear-site-data');

		return new Response(res.body, {
			status,
			headers: resHdrNew
		});
	}
};

/**
 * Main registry proxy handler
 */
const RegistryProxy = {
	/**
	 * 处理主请求
	 * @param {Request} request 请求对象
	 * @param {Object} env 环境变量
	 * @param {Object} ctx 执行上下文
	 * @returns {Promise<Response>} 响应承诺
	 */
	async handleRequest(request, env, ctx) {
		try {
			const getReqHeader = (key) => request.headers.get(key);
			let registryHost = DEFAULT_REGISTRY;
			
			let url = new URL(request.url);
			const workers_url = `https://${url.hostname}`;

			// 检查白名单
			const imageName = WhitelistManager.extractImageName(url.pathname);
			if (imageName) {
				const whitelist = WhitelistManager.parseWhitelist(env.WHITELIST);
				if (!WhitelistManager.isImageAllowed(imageName, whitelist)) {
					return ResponseUtils.makeResponse('Image not in whitelist', 403, {
						'Content-Type': 'application/json',
						'Docker-Distribution-API-Version': 'registry/2.0'
					});
				}
			}

			// 获取请求参数中的 ns，确定上游主机地址
			const ns = url.searchParams.get('ns');
			if (ns) {
				registryHost = ns === 'docker.io' ? DEFAULT_REGISTRY : ns;
			}

			console.log(`反代地址: ${registryHost}`);
			
			// 更改请求的主机名
			url.hostname = registryHost;

			// 修改包含 %2F 和 %3A 的请求
			if (!/%2F/.test(url.search) && /%3A/.test(url.toString())) {
				let modifiedUrl = url.toString().replace(/%3A(?=.*?&)/, '%3Alibrary%2F');
				url = new URL(modifiedUrl);
				console.log(`handle_url: ${url}`);
			}

			// 处理token请求
			if (url.pathname.includes('/token')) {
				let token_parameter = {
					headers: {
						'Host': 'auth.docker.io',
						'User-Agent': getReqHeader("User-Agent"),
						'Accept': getReqHeader("Accept"),
						'Accept-Language': getReqHeader("Accept-Language"),
						'Accept-Encoding': getReqHeader("Accept-Encoding"),
						'Connection': 'keep-alive',
						'Cache-Control': 'max-age=0'
					}
				};
				let token_url = AUTH_URL + url.pathname + url.search;
				return fetch(new Request(token_url, request), token_parameter);
			}

			// 修改 /v2/ 请求路径
			if (registryHost === DEFAULT_REGISTRY && 
				/^\/v2\/[^/]+\/[^/]+\/[^/]+$/.test(url.pathname) && 
				!/^\/v2\/library/.test(url.pathname)) {
				url.pathname = '/v2/library/' + url.pathname.split('/v2/')[1];
				console.log(`modified_url: ${url.pathname}`);
			}

			// 构造请求参数
			let parameter = {
				headers: {
					'Host': registryHost,
					'User-Agent': getReqHeader("User-Agent"),
					'Accept': getReqHeader("Accept"),
					'Accept-Language': getReqHeader("Accept-Language"),
					'Accept-Encoding': getReqHeader("Accept-Encoding"),
					'Connection': 'keep-alive',
					'Cache-Control': 'max-age=0'
				},
				cacheTtl: 3600 // 缓存时间
			};

			// 添加Authorization头
			if (request.headers.has("Authorization")) {
				parameter.headers.Authorization = getReqHeader("Authorization");
			}

			// 添加可能存在字段X-Amz-Content-Sha256
			if (request.headers.has("X-Amz-Content-Sha256")) {
				parameter.headers['X-Amz-Content-Sha256'] = getReqHeader("X-Amz-Content-Sha256");
			}

			// 发起请求并处理响应
			let original_response = await fetch(new Request(url, request), parameter);
			let original_response_clone = original_response.clone();
			let original_text = original_response_clone.body;
			let response_headers = original_response.headers;
			let new_response_headers = new Headers(response_headers);
			let status = original_response.status;

			// 修改 Www-Authenticate 头
			if (new_response_headers.get("Www-Authenticate")) {
				let re = new RegExp(AUTH_URL, 'g');
				new_response_headers.set("Www-Authenticate", 
					response_headers.get("Www-Authenticate").replace(re, workers_url));
			}

			// 处理重定向
			if (new_response_headers.get("Location")) {
				const location = new_response_headers.get("Location");
				console.info(`Found redirection location, redirecting to ${location}`);
				return ProxyService.handleRequest(request, location, registryHost);
			}

			// 返回修改后的响应
			return new Response(original_text, {
				status,
				headers: new_response_headers
			});
		} catch (error) {
			console.error(`Request handler failed: ${error.message}`);
			return ResponseUtils.makeResponse('Internal server error', 500, {
				'Content-Type': 'text/plain',
				'X-Error-Details': error.message
			});
		}
	}
};

export default {
	async fetch(request, env, ctx) {
		return RegistryProxy.handleRequest(request, env, ctx);
	}
};
