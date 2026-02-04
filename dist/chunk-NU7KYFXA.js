// package.json
var version = "0.1.37";

// src/lib/utils.ts
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SdkError } from "@modelcontextprotocol/sdk/shared/transport.js";
import { OAuthError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { OAuthClientInformationFullSchema } from "@modelcontextprotocol/sdk/shared/auth.js";

// src/lib/mcp-auth-config.ts
import path from "path";
import os from "os";
import fs from "fs/promises";
async function createLockfile(serverUrlHash, pid2, port) {
  const lockData = {
    pid: pid2,
    port,
    timestamp: Date.now()
  };
  await writeJsonFile(serverUrlHash, "lock.json", lockData);
}
async function checkLockfile(serverUrlHash) {
  try {
    const lockfile = await readJsonFile(serverUrlHash, "lock.json", {
      async parseAsync(data) {
        if (typeof data !== "object" || data === null) return null;
        if (typeof data.pid !== "number" || typeof data.port !== "number" || typeof data.timestamp !== "number") {
          return null;
        }
        return data;
      }
    });
    return lockfile || null;
  } catch {
    return null;
  }
}
async function deleteLockfile(serverUrlHash) {
  await deleteConfigFile(serverUrlHash, "lock.json");
}
function getConfigDir() {
  const baseConfigDir = process.env.MCP_REMOTE_CONFIG_DIR || path.join(os.homedir(), ".mcp-auth");
  return path.join(baseConfigDir, `mcp-remote-${version}`);
}
async function ensureConfigDir() {
  try {
    const configDir = getConfigDir();
    await fs.mkdir(configDir, { recursive: true });
  } catch (error) {
    log("Error creating config directory:", error);
    throw error;
  }
}
function getConfigFilePath(serverUrlHash, filename) {
  const configDir = getConfigDir();
  return path.join(configDir, `${serverUrlHash}_${filename}`);
}
async function deleteConfigFile(serverUrlHash, filename) {
  try {
    const filePath = getConfigFilePath(serverUrlHash, filename);
    await fs.unlink(filePath);
  } catch (error) {
    if (error.code !== "ENOENT") {
      log(`Error deleting ${filename}:`, error);
    }
  }
}
async function readJsonFile(serverUrlHash, filename, schema) {
  try {
    await ensureConfigDir();
    const filePath = getConfigFilePath(serverUrlHash, filename);
    const content = await fs.readFile(filePath, "utf-8");
    const result = await schema.parseAsync(JSON.parse(content));
    return result;
  } catch (error) {
    if (error.code === "ENOENT") {
      return void 0;
    }
    log(`Error reading ${filename}:`, error);
    return void 0;
  }
}
async function writeJsonFile(serverUrlHash, filename, data) {
  try {
    await ensureConfigDir();
    const filePath = getConfigFilePath(serverUrlHash, filename);
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), { encoding: "utf-8", mode: 384 });
  } catch (error) {
    log(`Error writing ${filename}:`, error);
    throw error;
  }
}
async function readTextFile(serverUrlHash, filename, errorMessage) {
  try {
    await ensureConfigDir();
    const filePath = getConfigFilePath(serverUrlHash, filename);
    return await fs.readFile(filePath, "utf-8");
  } catch (error) {
    throw new Error(errorMessage || `Error reading ${filename}`);
  }
}
async function writeTextFile(serverUrlHash, filename, text) {
  try {
    await ensureConfigDir();
    const filePath = getConfigFilePath(serverUrlHash, filename);
    await fs.writeFile(filePath, text, { encoding: "utf-8", mode: 384 });
  } catch (error) {
    log(`Error writing ${filename}:`, error);
    throw error;
  }
}

// src/lib/protected-resource-metadata.ts
function parseWWWAuthenticateHeader(header) {
  const result = {};
  if (!header) {
    return result;
  }
  const paramString = header.replace(/^Bearer\s+/i, "");
  const paramRegex = /(\w+)=(?:"([^"]*)"|([\w-]+))/g;
  let match;
  while ((match = paramRegex.exec(paramString)) !== null) {
    const key = match[1];
    const value = match[2] ?? match[3];
    switch (key) {
      case "resource_metadata":
        result.resourceMetadataUrl = value;
        break;
      case "scope":
        result.scope = value;
        break;
      case "error":
        result.error = value;
        break;
      case "error_description":
        result.errorDescription = value;
        break;
    }
  }
  debugLog("Parsed WWW-Authenticate header", {
    hasResourceMetadata: !!result.resourceMetadataUrl,
    hasScope: !!result.scope,
    error: result.error
  });
  return result;
}
function buildProtectedResourceMetadataUrls(resourceUrl) {
  const url = new URL(resourceUrl);
  const urls = [];
  const path3 = url.pathname.replace(/\/$/, "");
  if (path3 && path3 !== "/") {
    urls.push(`${url.origin}/.well-known/oauth-protected-resource${path3}`);
  }
  urls.push(`${url.origin}/.well-known/oauth-protected-resource`);
  debugLog("Built Protected Resource Metadata URLs", { resourceUrl, urls });
  return urls;
}
async function fetchProtectedResourceMetadataFromUrl(metadataUrl) {
  debugLog("Fetching Protected Resource Metadata", { metadataUrl });
  try {
    const response = await fetch(metadataUrl, {
      headers: {
        Accept: "application/json"
      },
      signal: AbortSignal.timeout(5e3)
    });
    if (!response.ok) {
      if (response.status === 404) {
        debugLog("Protected Resource Metadata not found (404)", { metadataUrl });
      } else {
        debugLog("Failed to fetch Protected Resource Metadata", {
          status: response.status,
          statusText: response.statusText
        });
      }
      return void 0;
    }
    const metadata = await response.json();
    debugLog("Successfully fetched Protected Resource Metadata", {
      resource: metadata.resource,
      authorizationServers: metadata.authorization_servers,
      scopesSupported: metadata.scopes_supported
    });
    return metadata;
  } catch (error) {
    debugLog("Error fetching Protected Resource Metadata", {
      error: error instanceof Error ? error.message : String(error),
      metadataUrl
    });
    return void 0;
  }
}
async function discoverProtectedResourceMetadata(resourceUrl, wwwAuthenticateHeader) {
  debugLog("Starting Protected Resource Metadata discovery", {
    resourceUrl,
    hasWWWAuthenticateHeader: !!wwwAuthenticateHeader
  });
  if (wwwAuthenticateHeader) {
    const params = parseWWWAuthenticateHeader(wwwAuthenticateHeader);
    if (params.resourceMetadataUrl) {
      debugLog("Using resource_metadata URL from WWW-Authenticate header", {
        url: params.resourceMetadataUrl
      });
      const metadata = await fetchProtectedResourceMetadataFromUrl(params.resourceMetadataUrl);
      if (metadata) {
        return metadata;
      }
      debugLog("Failed to fetch from WWW-Authenticate URL, falling back to well-known discovery");
    }
  }
  const wellKnownUrls = buildProtectedResourceMetadataUrls(resourceUrl);
  for (const url of wellKnownUrls) {
    const metadata = await fetchProtectedResourceMetadataFromUrl(url);
    if (metadata) {
      return metadata;
    }
  }
  debugLog("Protected Resource Metadata discovery failed - no metadata found");
  return void 0;
}
function getAuthorizationServerUrl(metadata) {
  if (metadata.authorization_servers && metadata.authorization_servers.length > 0) {
    return metadata.authorization_servers[0];
  }
  return void 0;
}

// src/lib/authorization-server-metadata.ts
function getMetadataUrl(serverUrl) {
  const url = new URL(serverUrl);
  const metadataPath = "/.well-known/oauth-authorization-server";
  return `${url.origin}${metadataPath}`;
}
async function fetchAuthorizationServerMetadata(serverUrl) {
  const metadataUrl = getMetadataUrl(serverUrl);
  debugLog("Fetching authorization server metadata", { serverUrl, metadataUrl });
  try {
    const response = await fetch(metadataUrl, {
      headers: {
        Accept: "application/json"
      },
      // Short timeout to avoid blocking
      signal: AbortSignal.timeout(5e3)
    });
    if (!response.ok) {
      if (response.status === 404) {
        debugLog("Authorization server metadata endpoint not found (404)", { metadataUrl });
      } else {
        debugLog("Failed to fetch authorization server metadata", {
          status: response.status,
          statusText: response.statusText
        });
      }
      return void 0;
    }
    const metadata = await response.json();
    debugLog("Successfully fetched authorization server metadata", {
      issuer: metadata.issuer,
      scopes_supported: metadata.scopes_supported,
      scopeCount: metadata.scopes_supported?.length || 0
    });
    return metadata;
  } catch (error) {
    debugLog("Error fetching authorization server metadata", {
      error: error instanceof Error ? error.message : String(error),
      metadataUrl
    });
    return void 0;
  }
}

// src/lib/utils.ts
import express from "express";
import net from "net";
import crypto from "crypto";
import fs2 from "fs";
import { readFile, rm } from "fs/promises";
import path2 from "path";
import { EnvHttpProxyAgent, fetch as fetch2, Headers, setGlobalDispatcher } from "undici";
var REASON_AUTH_NEEDED = "authentication-needed";
var REASON_TRANSPORT_FALLBACK = "falling-back-to-alternate-transport";
var pid = process.pid;
var DEBUG = false;
var SILENT = false;
function getTimestamp() {
  const now = /* @__PURE__ */ new Date();
  return now.toISOString();
}
function debugLog(message, ...args) {
  if (!DEBUG) return;
  const serverUrlHash = global.currentServerUrlHash;
  if (!serverUrlHash) {
    console.error("[DEBUG LOG ERROR] global.currentServerUrlHash is not set. Cannot write debug log.");
    return;
  }
  try {
    const formattedMessage = `[${getTimestamp()}][${pid}] ${message}`;
    console.error(formattedMessage, ...args);
    const configDir = getConfigDir();
    fs2.mkdirSync(configDir, { recursive: true });
    const logPath = path2.join(configDir, `${serverUrlHash}_debug.log`);
    const logMessage = `${formattedMessage} ${args.map((arg) => typeof arg === "object" ? JSON.stringify(arg) : String(arg)).join(" ")}
`;
    fs2.appendFileSync(logPath, logMessage, { encoding: "utf8" });
  } catch (error) {
    console.error(`[DEBUG LOG ERROR] ${error}`);
  }
}
function log(str, ...rest) {
  if (!SILENT) {
    console.error(`[${pid}] ${str}`, ...rest);
  }
  debugLog(str, ...rest);
}
var MESSAGE_BLOCKED = Symbol("MessageBlocked");
var isMessageBlocked = (value) => value === MESSAGE_BLOCKED;
function createMessageTransformer({
  transformRequestFunction,
  transformResponseFunction
} = {}) {
  const pendingRequests = /* @__PURE__ */ new Map();
  const interceptRequest = (message) => {
    const messageId = message.id;
    if (!messageId) return message;
    pendingRequests.set(messageId, message);
    return transformRequestFunction?.(message) ?? message;
  };
  const interceptResponse = (message) => {
    const messageId = message.id;
    if (!messageId) return message;
    const originalRequest = pendingRequests.get(messageId);
    if (!originalRequest) return message;
    pendingRequests.delete(messageId);
    return transformResponseFunction?.(originalRequest, message) ?? message;
  };
  return {
    interceptRequest,
    interceptResponse
  };
}
function mcpProxy({
  transportToClient,
  transportToServer,
  ignoredTools = []
}) {
  let transportToClientClosed = false;
  let transportToServerClosed = false;
  const messageTransformer = createMessageTransformer({
    transformRequestFunction: (request) => {
      if (request.method === "tools/call" && request.params?.name) {
        const toolName = request.params.name;
        if (!shouldIncludeTool(ignoredTools, toolName)) {
          const errorResponse = {
            jsonrpc: "2.0",
            id: request.id,
            error: {
              code: -32603,
              message: `Tool "${toolName}" is not available`
            }
          };
          transportToClient.send(errorResponse).catch(onClientError);
          return MESSAGE_BLOCKED;
        }
      }
      return request;
    },
    transformResponseFunction: (req, res) => {
      if (req.method === "tools/list") {
        return {
          ...res,
          result: {
            ...res.result,
            tools: res.result.tools.filter((tool) => shouldIncludeTool(ignoredTools, tool.name))
          }
        };
      }
      return res;
    }
  });
  transportToClient.onmessage = (_message) => {
    const message = messageTransformer.interceptRequest(_message);
    if (isMessageBlocked(message)) {
      return;
    }
    log("[Local\u2192Remote]", message.method || message.id);
    debugLog("Local \u2192 Remote message", {
      method: message.method,
      id: message.id,
      params: message.params ? JSON.stringify(message.params).substring(0, 500) : void 0
    });
    if (message.method === "initialize") {
      const { clientInfo } = message.params;
      if (clientInfo) clientInfo.name = `${clientInfo.name} (via mcp-remote ${version})`;
      log(JSON.stringify(message, null, 2));
      debugLog("Initialize message with modified client info", { clientInfo });
    }
    transportToServer.send(message).catch(onServerError);
  };
  transportToServer.onmessage = (_message) => {
    const message = messageTransformer.interceptResponse(_message);
    log("[Remote\u2192Local]", message.method || message.id);
    debugLog("Remote \u2192 Local message", {
      method: message.method,
      id: message.id,
      result: message.result ? "result-present" : void 0,
      error: message.error
    });
    transportToClient.send(message).catch(onClientError);
  };
  transportToClient.onclose = () => {
    if (transportToServerClosed) {
      return;
    }
    transportToClientClosed = true;
    debugLog("Local transport closed, closing remote transport");
    transportToServer.close().catch(onServerError);
  };
  transportToServer.onclose = () => {
    if (transportToClientClosed) {
      return;
    }
    transportToServerClosed = true;
    debugLog("Remote transport closed, closing local transport");
    transportToClient.close().catch(onClientError);
  };
  transportToClient.onerror = onClientError;
  transportToServer.onerror = onServerError;
  function onClientError(error) {
    log("Error from local client:", error);
    debugLog("Error from local client", { stack: error.stack });
  }
  function onServerError(error) {
    log("Error from remote server:", error);
    debugLog("Error from remote server", { stack: error.stack });
  }
}
async function discoverOAuthServerInfo(serverUrl, headers = {}) {
  debugLog("Starting OAuth server discovery", { serverUrl });
  let wwwAuthenticateHeader;
  let wwwAuthenticateScope;
  try {
    debugLog("Probing MCP server for WWW-Authenticate header");
    const response = await fetch2(serverUrl, {
      method: "GET",
      headers: {
        ...headers,
        Accept: "application/json, text/event-stream"
      },
      signal: AbortSignal.timeout(1e4)
    });
    if (response.ok) {
      debugLog("Server responded OK without auth, using server URL as authorization server");
      const authServerMetadata = await fetchAuthorizationServerMetadata(serverUrl);
      return {
        authorizationServerUrl: serverUrl,
        authorizationServerMetadata: authServerMetadata
      };
    }
    if (response.status === 401) {
      wwwAuthenticateHeader = response.headers.get("WWW-Authenticate") || void 0;
      debugLog("Received 401 with WWW-Authenticate header", {
        hasHeader: !!wwwAuthenticateHeader,
        header: wwwAuthenticateHeader
      });
      if (wwwAuthenticateHeader) {
        const params = parseWWWAuthenticateHeader(wwwAuthenticateHeader);
        wwwAuthenticateScope = params.scope;
      }
    }
  } catch (error) {
    debugLog("Error probing MCP server", {
      error: error instanceof Error ? error.message : String(error)
    });
  }
  const protectedResourceMetadata = await discoverProtectedResourceMetadata(serverUrl, wwwAuthenticateHeader);
  let authorizationServerUrl;
  if (protectedResourceMetadata) {
    const discoveredUrl = getAuthorizationServerUrl(protectedResourceMetadata);
    if (discoveredUrl) {
      authorizationServerUrl = discoveredUrl;
      debugLog("Using authorization server from Protected Resource Metadata", {
        authorizationServerUrl
      });
    } else {
      authorizationServerUrl = serverUrl;
      debugLog("PRM found but no authorization_servers, falling back to server URL");
    }
  } else {
    authorizationServerUrl = serverUrl;
    debugLog("No Protected Resource Metadata found, falling back to server URL as authorization server");
  }
  const authorizationServerMetadata = await fetchAuthorizationServerMetadata(authorizationServerUrl);
  return {
    authorizationServerUrl,
    authorizationServerMetadata,
    protectedResourceMetadata,
    wwwAuthenticateScope
  };
}
async function connectToRemoteServer(client, serverUrl, authProvider, headers, authInitializer, transportStrategy = "http-first", recursionReasons = /* @__PURE__ */ new Set()) {
  log(`[${pid}] Connecting to remote server: ${serverUrl}`);
  const url = new URL(serverUrl);
  const eventSourceInit = {
    fetch: (url2, init) => {
      return Promise.resolve(authProvider?.tokens?.()).then(
        (tokens) => fetch2(url2, {
          ...init,
          headers: {
            ...init?.headers instanceof Headers ? Object.fromEntries(init?.headers.entries()) : init?.headers || {},
            ...headers,
            ...tokens?.access_token ? { Authorization: `Bearer ${tokens.access_token}` } : {},
            Accept: "text/event-stream"
          }
        })
      );
    }
  };
  log(`Using transport strategy: ${transportStrategy}`);
  const shouldAttemptFallback = transportStrategy === "http-first" || transportStrategy === "sse-first";
  const sseTransport = transportStrategy === "sse-only" || transportStrategy === "sse-first";
  const transport = sseTransport ? new SSEClientTransport(url, {
    authProvider,
    requestInit: { headers },
    eventSourceInit
  }) : new StreamableHTTPClientTransport(url, {
    authProvider,
    requestInit: { headers }
  });
  try {
    debugLog("Attempting to connect to remote server", { sseTransport });
    if (client) {
      debugLog("Connecting client to transport");
      await client.connect(transport);
    } else {
      debugLog("Starting transport directly");
      await transport.start();
      if (!sseTransport) {
        debugLog("Creating test transport for HTTP-only connection test");
        const testTransport = new StreamableHTTPClientTransport(url, { authProvider, requestInit: { headers } });
        const testClient = new Client({ name: "mcp-remote-fallback-test", version: "0.0.0" }, { capabilities: {} });
        await testClient.connect(testTransport);
      }
    }
    log(`Connected to remote server using ${transport.constructor.name}`);
    return transport;
  } catch (error) {
    const isSdkError = error instanceof SdkError;
    const httpStatusCode = isSdkError && error.data && typeof error.data === "object" && "status" in error.data ? error.data.status : null;
    const shouldFallbackOnError = shouldAttemptFallback && error instanceof Error && (httpStatusCode === 404 || httpStatusCode === 405 || error.message.includes("405") || error.message.includes("Method Not Allowed") || error.message.includes("404") || error.message.includes("Not Found"));
    if (shouldFallbackOnError) {
      log(`Received error (status ${httpStatusCode ?? "unknown"}): ${error.message}`);
      if (recursionReasons.has(REASON_TRANSPORT_FALLBACK)) {
        const errorMessage = `Already attempted transport fallback. Giving up.`;
        log(errorMessage);
        throw new Error(errorMessage);
      }
      log(`Recursively reconnecting for reason: ${REASON_TRANSPORT_FALLBACK}`);
      recursionReasons.add(REASON_TRANSPORT_FALLBACK);
      return connectToRemoteServer(
        client,
        serverUrl,
        authProvider,
        headers,
        authInitializer,
        sseTransport ? "http-only" : "sse-only",
        recursionReasons
      );
    } else if (error instanceof UnauthorizedError || error instanceof Error && error.message.includes("Unauthorized")) {
      log("Authentication required. Initializing auth...");
      debugLog("Authentication error detected", {
        errorCode: error instanceof OAuthError ? error.errorCode : void 0,
        errorMessage: error.message,
        stack: error.stack
      });
      debugLog("Calling authInitializer to start auth flow");
      const { waitForAuthCode, skipBrowserAuth } = await authInitializer();
      if (skipBrowserAuth) {
        log("Authentication required but skipping browser auth - using shared auth");
      } else {
        log("Authentication required. Waiting for authorization...");
      }
      debugLog("Waiting for auth code from callback server");
      const code = await waitForAuthCode();
      debugLog("Received auth code from callback server");
      try {
        log("Completing authorization...");
        await transport.finishAuth(code);
        debugLog("Authorization completed successfully");
        if (recursionReasons.has(REASON_AUTH_NEEDED)) {
          const errorMessage = `Already attempted reconnection for reason: ${REASON_AUTH_NEEDED}. Giving up.`;
          log(errorMessage);
          debugLog("Already attempted auth reconnection, giving up", {
            recursionReasons: Array.from(recursionReasons)
          });
          throw new Error(errorMessage);
        }
        recursionReasons.add(REASON_AUTH_NEEDED);
        log(`Recursively reconnecting for reason: ${REASON_AUTH_NEEDED}`);
        debugLog("Recursively reconnecting after auth", { recursionReasons: Array.from(recursionReasons) });
        return connectToRemoteServer(client, serverUrl, authProvider, headers, authInitializer, transportStrategy, recursionReasons);
      } catch (authError) {
        log("Authorization error:", authError);
        debugLog("Authorization error during finishAuth", {
          errorMessage: authError.message,
          stack: authError.stack
        });
        throw authError;
      }
    } else {
      log("Connection error:", error);
      debugLog("Connection error", {
        errorMessage: error.message,
        stack: error.stack,
        transportType: transport.constructor.name
      });
      throw error;
    }
  }
}
function setupOAuthCallbackServerWithLongPoll(options) {
  let authCode = null;
  const app = express();
  let authCompletedResolve;
  const authCompletedPromise = new Promise((resolve) => {
    authCompletedResolve = resolve;
  });
  app.get("/wait-for-auth", (req, res) => {
    if (authCode) {
      log("Auth already completed, returning 200");
      res.status(200).send("Authentication completed");
      return;
    }
    if (req.query.poll === "false") {
      log("Client requested no long poll, responding with 202");
      res.status(202).send("Authentication in progress");
      return;
    }
    const longPollTimeout = setTimeout(() => {
      log("Long poll timeout reached, responding with 202");
      res.status(202).send("Authentication in progress");
    }, options.authTimeoutMs || 3e4);
    authCompletedPromise.then(() => {
      clearTimeout(longPollTimeout);
      if (!res.headersSent) {
        log("Auth completed during long poll, responding with 200");
        res.status(200).send("Authentication completed");
      }
    }).catch(() => {
      clearTimeout(longPollTimeout);
      if (!res.headersSent) {
        log("Auth failed during long poll, responding with 500");
        res.status(500).send("Authentication failed");
      }
    });
  });
  app.get(options.path, (req, res) => {
    const code = req.query.code;
    if (!code) {
      res.status(400).send("Error: No authorization code received");
      return;
    }
    authCode = code;
    log("Auth code received, resolving promise");
    authCompletedResolve(code);
    res.send(`
      Authorization successful!
      You may close this window and return to the CLI.
      <script>
        // If this is a non-interactive session (no manual approval step was required) then
        // this should automatically close the window. If not, this will have no effect and
        // the user will see the message above.
        window.close();
      </script>
    `);
    options.events.emit("auth-code-received", code);
  });
  const server = app.listen(options.port, "127.0.0.1", () => {
    log(`OAuth callback server running at http://127.0.0.1:${options.port}`);
  });
  const waitForAuthCode = () => {
    return new Promise((resolve) => {
      if (authCode) {
        resolve(authCode);
        return;
      }
      options.events.once("auth-code-received", (code) => {
        resolve(code);
      });
    });
  };
  return { server, authCode, waitForAuthCode, authCompletedPromise };
}
async function findExistingClientPort(serverUrlHash) {
  const clientInfo = await readJsonFile(serverUrlHash, "client_info.json", OAuthClientInformationFullSchema);
  if (!clientInfo) {
    return void 0;
  }
  const localhostRedirectUri = clientInfo.redirect_uris.map((uri) => new URL(uri)).find(({ hostname }) => hostname === "localhost" || hostname === "127.0.0.1");
  if (!localhostRedirectUri) {
    throw new Error("Cannot find localhost callback URI from existing client information");
  }
  return parseInt(localhostRedirectUri.port);
}
function calculateDefaultPort(serverUrlHash) {
  const offset = parseInt(serverUrlHash.substring(0, 4), 16);
  return 3335 + offset % 45816;
}
async function findAvailablePort(preferredPort) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on("error", (err) => {
      if (err.code === "EADDRINUSE") {
        server.listen(0);
      } else {
        reject(err);
      }
    });
    server.on("listening", () => {
      const { port } = server.address();
      server.close(() => {
        resolve(port);
      });
    });
    server.listen(preferredPort || 0);
  });
}
async function parseCommandLineArgs(args, usage) {
  const headers = {};
  let i = 0;
  while (i < args.length) {
    if (args[i] === "--header" && i < args.length - 1) {
      const value = args[i + 1];
      const match = value.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
      if (match) {
        headers[match[1]] = match[2];
      } else {
        log(`Warning: ignoring invalid header argument: ${value}`);
      }
      args.splice(i, 2);
      continue;
    }
    i++;
  }
  const serverUrl = args[0];
  const specifiedPort = args[1] ? parseInt(args[1]) : void 0;
  const allowHttp = args.includes("--allow-http");
  const debug = args.includes("--debug");
  if (debug) {
    DEBUG = true;
    log("Debug mode enabled - detailed logs will be written to ~/.mcp-auth/");
  }
  const silent = args.includes("--silent");
  if (silent) {
    SILENT = true;
    log("Silent mode enabled - stderr output will be suppressed, except when --debug is also enabled");
  }
  const enableProxy = args.includes("--enable-proxy");
  if (enableProxy) {
    setGlobalDispatcher(new EnvHttpProxyAgent());
    log("HTTP proxy support enabled - using system HTTP_PROXY/HTTPS_PROXY environment variables");
  }
  let transportStrategy = "http-first";
  const transportIndex = args.indexOf("--transport");
  if (transportIndex !== -1 && transportIndex < args.length - 1) {
    const strategy = args[transportIndex + 1];
    if (strategy === "sse-only" || strategy === "http-only" || strategy === "sse-first" || strategy === "http-first") {
      transportStrategy = strategy;
      log(`Using transport strategy: ${transportStrategy}`);
    } else {
      log(`Warning: Ignoring invalid transport strategy: ${strategy}. Valid values are: sse-only, http-only, sse-first, http-first`);
    }
  }
  let host = "localhost";
  const hostIndex = args.indexOf("--host");
  if (hostIndex !== -1 && hostIndex < args.length - 1) {
    host = args[hostIndex + 1];
    log(`Using callback hostname: ${host}`);
  }
  let staticOAuthClientMetadata = null;
  const staticOAuthClientMetadataIndex = args.indexOf("--static-oauth-client-metadata");
  if (staticOAuthClientMetadataIndex !== -1 && staticOAuthClientMetadataIndex < args.length - 1) {
    const staticOAuthClientMetadataArg = args[staticOAuthClientMetadataIndex + 1];
    if (staticOAuthClientMetadataArg.startsWith("@")) {
      const filePath = staticOAuthClientMetadataArg.slice(1);
      staticOAuthClientMetadata = JSON.parse(await readFile(filePath, "utf8"));
      log(`Using static OAuth client metadata from file: ${filePath}`);
    } else {
      staticOAuthClientMetadata = JSON.parse(staticOAuthClientMetadataArg);
      log(`Using static OAuth client metadata from string`);
    }
  }
  let staticOAuthClientInfo = null;
  const staticOAuthClientInfoIndex = args.indexOf("--static-oauth-client-info");
  if (staticOAuthClientInfoIndex !== -1 && staticOAuthClientInfoIndex < args.length - 1) {
    const staticOAuthClientInfoArg = args[staticOAuthClientInfoIndex + 1];
    if (staticOAuthClientInfoArg.startsWith("@")) {
      const filePath = staticOAuthClientInfoArg.slice(1);
      staticOAuthClientInfo = JSON.parse(await readFile(filePath, "utf8"));
      log(`Using static OAuth client information from file: ${filePath}`);
    } else {
      staticOAuthClientInfo = JSON.parse(staticOAuthClientInfoArg);
      log(`Using static OAuth client information from string`);
    }
  }
  let authorizeResource = "";
  const resourceIndex = args.indexOf("--resource");
  if (resourceIndex !== -1 && resourceIndex < args.length - 1) {
    authorizeResource = args[resourceIndex + 1];
    log(`Using authorize resource: ${authorizeResource}`);
  }
  const ignoredTools = [];
  let j = 0;
  while (j < args.length) {
    if (args[j] === "--ignore-tool" && j < args.length - 1) {
      const toolName = args[j + 1];
      ignoredTools.push(toolName);
      log(`Ignoring tool: ${toolName}`);
      args.splice(j, 2);
      continue;
    }
    j++;
  }
  let authTimeoutMs = 3e4;
  const authTimeoutIndex = args.indexOf("--auth-timeout");
  if (authTimeoutIndex !== -1 && authTimeoutIndex < args.length - 1) {
    const timeoutSeconds = parseInt(args[authTimeoutIndex + 1], 10);
    if (!isNaN(timeoutSeconds) && timeoutSeconds > 0) {
      authTimeoutMs = timeoutSeconds * 1e3;
      log(`Using auth callback timeout: ${timeoutSeconds} seconds`);
    } else {
      log(`Warning: Ignoring invalid auth timeout value: ${args[authTimeoutIndex + 1]}. Must be a positive number.`);
    }
  }
  if (!serverUrl) {
    log(usage);
    process.exit(1);
  }
  const url = new URL(serverUrl);
  const isLocalhost = (url.hostname === "localhost" || url.hostname === "127.0.0.1") && url.protocol === "http:";
  if (!(url.protocol == "https:" || isLocalhost || allowHttp)) {
    log("Error: Non-HTTPS URLs are only allowed for localhost or when --allow-http flag is provided");
    log(usage);
    process.exit(1);
  }
  const serverUrlHash = getServerUrlHash(serverUrl, authorizeResource, headers);
  global.currentServerUrlHash = serverUrlHash;
  debugLog(`Starting mcp-remote with server URL: ${serverUrl}`);
  const defaultPort = calculateDefaultPort(serverUrlHash);
  const [existingClientPort, availablePort] = await Promise.all([findExistingClientPort(serverUrlHash), findAvailablePort(defaultPort)]);
  let callbackPort;
  if (specifiedPort) {
    if (existingClientPort && specifiedPort !== existingClientPort) {
      log(
        `Warning! Specified callback port of ${specifiedPort}, which conflicts with existing client registration port ${existingClientPort}. Deleting existing client data to force reregistration.`
      );
      await rm(getConfigFilePath(serverUrlHash, "client_info.json"));
    }
    log(`Using specified callback port: ${specifiedPort}`);
    callbackPort = specifiedPort;
  } else if (existingClientPort) {
    log(`Using existing client port: ${existingClientPort}`);
    callbackPort = existingClientPort;
  } else {
    log(`Using automatically selected callback port: ${availablePort}`);
    callbackPort = availablePort;
  }
  if (Object.keys(headers).length > 0) {
    log(`Using custom headers: ${JSON.stringify(headers)}`);
  }
  for (const [key, value] of Object.entries(headers)) {
    headers[key] = value.replace(/\$\{([^}]+)}/g, (match, envVarName) => {
      const envVarValue = process.env[envVarName];
      if (envVarValue !== void 0) {
        log(`Replacing ${match} with environment value in header '${key}'`);
        return envVarValue;
      } else {
        log(`Warning: Environment variable '${envVarName}' not found for header '${key}'.`);
        return "";
      }
    });
  }
  return {
    serverUrl,
    callbackPort,
    headers,
    transportStrategy,
    host,
    debug,
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    authorizeResource,
    ignoredTools,
    authTimeoutMs,
    serverUrlHash
  };
}
function setupSignalHandlers(cleanup) {
  process.on("SIGINT", async () => {
    log("\nShutting down...");
    await cleanup();
    process.exit(0);
  });
  process.stdin.resume();
  process.stdin.on("end", async () => {
    log("\nShutting down...");
    await cleanup();
    process.exit(0);
  });
}
function getServerUrlHash(serverUrl, authorizeResource, headers) {
  const parts = [serverUrl];
  if (authorizeResource) parts.push(authorizeResource);
  if (headers && Object.keys(headers).length > 0) {
    const sortedKeys = Object.keys(headers).sort();
    parts.push(JSON.stringify(headers, sortedKeys));
  }
  return crypto.createHash("md5").update(parts.join("|")).digest("hex");
}
function patternToRegex(pattern) {
  const parts = pattern.split("*");
  const escapedParts = parts.map((part) => part.replace(/\W/g, "\\$&"));
  const regexPattern = escapedParts.join(".*");
  return new RegExp(`^${regexPattern}$`, "i");
}
function shouldIncludeTool(ignorePatterns, toolName) {
  if (!ignorePatterns || ignorePatterns.length === 0) {
    return true;
  }
  for (const pattern of ignorePatterns) {
    const regex = patternToRegex(pattern);
    if (regex.test(toolName)) {
      return false;
    }
  }
  return true;
}

// src/lib/node-oauth-client-provider.ts
import open from "open";
import {
  OAuthClientInformationFullSchema as OAuthClientInformationFullSchema2,
  OAuthTokensSchema
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { sanitizeUrl } from "strict-url-sanitise";
import { randomUUID } from "node:crypto";
var NodeOAuthClientProvider = class {
  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(options) {
    this.options = options;
    this.serverUrlHash = options.serverUrlHash;
    this.callbackPath = options.callbackPath || "/oauth/callback";
    this.clientName = options.clientName || "MCP CLI Client";
    this.clientUri = options.clientUri || "https://github.com/modelcontextprotocol/mcp-cli";
    this.softwareId = options.softwareId || "2e6dc280-f3c3-4e01-99a7-8181dbd1d23d";
    this.softwareVersion = options.softwareVersion || version;
    this.staticOAuthClientMetadata = options.staticOAuthClientMetadata;
    this.staticOAuthClientInfo = options.staticOAuthClientInfo;
    this.authorizeResource = options.authorizeResource;
    this._state = randomUUID();
    this._clientInfo = void 0;
    this.authorizationServerMetadata = options.authorizationServerMetadata;
    this.protectedResourceMetadata = options.protectedResourceMetadata;
    this.wwwAuthenticateScope = options.wwwAuthenticateScope;
  }
  serverUrlHash;
  callbackPath;
  clientName;
  clientUri;
  softwareId;
  softwareVersion;
  staticOAuthClientMetadata;
  staticOAuthClientInfo;
  authorizeResource;
  _state;
  _clientInfo;
  authorizationServerMetadata;
  protectedResourceMetadata;
  wwwAuthenticateScope;
  get redirectUrl() {
    return `http://${this.options.host}:${this.options.callbackPort}${this.callbackPath}`;
  }
  get clientMetadata() {
    const effectiveScope = this.getEffectiveScope();
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      client_name: this.clientName,
      client_uri: this.clientUri,
      software_id: this.softwareId,
      software_version: this.softwareVersion,
      ...this.staticOAuthClientMetadata,
      scope: effectiveScope
    };
  }
  state() {
    return this._state;
  }
  /**
   * Gets the authorization server metadata, fetching it if not already available
   * @returns The authorization server metadata, or undefined if unavailable
   */
  async getAuthorizationServerMetadata() {
    debugLog(`authorizationServerMetadata: ${JSON.stringify(this.authorizationServerMetadata)}`);
    if (this.authorizationServerMetadata) {
      return this.authorizationServerMetadata;
    }
    try {
      this.authorizationServerMetadata = await fetchAuthorizationServerMetadata(this.options.serverUrl);
      if (this.authorizationServerMetadata?.scopes_supported) {
        debugLog("Authorization server supports scopes", {
          scopes_supported: this.authorizationServerMetadata.scopes_supported
        });
      }
      return this.authorizationServerMetadata;
    } catch (error) {
      debugLog("Failed to fetch authorization server metadata", error);
      return void 0;
    }
  }
  getEffectiveScope() {
    if (this.staticOAuthClientMetadata?.scope && this.staticOAuthClientMetadata.scope.trim().length > 0) {
      debugLog("Using scope from staticOAuthClientMetadata", { scope: this.staticOAuthClientMetadata.scope });
      return this.staticOAuthClientMetadata.scope;
    }
    if (this.wwwAuthenticateScope && this.wwwAuthenticateScope.trim().length > 0) {
      debugLog("Using scope from WWW-Authenticate header", { scope: this.wwwAuthenticateScope });
      return this.wwwAuthenticateScope;
    }
    if (this.protectedResourceMetadata?.scopes_supported?.length) {
      const scope = this.protectedResourceMetadata.scopes_supported.join(" ");
      debugLog("Using scopes from Protected Resource Metadata", {
        scopes_supported: this.protectedResourceMetadata.scopes_supported,
        scope
      });
      return scope;
    }
    if (this._clientInfo?.scope && this._clientInfo.scope.trim().length > 0) {
      debugLog("Using scope from client registration response", { scope: this._clientInfo.scope });
      return this._clientInfo.scope;
    }
    if (this.authorizationServerMetadata?.scopes_supported?.length) {
      const scope = this.authorizationServerMetadata.scopes_supported.join(" ");
      debugLog("Using scopes from Authorization Server Metadata", {
        scopes_supported: this.authorizationServerMetadata.scopes_supported,
        scope
      });
      return scope;
    }
    debugLog("Using fallback default scope");
    return "openid email profile";
  }
  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation() {
    debugLog("Reading client info");
    if (this.staticOAuthClientInfo) {
      debugLog("Returning static client info");
      this._clientInfo = this.staticOAuthClientInfo;
      return this.staticOAuthClientInfo;
    }
    const clientInfo = await readJsonFile(
      this.serverUrlHash,
      "client_info.json",
      OAuthClientInformationFullSchema2
    );
    if (clientInfo) {
      this._clientInfo = clientInfo;
    }
    debugLog("Client info result:", clientInfo ? "Found" : "Not found");
    return clientInfo;
  }
  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation) {
    debugLog("Saving client info", { client_id: clientInformation.client_id });
    this._clientInfo = clientInformation;
    await writeJsonFile(this.serverUrlHash, "client_info.json", clientInformation);
  }
  /**
   * Gets the OAuth tokens if they exist
   * @returns The OAuth tokens or undefined
   */
  async tokens() {
    debugLog("Reading OAuth tokens");
    debugLog("Token request stack trace:", new Error().stack);
    const tokens = await readJsonFile(this.serverUrlHash, "tokens.json", OAuthTokensSchema);
    if (tokens) {
      const timeLeft = tokens.expires_in || 0;
      if (typeof tokens.expires_in !== "number" || tokens.expires_in < 0) {
        debugLog("\u26A0\uFE0F WARNING: Invalid expires_in detected while reading tokens \u26A0\uFE0F", {
          expiresIn: tokens.expires_in,
          tokenObject: JSON.stringify(tokens),
          stack: new Error("Invalid expires_in value").stack
        });
      }
      debugLog("Token result:", {
        found: true,
        hasAccessToken: !!tokens.access_token,
        hasRefreshToken: !!tokens.refresh_token,
        expiresIn: `${timeLeft} seconds`,
        isExpired: timeLeft <= 0,
        expiresInValue: tokens.expires_in
      });
    } else {
      debugLog("Token result: Not found");
    }
    return tokens;
  }
  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  async saveTokens(tokens) {
    const timeLeft = tokens.expires_in || 0;
    if (typeof tokens.expires_in !== "number" || tokens.expires_in < 0) {
      debugLog("\u26A0\uFE0F WARNING: Invalid expires_in detected in tokens \u26A0\uFE0F", {
        expiresIn: tokens.expires_in,
        tokenObject: JSON.stringify(tokens),
        stack: new Error("Invalid expires_in value").stack
      });
    }
    debugLog("Saving tokens", {
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiresIn: `${timeLeft} seconds`,
      expiresInValue: tokens.expires_in
    });
    await writeJsonFile(this.serverUrlHash, "tokens.json", tokens);
  }
  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl) {
    this.getAuthorizationServerMetadata().catch(() => {
    });
    if (this.authorizeResource) {
      authorizationUrl.searchParams.set("resource", this.authorizeResource);
    }
    const effectiveScope = this.getEffectiveScope();
    authorizationUrl.searchParams.set("scope", effectiveScope);
    debugLog("Added scope parameter to authorization URL", { scopes: effectiveScope });
    log(`
Please authorize this client by visiting:
${authorizationUrl.toString()}
`);
    debugLog("Redirecting to authorization URL", authorizationUrl.toString());
    try {
      await open(sanitizeUrl(authorizationUrl.toString()));
      log("Browser opened automatically.");
    } catch (error) {
      log("Could not open browser automatically. Please copy and paste the URL above into your browser.");
      debugLog("Failed to open browser", error);
    }
  }
  /**
   * Saves the PKCE code verifier
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier) {
    debugLog("Saving code verifier");
    await writeTextFile(this.serverUrlHash, "code_verifier.txt", codeVerifier);
  }
  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier() {
    debugLog("Reading code verifier");
    const verifier = await readTextFile(this.serverUrlHash, "code_verifier.txt", "No code verifier saved for session");
    debugLog("Code verifier found:", !!verifier);
    return verifier;
  }
  /**
   * Invalidates the specified credentials
   * @param scope The scope of credentials to invalidate
   */
  async invalidateCredentials(scope) {
    debugLog(`Invalidating credentials: ${scope}`);
    switch (scope) {
      case "all":
        await Promise.all([
          deleteConfigFile(this.serverUrlHash, "client_info.json"),
          deleteConfigFile(this.serverUrlHash, "tokens.json"),
          deleteConfigFile(this.serverUrlHash, "code_verifier.txt")
        ]);
        this._clientInfo = void 0;
        debugLog("All credentials invalidated");
        break;
      case "client":
        await deleteConfigFile(this.serverUrlHash, "client_info.json");
        this._clientInfo = void 0;
        debugLog("Client information invalidated");
        break;
      case "tokens":
        await deleteConfigFile(this.serverUrlHash, "tokens.json");
        debugLog("OAuth tokens invalidated");
        break;
      case "verifier":
        await deleteConfigFile(this.serverUrlHash, "code_verifier.txt");
        debugLog("Code verifier invalidated");
        break;
      default:
        throw new Error(`Unknown credential scope: ${scope}`);
    }
  }
};

// src/lib/coordination.ts
import express2 from "express";
import { unlinkSync } from "fs";
async function isPidRunning(pid2) {
  try {
    process.kill(pid2, 0);
    debugLog(`Process ${pid2} is running`);
    return true;
  } catch (err) {
    debugLog(`Process ${pid2} is not running`, err);
    return false;
  }
}
async function isLockValid(lockData) {
  debugLog("Checking if lockfile is valid", lockData);
  const MAX_LOCK_AGE = 30 * 60 * 1e3;
  if (Date.now() - lockData.timestamp > MAX_LOCK_AGE) {
    log("Lockfile is too old");
    debugLog("Lockfile is too old", {
      age: Date.now() - lockData.timestamp,
      maxAge: MAX_LOCK_AGE
    });
    return false;
  }
  if (!await isPidRunning(lockData.pid)) {
    log("Process from lockfile is not running");
    debugLog("Process from lockfile is not running", { pid: lockData.pid });
    return false;
  }
  try {
    debugLog("Checking if endpoint is accessible", { port: lockData.port });
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1e3);
    const response = await fetch(`http://127.0.0.1:${lockData.port}/wait-for-auth?poll=false`, {
      signal: controller.signal
    });
    clearTimeout(timeout);
    const isValid = response.status === 200 || response.status === 202;
    debugLog(`Endpoint check result: ${isValid ? "valid" : "invalid"}`, { status: response.status });
    return isValid;
  } catch (error) {
    log(`Error connecting to auth server: ${error.message}`);
    debugLog("Error connecting to auth server", error);
    return false;
  }
}
async function waitForAuthentication(port) {
  log(`Waiting for authentication from the server on port ${port}...`);
  try {
    let attempts = 0;
    while (true) {
      attempts++;
      const url = `http://127.0.0.1:${port}/wait-for-auth`;
      log(`Querying: ${url}`);
      debugLog(`Poll attempt ${attempts}`);
      try {
        const response = await fetch(url);
        debugLog(`Poll response status: ${response.status}`);
        if (response.status === 200) {
          log(`Authentication completed by other instance`);
          return true;
        } else if (response.status === 202) {
          log(`Authentication still in progress`);
          debugLog(`Will retry in 1s`);
          await new Promise((resolve) => setTimeout(resolve, 1e3));
        } else {
          log(`Unexpected response status: ${response.status}`);
          return false;
        }
      } catch (fetchError) {
        debugLog(`Fetch error during poll`, fetchError);
        await new Promise((resolve) => setTimeout(resolve, 2e3));
      }
    }
  } catch (error) {
    log(`Error waiting for authentication: ${error.message}`);
    debugLog(`Error waiting for authentication`, error);
    return false;
  }
}
function createLazyAuthCoordinator(serverUrlHash, callbackPort, events, authTimeoutMs) {
  let authState = null;
  return {
    initializeAuth: async () => {
      if (authState) {
        debugLog("Auth already initialized, reusing existing state");
        return authState;
      }
      log("Initializing auth coordination on-demand");
      debugLog("Initializing auth coordination on-demand", { serverUrlHash, callbackPort });
      authState = await coordinateAuth(serverUrlHash, callbackPort, events, authTimeoutMs);
      debugLog("Auth coordination completed", { skipBrowserAuth: authState.skipBrowserAuth });
      return authState;
    }
  };
}
async function coordinateAuth(serverUrlHash, callbackPort, events, authTimeoutMs) {
  debugLog("Coordinating authentication", { serverUrlHash, callbackPort });
  const lockData = process.platform === "win32" ? null : await checkLockfile(serverUrlHash);
  if (process.platform === "win32") {
    debugLog("Skipping lockfile check on Windows");
  } else {
    debugLog("Lockfile check result", { found: !!lockData, lockData });
  }
  if (lockData && await isLockValid(lockData)) {
    log(`Another instance is handling authentication on port ${lockData.port} (pid: ${lockData.pid})`);
    try {
      debugLog("Waiting for authentication from other instance");
      const authCompleted = await waitForAuthentication(lockData.port);
      if (authCompleted) {
        log("Authentication completed by another instance. Using tokens from disk");
        const dummyServer = express2().listen(0);
        const dummyPort = dummyServer.address().port;
        debugLog("Started dummy server", { port: dummyPort });
        const dummyWaitForAuthCode = () => {
          log("WARNING: waitForAuthCode called in secondary instance - this is unexpected");
          return new Promise(() => {
          });
        };
        return {
          server: dummyServer,
          waitForAuthCode: dummyWaitForAuthCode,
          skipBrowserAuth: true
        };
      } else {
        log("Taking over authentication process...");
      }
    } catch (error) {
      log(`Error waiting for authentication: ${error}`);
      debugLog("Error waiting for authentication", error);
    }
    debugLog("Other instance did not complete auth successfully, deleting lockfile");
    await deleteLockfile(serverUrlHash);
  } else if (lockData) {
    log("Found invalid lockfile, deleting it");
    await deleteLockfile(serverUrlHash);
  }
  debugLog("Setting up OAuth callback server", { port: callbackPort });
  const { server, waitForAuthCode, authCompletedPromise } = setupOAuthCallbackServerWithLongPoll({
    port: callbackPort,
    path: "/oauth/callback",
    events,
    authTimeoutMs
  });
  let address = server.address();
  if (!address) {
    await new Promise((resolve) => server.once("listening", resolve));
    address = server.address();
  }
  if (!address) {
    throw new Error("Failed to get server address after listening event");
  }
  const actualPort = address.port;
  debugLog("OAuth callback server running", { port: actualPort });
  log(`Creating lockfile for server ${serverUrlHash} with process ${process.pid} on port ${actualPort}`);
  await createLockfile(serverUrlHash, process.pid, actualPort);
  const cleanupHandler = async () => {
    try {
      log(`Cleaning up lockfile for server ${serverUrlHash}`);
      await deleteLockfile(serverUrlHash);
    } catch (error) {
      log(`Error cleaning up lockfile: ${error}`);
      debugLog("Error cleaning up lockfile", error);
    }
  };
  process.once("exit", () => {
    try {
      const configPath = getConfigFilePath(serverUrlHash, "lock.json");
      unlinkSync(configPath);
      debugLog(`Removed lockfile on exit: ${configPath}`);
    } catch (error) {
      debugLog(`Error removing lockfile on exit:`, error);
    }
  });
  process.once("SIGINT", async () => {
    debugLog("Received SIGINT signal, cleaning up");
    await cleanupHandler();
  });
  debugLog("Auth coordination complete, returning primary instance handlers");
  return {
    server,
    waitForAuthCode,
    skipBrowserAuth: false
  };
}

export {
  version,
  debugLog,
  log,
  mcpProxy,
  discoverOAuthServerInfo,
  connectToRemoteServer,
  parseCommandLineArgs,
  setupSignalHandlers,
  NodeOAuthClientProvider,
  createLazyAuthCoordinator
};
