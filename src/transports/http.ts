import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import cors from "cors";
import express from "express";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  authenticateHttpRequest,
  cleanupAllClients,
  startClientCacheCleanup,
  stopClientCacheCleanup,
} from "../auth/http.js";
import type { SessionData } from "../auth/types.js";
import { getSessionConfig } from "../config/session-config.js";
import type { TransportConfig } from "../config/transport.js";
import { PACKAGE_NAME, VERSION } from "../constants.js";
import { SessionManager } from "../session/session-manager.js";

// Unified session management
export const sessionManager = new SessionManager();

// Configuration - loaded from environment
const sessionConfig = getSessionConfig();
const CLEANUP_INTERVAL = sessionConfig.CLEANUP_INTERVAL;

/**
 * Start periodic cleanup of expired sessions
 */
let cleanupTimer: Timer | null = null;

function startSessionCacheCleanup(): void {
  if (cleanupTimer) return; // Already started

  cleanupTimer = setInterval(() => {
    sessionManager.cleanupExpired();
  }, CLEANUP_INTERVAL);

  console.error('[Session Cache] Started periodic cleanup');
}

/**
 * Stop periodic cleanup (for graceful shutdown)
 */
function stopSessionCacheCleanup(): void {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
    console.error('[Session Cache] Stopped periodic cleanup');
  }
}

export async function setupHttpTransport(
  server: McpServer,
  config: Extract<TransportConfig, { transportType: "http" }>
) {
  const app = express();

  // CORS with MCP-required headers
  app.use(
    cors({
      origin: "*",
      exposedHeaders: ["Mcp-Session-Id"],
      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "Mcp-Session-Id",
        "Last-Event-ID",
      ],
      methods: ["GET", "POST", "DELETE", "OPTIONS"],
    })
  );

  app.use(express.json({limit: "4mb"}));

  // Health check endpoint
  app.get("/", (req, res) => {
    res.json({
      name: PACKAGE_NAME,
      version: VERSION,
      transport: "http",
      activeSessions: sessionManager.getSessionCount(),
    });
  });

  // Favicon for Claude connector icon
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const faviconPath = join(__dirname, "assets", "favicon.ico");
  console.error(`[Favicon] Serving from: ${faviconPath}`);
  app.get("/favicon.ico", (req, res) => {
    res.sendFile(faviconPath, (err) => {
      if (err) {
        console.error(`[Favicon] Error serving favicon:`, err);
        res.status(404).send("Favicon not found");
      }
    });
  });

  // OAuth2 endpoints for Claude connector authentication
  // GET /authorize - OAuth authorization endpoint (redirects back with code)
  app.get("/authorize", (req, res) => {
    const { redirect_uri, state } = req.query;
    if (!redirect_uri) {
      res.status(400).json({ error: "redirect_uri required" });
      return;
    }
    // Generate a simple auth code and redirect back
    const code = randomUUID();
    const redirectUrl = new URL(redirect_uri as string);
    redirectUrl.searchParams.set("code", code);
    if (state) redirectUrl.searchParams.set("state", state as string);
    console.error(`[OAuth] Redirecting to ${redirectUrl.toString()}`);
    res.redirect(redirectUrl.toString());
  });

  // POST /token - OAuth token endpoint (validates client_secret, returns access_token)
  // Security model: client_secret == API_KEY, and access_token == API_KEY
  // The MCP endpoint validates Bearer token matches API_KEY
  app.post("/token", express.urlencoded({ extended: true }), (req, res) => {
    const { client_id, client_secret, code, grant_type } = req.body;
    const apiKey = process.env.API_KEY;

    // Validate grant_type
    if (grant_type !== "authorization_code") {
      console.error(`[OAuth] Unsupported grant_type: ${grant_type}`);
      res.status(400).json({ error: "unsupported_grant_type", error_description: "Only authorization_code is supported" });
      return;
    }

    if (!apiKey) {
      console.error("[OAuth] API_KEY not configured");
      res.status(500).json({ error: "server_error", error_description: "API_KEY not configured" });
      return;
    }

    // Validate client_secret matches API_KEY
    if (client_secret !== apiKey) {
      console.error("[OAuth] Invalid client_secret");
      res.status(401).json({ error: "invalid_client", error_description: "Invalid client credentials" });
      return;
    }

    // Return access token - we use the API_KEY as the access_token
    // This is validated in authenticateHttpRequest when Bearer token is received
    console.error(`[OAuth] Token issued for client_id: ${client_id}`);
    res.json({
      access_token: apiKey,
      token_type: "Bearer",
      expires_in: 86400
    });
  });

  // MCP endpoint - POST for client requests
  app.post(config.httpStream.endpoint, async (req, res) => {
    try {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;
      let transport: StreamableHTTPServerTransport;
      let sessionData: SessionData;

      // Check for existing session
      if (sessionId && sessionManager.hasSession(sessionId)) {
        console.error(`[Transport] Reusing session ${sessionId}`);
        transport = sessionManager.getTransport(sessionId)!;
        sessionData = sessionManager.getSessionData(sessionId)!;
      } else if (sessionId && !sessionManager.hasSession(sessionId)) {
        // Session ID provided but expired/invalid
        console.error(`[Transport] Session ${sessionId} expired or invalid`);
        res.status(404).json({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: "Session expired or invalid",
          },
          id: null,
        });
        return;
      } else if (!sessionId && isInitializeRequest(req.body)) {
        // New initialization request
        console.error(`[Transport] New initialization request`);

        // Authenticate and get/create cached client
        const authHeader = req.headers["authorization"];
        sessionData = await authenticateHttpRequest(
          Array.isArray(authHeader) ? authHeader[0] : authHeader
        );

        // Create new transport
        // Allow custom hosts via ALLOWED_HOSTS env var (comma-separated)
        const customHosts = process.env.ALLOWED_HOSTS?.split(',').map(h => h.trim()).filter(Boolean) || [];
        const defaultHosts = [
          "127.0.0.1",
          "localhost",
          `127.0.0.1:${config.httpStream.port}`,
          `localhost:${config.httpStream.port}`,
        ];
        transport = new StreamableHTTPServerTransport({
          enableDnsRebindingProtection: true,
          allowedHosts: [...defaultHosts, ...customHosts],
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newSessionId) => {
            console.error(`[Transport] Session initialized: ${newSessionId}`);

            // Store in SessionManager
            sessionManager.createSession(newSessionId, transport, sessionData);
          },
        });

        // Set up cleanup on close
        transport.onclose = () => {
          const sid = transport.sessionId;
          if (sid) {
            console.error(`[Transport] Transport closed for session ${sid}`);
            sessionManager.removeSession(sid);
          }
        };

        // Connect transport to server
        await server.connect(transport);
        console.error(`[Transport] Connected new transport to MCP server`);
      } else {
        // Invalid request - no session ID and not an initialization request
        console.error("[Transport] Invalid request: missing session or not initialization");
        res.status(400).json({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: "Bad Request: No valid session ID provided",
          },
          id: null,
        });
        return;
      }

      // Handle the request with the transport
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      console.error("[HTTP transport] Error:", error);

      if (!res.headersSent) {
        res.status(401).json({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: "Authentication failed",
          },
          id: null,
        });
      }
    }
  });

  // MCP endpoint - GET for SSE (Server-Sent Events)
  app.get(config.httpStream.endpoint, async (req, res) => {
    try {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      if (!sessionId || !sessionManager.hasSession(sessionId)) {
        console.error(`[Transport] Invalid session ID in GET request: ${sessionId}`);
        res.status(400).send("Invalid or missing session ID");
        return;
      }

      const session = sessionManager.getSession(sessionId);
      if (!session) {
        console.error(`[Transport] Session ${sessionId} expired during GET`);
        res.status(404).send("Session expired");
        return;
      }

      const lastEventId = req.headers["last-event-id"] as string | undefined;
      if (lastEventId) {
        console.error(`[Transport] SSE reconnection with Last-Event-ID: ${lastEventId}`);
      } else {
        console.error(`[Transport] New SSE stream for session ${sessionId}`);
      }

      // Handle SSE stream
      try {
        await session.transport.handleRequest(req, res);
      } catch (err) {
        console.error(`[Transport] Error handling SSE request for session ${sessionId}:`, err);
        throw err; // Re-throw to outer error handler
      }
    } catch (error) {
      console.error("[HTTP transport] Error in GET handler:", error);
      if (!res.headersSent) {
        res.status(500).send("Internal server error");
      }
    }
  });

  // MCP endpoint - DELETE for session termination
  app.delete(config.httpStream.endpoint, async (req, res) => {
    try {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      if (!sessionId || !sessionManager.hasSession(sessionId)) {
        console.error(`[Transport] Invalid session ID in DELETE request: ${sessionId}`);
        res.status(400).send("Invalid or missing session ID");
        return;
      }

      console.error(`[Transport] Session termination request for ${sessionId}`);
      const session = sessionManager.getSession(sessionId);

      if (session) {
        try {
          await session.transport.handleRequest(req, res);
          // Note: The transport's onclose callback will handle cleanup via SessionManager
        } catch (err) {
          console.error(`[Transport] Error handling DELETE request for session ${sessionId}:`, err);
          throw err; // Re-throw to outer error handler
        }
      }
    } catch (error) {
      console.error("[HTTP transport] Error in DELETE handler:", error);
      if (!res.headersSent) {
        res.status(500).send("Error processing session termination");
      }
    }
  });

  const {port} = config.httpStream;

  // Start cleanup timers
  startClientCacheCleanup();
  startSessionCacheCleanup();

  // Graceful shutdown handlers
  const shutdown = async () => {
    console.error("\n[HTTP transport] Shutting down gracefully...");

    // Stop cleanup timers
    stopClientCacheCleanup();
    stopSessionCacheCleanup();

    // Cleanup all sessions
    sessionManager.cleanupAll();

    // Cleanup all clients
    cleanupAllClients();

    console.error("[HTTP transport] Shutdown complete");
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  return new Promise<void>((resolve, reject) => {
    app
      .listen(port, () => {
        console.error(`HTTP transport listening on port ${port}`);
        console.error(
          `MCP endpoint: http://localhost:${port}${config.httpStream.endpoint}`
        );
        resolve();
      })
      .on("error", reject);
  });
}
