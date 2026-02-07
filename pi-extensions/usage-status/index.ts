import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Type } from "@sinclair/typebox";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

interface RateLimitWindow {
  used_percent: number;
  limit_window_seconds: number;
  reset_after_seconds: number;
}

interface OpenAIUsageResponse {
  plan_type: string;
  rate_limit: {
    limit_reached: boolean;
    primary_window: RateLimitWindow;
    secondary_window: RateLimitWindow | null;
  } | null;
}

interface JwtPayload {
  "https://api.openai.com/profile"?: {
    email?: string;
  };
  "https://api.openai.com/auth"?: {
    chatgpt_account_id?: string;
  };
}

interface CodexStatusConfig {
  accessToken: string;
}

interface OpenCodeAuthData {
  openai?: {
    type?: string;
    access?: string;
    expires?: number;
  };
  "zai-coding-plan"?: {
    type?: string;
    key?: string;
  };
}

interface ZaiUsageLimitItem {
  type: "TIME_LIMIT" | "TOKENS_LIMIT";
  usage: number;
  currentValue: number;
  percentage: number;
  nextResetTime?: number;
}

interface ZaiQuotaLimitResponse {
  code: number;
  msg: string;
  success: boolean;
  data: {
    limits: ZaiUsageLimitItem[];
  };
}

const OPENAI_USAGE_URL = "https://chatgpt.com/backend-api/wham/usage";
const ZAI_USAGE_URL = "https://api.z.ai/api/monitor/usage/quota/limit";
const CONFIG_PATH = join(homedir(), ".pi", "agent", "codex-status.json");
const OPENCODE_AUTH_PATH = join(homedir(), ".local", "share", "opencode", "auth.json");
const REQUEST_TIMEOUT_MS = 10000;

function base64UrlDecode(input: string): string {
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (base64.length % 4)) % 4;
  const padded = base64 + "=".repeat(padLen);
  return Buffer.from(padded, "base64").toString("utf8");
}

function parseJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payloadJson = base64UrlDecode(parts[1]);
    return JSON.parse(payloadJson) as JwtPayload;
  } catch {
    return null;
  }
}

function getEmailFromJwt(token: string): string | null {
  const payload = parseJwt(token);
  return payload?.["https://api.openai.com/profile"]?.email ?? null;
}

function getAccountIdFromJwt(token: string): string | null {
  const payload = parseJwt(token);
  return payload?.["https://api.openai.com/auth"]?.chatgpt_account_id ?? null;
}

function maskEmail(email: string): string {
  const [local, domain] = email.split("@");
  if (!domain) return email;

  const visibleStart = local.slice(0, 2);
  const visibleEnd = local.slice(-1);
  const masked = `${visibleStart}****${visibleEnd}`;
  return `${masked}@${domain}`;
}

function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0 || parts.length === 0) parts.push(`${minutes}m`);

  return parts.join(" ");
}

function createProgressBar(remainPercent: number, width: number = 30): string {
  const safePercent = Math.max(0, Math.min(100, remainPercent));
  const filled = Math.round((safePercent / 100) * width);
  const empty = width - filled;
  return "█".repeat(filled) + "░".repeat(empty);
}

function formatWindow(window: RateLimitWindow): string[] {
  const hours = Math.round(window.limit_window_seconds / 3600);
  const windowName = hours >= 24 ? `${Math.round(hours / 24)}-day limit` : `${hours}-hour limit`;
  const remainPercent = Math.round(100 - window.used_percent);
  const progressBar = createProgressBar(remainPercent);
  const resetTime = formatDuration(window.reset_after_seconds);

  return [windowName, `${progressBar} ${remainPercent}% remaining`, `Resets in: ${resetTime}`];
}

async function fetchWithTimeout(url: string, options: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

async function readConfigAccessToken(): Promise<string | null> {
  try {
    const content = await readFile(CONFIG_PATH, "utf-8");
    const config = JSON.parse(content) as CodexStatusConfig;

    if (!config.accessToken) {
      throw new Error("Missing accessToken in codex-status.json");
    }

    return config.accessToken;
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return null;
    }

    throw error instanceof Error ? error : new Error("Failed to read codex-status.json");
  }
}

async function readOpenCodeAccessToken(): Promise<string | null> {
  try {
    const content = await readFile(OPENCODE_AUTH_PATH, "utf-8");
    const auth = JSON.parse(content) as OpenCodeAuthData;
    const openai = auth.openai;

    if (!openai || openai.type !== "oauth" || !openai.access) {
      return null;
    }

    if (openai.expires && openai.expires < Date.now()) {
      throw new Error("OpenCode OAuth token expired");
    }

    return openai.access;
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return null;
    }

    throw error instanceof Error ? error : new Error("Failed to read OpenCode auth.json");
  }
}

async function loadAccessToken(): Promise<string> {
  if (process.env.OPENAI_CHATGPT_TOKEN) {
    return process.env.OPENAI_CHATGPT_TOKEN;
  }

  const configToken = await readConfigAccessToken();
  if (configToken) {
    return configToken;
  }

  const opencodeToken = await readOpenCodeAccessToken();
  if (opencodeToken) {
    return opencodeToken;
  }

  throw new Error("No ChatGPT OAuth access token found");
}

async function fetchOpenAIUsage(accessToken: string): Promise<OpenAIUsageResponse> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${accessToken}`,
    "User-Agent": "pi-codex-status/1.0",
  };

  const accountId = getAccountIdFromJwt(accessToken);
  if (accountId) {
    headers["ChatGPT-Account-Id"] = accountId;
  }

  const response = await fetchWithTimeout(OPENAI_USAGE_URL, { headers });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`OpenAI usage API error (${response.status}): ${errorText}`);
  }

  return response.json() as Promise<OpenAIUsageResponse>;
}

function formatOpenAIUsage(data: OpenAIUsageResponse, email: string | null): string {
  const { plan_type, rate_limit } = data;
  const lines: string[] = [];

  const accountEmail = email ? maskEmail(email) : "unknown";
  lines.push(`Account:        ${accountEmail} (${plan_type})`);
  lines.push("");

  if (rate_limit?.primary_window) {
    lines.push(...formatWindow(rate_limit.primary_window));
  }

  if (rate_limit?.secondary_window) {
    lines.push("");
    lines.push(...formatWindow(rate_limit.secondary_window));
  }

  if (rate_limit?.limit_reached) {
    lines.push("");
    lines.push("Limit reached.");
  }

  return lines.join("\n");
}

async function readOpenCodeZaiApiKey(): Promise<string | null> {
  try {
    const content = await readFile(OPENCODE_AUTH_PATH, "utf-8");
    const auth = JSON.parse(content) as OpenCodeAuthData;
    const zai = auth["zai-coding-plan"];

    if (!zai || !zai.key) {
      return null;
    }

    return zai.key;
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return null;
    }

    throw error instanceof Error ? error : new Error("Failed to read OpenCode auth.json");
  }
}

async function loadZaiApiKey(): Promise<string> {
  // Priority: env first, then OpenCode auth.json
  const envKey = process.env.ZAI_API_KEY || process.env.ZAI_TOKEN;
  if (envKey) return envKey;

  const opencodeKey = await readOpenCodeZaiApiKey();
  if (opencodeKey) return opencodeKey;

  throw new Error("No Z.ai API key found (set ZAI_API_KEY or configure zai-coding-plan in OpenCode auth.json)");
}

async function fetchZaiUsage(apiKey: string): Promise<ZaiQuotaLimitResponse> {
  const headers: Record<string, string> = {
    Authorization: apiKey,
    "Content-Type": "application/json",
    "User-Agent": "pi-codex-status/1.0",
  };

  const response = await fetchWithTimeout(ZAI_USAGE_URL, { headers });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Z.ai usage API error (${response.status}): ${errorText}`);
  }

  return response.json() as Promise<ZaiQuotaLimitResponse>;
}

function formatZaiUsage(data: ZaiQuotaLimitResponse): string {
  if (!data.success || data.code !== 200) {
    throw new Error(`Z.ai API error (${data.code}): ${data.msg || "Unknown error"}`);
  }

  const limits = data.data?.limits ?? [];
  const tokenLimit = limits.find((l) => l.type === "TOKENS_LIMIT");

  if (!tokenLimit) {
    throw new Error("Missing TOKENS_LIMIT in Z.ai usage response");
  }

  // Try to mimic OpenAI output format as closely as possible
  const lines: string[] = [];

  // No email available for API-key auth; display masked key-like identifier if provided via OpenCode
  lines.push(`Account:        z.ai (plus)`);
  lines.push("");

  const remainPercent = Math.max(0, Math.min(100, Math.round(100 - tokenLimit.percentage)));

  let resetAfterSeconds = 0;
  if (typeof tokenLimit.nextResetTime === "number") {
    resetAfterSeconds = Math.max(0, Math.round((tokenLimit.nextResetTime - Date.now()) / 1000));
  }

  const progressBar = createProgressBar(remainPercent);
  lines.push("5-hour limit");
  lines.push(`${progressBar} ${remainPercent}% remaining`);
  lines.push(`Resets in: ${formatDuration(resetAfterSeconds)}`);

  // If Z.ai includes additional windows, attempt to map them heuristically
  // (e.g. TIME_LIMIT could correspond to a longer window; we only show it if it looks like a window percentage)
  const otherLimits = limits.filter((l) => l.type !== "TOKENS_LIMIT");
  if (otherLimits.length > 0) {
    const bestOther = otherLimits.reduce((a, b) => (a.usage > b.usage ? a : b));
    const otherRemain = Math.max(0, Math.min(100, Math.round(100 - bestOther.percentage)));
    // We don't know the true duration; label generically as "additional limit"
    lines.push("");
    lines.push("Additional limit");
    lines.push(`${createProgressBar(otherRemain)} ${otherRemain}% remaining`);
  }

  return lines.join("\n");
}

type UsageProvider = "zai" | "openai";

function getProviderFromModelId(modelId: string | undefined): UsageProvider {
  const id = (modelId || "").toLowerCase().trim();

  // Z.ai models: user says they start with "glm" (e.g. glm-4.5, glm-4.5-air)
  if (id.startsWith("glm")) return "zai";

  // Fallback heuristics
  if (id.includes("z.ai") || id.startsWith("zai/") || id.startsWith("z.ai/")) return "zai";

  // Codex/OpenAI models typically start with "gpt"
  if (id.startsWith("gpt")) return "openai";

  return "openai";
}

async function getUsageStatus(provider: UsageProvider): Promise<string> {
  if (provider === "zai") {
    const apiKey = await loadZaiApiKey();
    const usage = await fetchZaiUsage(apiKey);
    return ["Provider: Z.ai", "", formatZaiUsage(usage)].join("\n");
  }

  const token = await loadAccessToken();
  const email = getEmailFromJwt(token);
  const usage = await fetchOpenAIUsage(token);
  return ["Provider: OpenAI/Codex", "", formatOpenAIUsage(usage, email)].join("\n");
}

function formatConfigHint(error: Error): string {
  return [
    `Failed to load usage: ${error.message}`,
    "",
    "Z.ai (preferred):",
    "- Environment variable: ZAI_API_KEY (or ZAI_TOKEN)",
    `- OpenCode auth file: ${OPENCODE_AUTH_PATH} (key: zai-coding-plan.key)`,
    "",
    "OpenAI/Codex (fallback):",
    "Provide a ChatGPT OAuth access token via one of:",
    `- Environment variable: OPENAI_CHATGPT_TOKEN`,
    `- Config file: ${CONFIG_PATH}`,
    "  {",
    "    \"accessToken\": \"<chatgpt-oauth-access-token>\"",
    "  }",
    `- OpenCode auth file: ${OPENCODE_AUTH_PATH}`,
  ].join("\n");
}

export default function registerCodexStatus(pi: ExtensionAPI) {
  pi.registerTool({
    name: "usage_status",
    label: "Usage status",
    description:
      "Check usage limits for the configured provider (Z.ai preferred, OpenAI/Codex fallback).",
    parameters: Type.Object({}),
    async execute() {
      try {
        const output = await getUsageStatus(getProviderFromModelId((pi as any).context?.model?.id));
        return {
          content: [{ type: "text", text: output }],
          details: { output },
        };
      } catch (error) {
        const message = formatConfigHint(error as Error);
        return {
          content: [{ type: "text", text: message }],
          details: { error: message },
          isError: true,
        };
      }
    },
  });

  pi.registerCommand("usage", {
    description: "Show usage limits (Z.ai preferred, OpenAI/Codex fallback)",
    handler: async (_args, ctx) => {
      try {
        const output = await getUsageStatus(getProviderFromModelId((ctx as any).model?.id));
        pi.sendMessage({
          customType: "usage-status",
          content: output,
          display: true,
        });
        if (ctx.hasUI) {
          ctx.ui.notify("Usage status fetched", "info");
        }
      } catch (error) {
        const message = formatConfigHint(error as Error);
        pi.sendMessage({
          customType: "usage-status",
          content: message,
          display: true,
        });
        if (ctx.hasUI) {
          ctx.ui.notify("Failed to fetch usage status", "error");
        }
      }
    },
  });
}
