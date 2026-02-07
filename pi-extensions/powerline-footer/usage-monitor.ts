import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { CodexUsageSummary } from "./types.js";

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

function getAccountIdFromJwt(token: string): string | null {
  const payload = parseJwt(token);
  return payload?.["https://api.openai.com/auth"]?.chatgpt_account_id ?? null;
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

function normalizeZaiWindows(data: ZaiQuotaLimitResponse): {
  remainingPercent: number;
  resetAfterSeconds: number;
  limitReached: boolean;
  planType: string;
  weeklyRemainingPercent?: number;
  weeklyResetAfterSeconds?: number;
} {
  if (!data.success || data.code !== 200) {
    throw new Error(`Z.ai API error (${data.code}): ${data.msg || "Unknown error"}`);
  }

  const limits = data.data?.limits ?? [];
  const tokenLimit = limits.find((l) => l.type === "TOKENS_LIMIT");

  if (!tokenLimit) {
    throw new Error("Missing TOKENS_LIMIT in Z.ai usage response");
  }

  const remainingPercent = Math.max(0, Math.min(100, 100 - tokenLimit.percentage));

  let resetAfterSeconds = 0;
  if (typeof tokenLimit.nextResetTime === "number") {
    resetAfterSeconds = Math.max(0, Math.round((tokenLimit.nextResetTime - Date.now()) / 1000));
  }

  const maxUsedPercent = limits.reduce((acc, l) => Math.max(acc, l.percentage ?? 0), 0);
  const limitReached = maxUsedPercent >= 100;

  return {
    remainingPercent,
    resetAfterSeconds,
    limitReached,
    planType: "z.ai",
    // weekly* currently not known for z.ai, leave undefined
  };
}

export async function fetchZaiUsageSummary(): Promise<CodexUsageSummary> {
  const key = await loadZaiApiKey();
  const usage = await fetchZaiUsage(key);
  const normalized = normalizeZaiWindows(usage);

  return {
    remainingPercent: normalized.remainingPercent,
    resetAfterSeconds: normalized.resetAfterSeconds,
    limitReached: normalized.limitReached,
    planType: normalized.planType,
    weeklyRemainingPercent: normalized.weeklyRemainingPercent,
    weeklyResetAfterSeconds: normalized.weeklyResetAfterSeconds,
  };
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

export async function fetchCodexUsageSummary(): Promise<CodexUsageSummary> {
  const token = await loadAccessToken();
  const usage = await fetchOpenAIUsage(token);
  const primaryWindow = usage.rate_limit?.primary_window;
  const secondaryWindow = usage.rate_limit?.secondary_window ?? null;

  if (!primaryWindow) {
    throw new Error("Missing rate limit window in OpenAI usage response");
  }

  const remainingPercent = Math.max(0, Math.min(100, 100 - primaryWindow.used_percent));
  const weeklyRemainingPercent = secondaryWindow
    ? Math.max(0, Math.min(100, 100 - secondaryWindow.used_percent))
    : undefined;

  return {
    remainingPercent,
    resetAfterSeconds: primaryWindow.reset_after_seconds,
    limitReached: usage.rate_limit?.limit_reached ?? false,
    planType: usage.plan_type,
    weeklyRemainingPercent,
    weeklyResetAfterSeconds: secondaryWindow?.reset_after_seconds,
  };
}
