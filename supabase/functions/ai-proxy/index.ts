// AI provider proxy.
//
// Browsers cannot call most LLM vendor APIs directly (no CORS headers on
// api.anthropic.com, api.cohere.com, api.deepseek.com, ...), which surfaced in
// the UI as the opaque "Failed to fetch". This function performs the vendor
// call server-side and returns a normalised JSON shape.
//
// Keys are supplied per request by the caller, used once, and never persisted
// or logged.

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

type Action = "test" | "models" | "chat";

interface ModelOption {
  id: string;
  name: string;
  description?: string;
  available: boolean;
  contextWindow?: number;
}

interface ProxyRequest {
  action: Action;
  provider: string;
  apiKey?: string;
  model?: string;
  prompt?: string;
  messages?: { role: string; content: string }[];
  maxTokens?: number;
  temperature?: number;
}

const REQUEST_TIMEOUT_MS = 60_000;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

async function vendorFetch(url: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** Never echo key material back to the client or into logs. */
function safeError(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  if (msg.includes("aborted") || msg.includes("AbortError")) {
    return "The provider did not respond in time. Please try again.";
  }
  return msg.replace(/(sk-|key-|xai-|gsk_|sk-ant-)[A-Za-z0-9_\-]{8,}/g, "[redacted]");
}

const titleCase = (id: string) =>
  id.replace(/[-_]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

async function readError(res: Response): Promise<string> {
  const text = await res.text();
  try {
    const parsed = JSON.parse(text);
    const msg =
      parsed?.error?.message ?? parsed?.error ?? parsed?.message ?? parsed?.detail ?? text;
    return `${res.status}: ${typeof msg === "string" ? msg : JSON.stringify(msg)}`;
  } catch {
    return `${res.status}: ${text.slice(0, 400)}`;
  }
}

// ---------------------------------------------------------------------------
// Provider adapters
// ---------------------------------------------------------------------------

interface Adapter {
  listModels(apiKey: string): Promise<ModelOption[]>;
  chat(
    apiKey: string,
    model: string,
    messages: { role: string; content: string }[],
    maxTokens: number,
    temperature: number,
  ): Promise<{ text: string; usage?: Record<string, number> }>;
}

/** OpenAI-compatible providers (OpenAI, DeepSeek, Groq, Mistral, xAI, OpenRouter, Together). */
function openAiCompatible(
  baseUrl: string,
  opts: { filter?: (id: string) => boolean; extraHeaders?: Record<string, string> } = {},
): Adapter {
  const headers = (apiKey: string) => ({
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
    ...(opts.extraHeaders ?? {}),
  });

  return {
    async listModels(apiKey) {
      const res = await vendorFetch(`${baseUrl}/models`, {
        method: "GET",
        headers: headers(apiKey),
      });
      if (!res.ok) throw new Error(await readError(res));
      const data = await res.json();
      const list: any[] = data.data ?? data.models ?? [];
      return list
        .map((m) => (typeof m === "string" ? { id: m } : m))
        .filter((m) => m?.id && (opts.filter ? opts.filter(m.id) : true))
        .map((m) => ({
          id: m.id,
          name: m.name ?? m.id,
          description: m.description ?? undefined,
          contextWindow: m.context_length ?? m.context_window ?? undefined,
          available: true,
        }))
        .sort((a, b) => a.id.localeCompare(b.id));
    },
    async chat(apiKey, model, messages, maxTokens, temperature) {
      const body: Record<string, unknown> = { model, messages };
      // The GPT-5 / o-series families reject max_tokens and custom temperature.
      if (/^(gpt-5|o[1-9])/.test(model)) {
        body.max_completion_tokens = maxTokens;
      } else {
        body.max_tokens = maxTokens;
        body.temperature = temperature;
      }
      const res = await vendorFetch(`${baseUrl}/chat/completions`, {
        method: "POST",
        headers: headers(apiKey),
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(await readError(res));
      const data = await res.json();
      return {
        text: data.choices?.[0]?.message?.content ?? "",
        usage: {
          promptTokens: data.usage?.prompt_tokens ?? 0,
          completionTokens: data.usage?.completion_tokens ?? 0,
          totalTokens: data.usage?.total_tokens ?? 0,
        },
      };
    },
  };
}

const anthropicAdapter: Adapter = {
  async listModels(apiKey) {
    const res = await vendorFetch("https://api.anthropic.com/v1/models?limit=100", {
      method: "GET",
      headers: {
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
      },
    });
    if (!res.ok) throw new Error(await readError(res));
    const data = await res.json();
    return (data.data ?? []).map((m: any) => ({
      id: m.id,
      name: m.display_name ?? m.id,
      contextWindow: 200000,
      available: true,
    }));
  },
  async chat(apiKey, model, messages, maxTokens, temperature) {
    const system = messages.filter((m) => m.role === "system").map((m) => m.content).join("\n\n");
    const turns = messages.filter((m) => m.role !== "system");
    const res = await vendorFetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        ...(system ? { system } : {}),
        messages: turns,
        max_tokens: maxTokens,
        temperature,
      }),
    });
    if (!res.ok) throw new Error(await readError(res));
    const data = await res.json();
    return {
      text: (data.content ?? [])
        .filter((c: any) => c.type === "text")
        .map((c: any) => c.text)
        .join(""),
      usage: {
        promptTokens: data.usage?.input_tokens ?? 0,
        completionTokens: data.usage?.output_tokens ?? 0,
        totalTokens: (data.usage?.input_tokens ?? 0) + (data.usage?.output_tokens ?? 0),
      },
    };
  },
};

const googleAdapter: Adapter = {
  async listModels(apiKey) {
    const res = await vendorFetch(
      `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(apiKey)}&pageSize=200`,
      { method: "GET" },
    );
    if (!res.ok) throw new Error(await readError(res));
    const data = await res.json();
    return (data.models ?? [])
      .filter((m: any) => (m.supportedGenerationMethods ?? []).includes("generateContent"))
      .map((m: any) => ({
        id: String(m.name).replace(/^models\//, ""),
        name: m.displayName ?? m.name,
        description: m.description,
        contextWindow: m.inputTokenLimit,
        available: true,
      }));
  },
  async chat(apiKey, model, messages, maxTokens, temperature) {
    const system = messages.filter((m) => m.role === "system").map((m) => m.content).join("\n\n");
    const contents = messages
      .filter((m) => m.role !== "system")
      .map((m) => ({
        role: m.role === "assistant" ? "model" : "user",
        parts: [{ text: m.content }],
      }));
    const res = await vendorFetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents,
          ...(system ? { systemInstruction: { parts: [{ text: system }] } } : {}),
          generationConfig: { temperature, maxOutputTokens: maxTokens },
        }),
      },
    );
    if (!res.ok) throw new Error(await readError(res));
    const data = await res.json();
    return {
      text: (data.candidates?.[0]?.content?.parts ?? []).map((p: any) => p.text ?? "").join(""),
      usage: {
        promptTokens: data.usageMetadata?.promptTokenCount ?? 0,
        completionTokens: data.usageMetadata?.candidatesTokenCount ?? 0,
        totalTokens: data.usageMetadata?.totalTokenCount ?? 0,
      },
    };
  },
};

const cohereAdapter: Adapter = {
  async listModels(apiKey) {
    const res = await vendorFetch("https://api.cohere.com/v1/models?page_size=200", {
      method: "GET",
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    if (!res.ok) throw new Error(await readError(res));
    const data = await res.json();
    return (data.models ?? [])
      .filter((m: any) => (m.endpoints ?? []).includes("chat"))
      .map((m: any) => ({
        id: m.name,
        name: titleCase(m.name),
        contextWindow: m.context_length,
        available: true,
      }));
  },
  async chat(apiKey, model, messages, maxTokens, temperature) {
    const res = await vendorFetch("https://api.cohere.com/v2/chat", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ model, messages, max_tokens: maxTokens, temperature }),
    });
    if (!res.ok) throw new Error(await readError(res));
    const data = await res.json();
    return {
      text: (data.message?.content ?? []).map((c: any) => c.text ?? "").join(""),
      usage: {
        promptTokens: data.usage?.tokens?.input_tokens ?? 0,
        completionTokens: data.usage?.tokens?.output_tokens ?? 0,
        totalTokens:
          (data.usage?.tokens?.input_tokens ?? 0) + (data.usage?.tokens?.output_tokens ?? 0),
      },
    };
  },
};

/** Built-in gateway — no user key required. */
const builtInAdapter: Adapter = {
  async listModels() {
    return [
      { id: "google/gemini-3.7-flash", name: "Gemini 3.7 Flash", description: "Fast default for packet analysis", available: true },
      { id: "google/gemini-3.6-flash", name: "Gemini 3.6 Flash", description: "High-efficiency reasoning", available: true },
      { id: "google/gemini-3.1-flash-lite", name: "Gemini 3.1 Flash Lite", description: "Cheapest, high volume", available: true },
      { id: "google/gemini-3.1-pro-preview", name: "Gemini 3.1 Pro", description: "Deepest reasoning", available: true },
      { id: "openai/gpt-5.4", name: "GPT-5.4", description: "Frontier coding and analysis", available: true },
      { id: "openai/gpt-5.4-mini", name: "GPT-5.4 Mini", description: "Balanced cost and quality", available: true },
      { id: "openai/gpt-5-nano", name: "GPT-5 Nano", description: "Fastest, lowest cost", available: true },
    ];
  },
  async chat(_key, model, messages, maxTokens, temperature) {
    const gatewayKey = Deno.env.get("LOVABLE_API_KEY");
    if (!gatewayKey) throw new Error("Built-in AI is not configured on this project.");
    const body: Record<string, unknown> = { model, messages };
    if (model.startsWith("openai/gpt-5")) {
      body.max_completion_tokens = maxTokens;
    } else {
      body.max_tokens = maxTokens;
      body.temperature = temperature;
    }
    const res = await vendorFetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${gatewayKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    if (res.status === 429) throw new Error("Rate limit reached on built-in AI. Please retry shortly.");
    if (res.status === 402) throw new Error("Built-in AI credits are exhausted. Add credits in Lovable.");
    if (!res.ok) throw new Error(await readError(res));
    const data = await res.json();
    return {
      text: data.choices?.[0]?.message?.content ?? "",
      usage: {
        promptTokens: data.usage?.prompt_tokens ?? 0,
        completionTokens: data.usage?.completion_tokens ?? 0,
        totalTokens: data.usage?.total_tokens ?? 0,
      },
    };
  },
};

const adapters: Record<string, Adapter> = {
  lovable: builtInAdapter,
  openai: openAiCompatible("https://api.openai.com/v1", {
    filter: (id) => /^(gpt|o[1-9]|chatgpt)/.test(id),
  }),
  anthropic: anthropicAdapter,
  google: googleAdapter,
  cohere: cohereAdapter,
  deepseek: openAiCompatible("https://api.deepseek.com/v1"),
  groq: openAiCompatible("https://api.groq.com/openai/v1"),
  mistral: openAiCompatible("https://api.mistral.ai/v1"),
  xai: openAiCompatible("https://api.x.ai/v1"),
  openrouter: openAiCompatible("https://openrouter.ai/api/v1"),
  together: openAiCompatible("https://api.together.xyz/v1"),
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  let body: ProxyRequest;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const { action, provider } = body;
  const adapter = adapters[provider];
  if (!adapter) return json({ error: `Unknown provider "${provider}"` }, 400);

  const needsKey = provider !== "lovable";
  const apiKey = body.apiKey ?? "";
  if (needsKey && !apiKey.trim()) {
    return json({ error: "An API key is required for this provider." }, 400);
  }

  try {
    if (action === "test") {
      const models = await adapter.listModels(apiKey);
      return json({ ok: true, modelCount: models.length });
    }

    if (action === "models") {
      const models = await adapter.listModels(apiKey);
      return json({ models });
    }

    if (action === "chat") {
      const model = body.model;
      if (!model) return json({ error: "A model id is required." }, 400);
      const messages =
        body.messages && body.messages.length
          ? body.messages
          : [{ role: "user", content: body.prompt ?? "" }];
      if (!messages.some((m) => m.content?.trim())) {
        return json({ error: "The prompt is empty." }, 400);
      }
      const result = await adapter.chat(
        apiKey,
        model,
        messages,
        Math.min(Math.max(body.maxTokens ?? 1500, 1), 8192),
        Math.min(Math.max(body.temperature ?? 0.4, 0), 2),
      );
      return json(result);
    }

    return json({ error: `Unknown action "${action}"` }, 400);
  } catch (e) {
    // Logged without any credential material.
    console.error(`ai-proxy ${action}/${provider} failed:`, safeError(e));
    return json({ error: safeError(e) }, 502);
  }
});
