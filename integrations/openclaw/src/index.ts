import { Type } from "typebox";
import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";

const DEFAULT_BROKER_URL = "http://127.0.0.1:8765";
const BROKER_ENDPOINT = "/v1/proposals";

const ConfigSchema = Type.Object(
  {
    broker_url: Type.Optional(Type.String({ description: "VMGA broker base URL." })),
    broker_token: Type.Optional(Type.String({ description: "Optional VMGA broker bearer token." })),
    broker_timeout_seconds: Type.Optional(Type.Number({ minimum: 1, maximum: 120 })),
  },
  { additionalProperties: false },
);

const CommonMailFields = {
  actor_id: Type.Optional(Type.String()),
  session_id: Type.Optional(Type.String()),
  thread_id: Type.Optional(Type.String()),
  message_ids: Type.Optional(Type.Array(Type.String())),
  content: Type.Optional(Type.String()),
  subject: Type.Optional(Type.String()),
  recipients: Type.Optional(Type.Array(Type.String())),
  attachment_ids: Type.Optional(Type.Array(Type.String())),
  justification: Type.Optional(Type.String()),
};

const MailSearchSchema = Type.Object(
  {
    ...CommonMailFields,
    query: Type.String({ description: "Gmail search query." }),
    max_results: Type.Optional(Type.Integer({ minimum: 1, maximum: 100 })),
  },
  { additionalProperties: false },
);

const MailGetSchema = Type.Object(
  {
    ...CommonMailFields,
    message_id: Type.String({ description: "Gmail message id." }),
  },
  { additionalProperties: false },
);

const MailGetAttachmentSchema = Type.Object(
  {
    ...CommonMailFields,
    message_id: Type.String({ description: "Gmail message id." }),
    attachment_id: Type.String({ description: "Gmail attachment id." }),
  },
  { additionalProperties: false },
);

const MailCreateDraftSchema = Type.Object(
  {
    ...CommonMailFields,
    recipients: Type.Array(Type.String(), { minItems: 1 }),
    content: Type.String({ minLength: 1 }),
    subject: Type.Optional(Type.String()),
  },
  { additionalProperties: false },
);

const MailSendSchema = MailCreateDraftSchema;

type JsonMap = Record<string, unknown>;

function asStringList(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  if (typeof value === "string") return [value];
  return [];
}

function buildPayload(toolName: string, action: string, params: JsonMap): JsonMap {
  const actorId = typeof params.actor_id === "string" && params.actor_id.trim() ? params.actor_id : "openclaw-operator";
  const payload: JsonMap = {
    action,
    actor_id: actorId,
    thread_id: params.thread_id,
    message_ids: asStringList(params.message_ids),
    content: params.content,
    subject: params.subject,
    recipients: asStringList(params.recipients),
    attachment_ids: asStringList(params.attachment_ids),
    justification: typeof params.justification === "string" ? params.justification : "",
    metadata: {
      source: "openclaw",
      tool_id: toolName,
      session_id: params.session_id,
    },
  };

  if (toolName === "mail_search") {
    payload.search_query = params.query;
    payload.max_results = params.max_results ?? 10;
  }
  if (toolName === "mail_get") {
    payload.message_id = params.message_id;
  }
  if (toolName === "mail_get_attachment") {
    payload.message_id = params.message_id;
    payload.attachment_ids = typeof params.attachment_id === "string" ? [params.attachment_id] : [];
  }
  return payload;
}

async function postToBroker(config: { broker_url?: string; broker_token?: string; broker_timeout_seconds?: number }, payload: JsonMap): Promise<JsonMap> {
  const brokerUrl = (config.broker_url || DEFAULT_BROKER_URL).replace(/\/+$/, "");
  const timeoutMs = Math.max(1, config.broker_timeout_seconds ?? 10) * 1000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const headers: Record<string, string> = { "Content-Type": "application/json", Accept: "application/json" };
  if (config.broker_token) {
    headers.Authorization = `Bearer ${config.broker_token}`;
  }

  try {
    const response = await fetch(`${brokerUrl}${BROKER_ENDPOINT}`, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const text = await response.text();
    let brokerResponse: unknown;
    try {
      brokerResponse = text ? JSON.parse(text) : null;
    } catch (error) {
      return {
        status: "DENY",
        error_code: "vmga_broker_bad_json",
        error: error instanceof Error ? error.message : String(error),
      };
    }
    return {
      status: response.ok ? "OK" : "DENY",
      http_status: response.status,
      broker_response: brokerResponse,
    };
  } catch (error) {
    return {
      status: "DENY",
      error_code: "vmga_broker_unreachable",
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    clearTimeout(timeout);
  }
}

function toolHandler(toolName: string, action: string) {
  return async (params: JsonMap, config: { broker_url?: string; broker_token?: string; broker_timeout_seconds?: number }) => {
    const payload = buildPayload(toolName, action, params);
    const result = await postToBroker(config, payload);
    return { tool: toolName, ...result };
  };
}

export default defineToolPlugin({
  id: "plugin.vmga",
  name: "VMGA Mail Governance",
  description: "Route OpenClaw mailbox tools through the VMGA broker.",
  configSchema: ConfigSchema,
  tools: (tool) => [
    tool({
      name: "mail_search",
      description: "Search Gmail through the VMGA broker.",
      parameters: MailSearchSchema,
      execute: toolHandler("mail_search", "read"),
    }),
    tool({
      name: "mail_get",
      description: "Read a Gmail message through the VMGA broker.",
      parameters: MailGetSchema,
      execute: toolHandler("mail_get", "read"),
    }),
    tool({
      name: "mail_get_attachment",
      description: "Request a Gmail attachment through the VMGA broker.",
      parameters: MailGetAttachmentSchema,
      execute: toolHandler("mail_get_attachment", "download_attachment"),
    }),
    tool({
      name: "mail_create_draft",
      description: "Propose draft creation through the VMGA broker.",
      parameters: MailCreateDraftSchema,
      execute: toolHandler("mail_create_draft", "create_draft"),
    }),
    tool({
      name: "mail_send",
      description: "Propose mail sending through the VMGA broker.",
      parameters: MailSendSchema,
      execute: toolHandler("mail_send", "send"),
    }),
  ],
});
