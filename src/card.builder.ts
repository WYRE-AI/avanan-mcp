/**
 * Security-event-card payload builder for the MCP Apps (SEP-1865) UI surface.
 *
 * hec_get_event results get a normalized `_card` object attached (see
 * tools/events.ts) that the ui:// security event card renders from. The card
 * is progressive enhancement: every step here is best-effort, and a null
 * return simply means the host renders no card while the JSON payload is
 * unchanged.
 *
 * The card is read-only by policy — remediation stays in chat, where the
 * existing action tools carry their destructive-action warnings.
 */

import type { HecEvent } from "./utils/types.js";

export const EVENT_CARD_RESOURCE_URI = "ui://avanan/security-event-card.html";

/** MCP Apps resource MIME (RESOURCE_MIME_TYPE in @modelcontextprotocol/ext-apps). */
export const MCP_APP_RESOURCE_MIME = "text/html;profile=mcp-app";

/**
 * Tool `_meta` advertising the card. Carries both the canonical flat key
 * (RESOURCE_URI_META_KEY in ext-apps) and the nested form ext-apps'
 * registerAppTool emits, so any MCP Apps host revision finds it.
 */
export const EVENT_CARD_META = {
  "ui/resourceUri": EVENT_CARD_RESOURCE_URI,
  ui: { resourceUri: EVENT_CARD_RESOURCE_URI },
} as const;

/** Mirror of Brand in ui/event-card.ts — keep in sync. */
export interface CardBrand {
  name?: string;
  logoUrl?: string;
  primaryColor?: string;
  accentColor?: string;
  bg?: string;
  text?: string;
}

/** The brand-inject comment marker baked into the card HTML (see ui/index.html). */
const BRAND_INJECT_RE = /<!--\s*BRAND_INJECT:[\s\S]*?-->/;

/**
 * Serve-time brand injection: replace the marker with an inline
 * `window.__BRAND__` script so self-hosters can theme the card without
 * rebuilding the bundle. An empty brand returns the HTML unchanged (the card
 * renders its neutral defaults). `<` is escaped so brand values can never
 * break out of the script tag.
 */
export function applyBrandInjection(html: string, brand: CardBrand): string {
  if (!brand || Object.values(brand).every((v) => !v)) return html;
  const json = JSON.stringify(brand).replace(/</g, "\\u003c");
  return html.replace(BRAND_INJECT_RE, `<script>window.__BRAND__=${json}</script>`);
}

/**
 * Resolve brand overrides from MCP_BRAND_* environment variables. Guarded for
 * runtimes without `process`, where this returns an empty brand and the card
 * serves its neutral defaults.
 */
export function resolveBrandFromEnv(): CardBrand {
  if (typeof process === "undefined" || !process.env) return {};
  const env = process.env;
  const brand: CardBrand = {};
  if (env.MCP_BRAND_NAME) brand.name = env.MCP_BRAND_NAME;
  if (env.MCP_BRAND_LOGO_URL) brand.logoUrl = env.MCP_BRAND_LOGO_URL;
  if (env.MCP_BRAND_PRIMARY_COLOR) brand.primaryColor = env.MCP_BRAND_PRIMARY_COLOR;
  if (env.MCP_BRAND_ACCENT_COLOR) brand.accentColor = env.MCP_BRAND_ACCENT_COLOR;
  if (env.MCP_BRAND_BG) brand.bg = env.MCP_BRAND_BG;
  if (env.MCP_BRAND_TEXT) brand.text = env.MCP_BRAND_TEXT;
  return brand;
}

/** Mirror of EventCard in ui/event-card.ts — keep in sync. */
export interface EventCard {
  eventId: string;
  title: string;
  severity?: string;
  state?: string;
  confidence?: string;
  saas?: string;
  detected?: string;
  description?: string;
  /** Remediation already applied to the event (humanized action names). */
  actionsTaken: string[];
  /** Remediation the API offers for this event — informational only (read-only card). */
  availableActions: string[];
}

const CARD_DESCRIPTION_MAX_LENGTH = 500;
const CARD_ACTION_LIMIT = 6;

/** Event-type labels, from the hec_query_events enum (HEC Smart API v1.50). */
const TYPE_LABELS: Record<string, string> = {
  phishing: "Phishing",
  malware: "Malware",
  suspicious_malware: "Suspicious Malware",
  suspicious_phishing: "Suspicious Phishing",
  dlp: "DLP",
  anomaly: "Anomaly",
  shadow_it: "Shadow IT",
  malicious_url_click: "Malicious URL Click",
  malicious_url: "Malicious URL",
  alert: "Alert",
};

/** SaaS-platform labels, from the hec_query_events enum. */
const SAAS_LABELS: Record<string, string> = {
  email: "Email",
  office365_emails: "Office 365 Mail",
  office365_onedrive: "OneDrive",
  office365_sharepoint: "SharePoint",
  slack: "Slack",
  ms_teams: "Microsoft Teams",
  google_mail: "Gmail",
  box2: "Box",
  dropbox2: "Dropbox",
  google_drive: "Google Drive",
};

/** Fallback humanizer for values outside the known enums: "malicious_url" → "Malicious Url". */
function humanize(value: string): string {
  return value
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function labelFor(value: unknown, table?: Record<string, string>): string | undefined {
  if (typeof value !== "string" || !value) return undefined;
  return table?.[value] ?? humanize(value);
}

/**
 * Build the renderable card from a hec_get_event payload. Pure normalization —
 * no API calls — using only the enum labels this server already ships in its
 * tool schemas. Returns null when the payload is not recognizably an event.
 */
export function buildEventCard(event: Partial<HecEvent> | undefined): EventCard | null {
  if (!event || typeof event.eventId !== "string" || !event.eventId || typeof event.type !== "string" || !event.type) {
    return null;
  }

  const card: EventCard = {
    eventId: event.eventId,
    title: labelFor(event.type, TYPE_LABELS) ?? event.type,
    actionsTaken: [],
    availableActions: [],
  };

  const severity = labelFor(event.severity);
  const state = labelFor(event.state);
  const confidence = labelFor(event.confidenceIndicator);
  const saas = labelFor(event.saas, SAAS_LABELS);
  if (severity) card.severity = severity;
  if (state) card.state = state;
  if (confidence) card.confidence = confidence;
  if (saas) card.saas = saas;
  if (typeof event.eventCreated === "string" && event.eventCreated) {
    card.detected = event.eventCreated;
  }
  if (typeof event.description === "string" && event.description) {
    card.description = event.description.slice(0, CARD_DESCRIPTION_MAX_LENGTH);
  }

  if (Array.isArray(event.actions)) {
    card.actionsTaken = event.actions
      .map((a) => labelFor(a?.actionType))
      .filter((a): a is string => !!a)
      .slice(0, CARD_ACTION_LIMIT);
  }
  if (Array.isArray(event.availableEventActions)) {
    card.availableActions = event.availableEventActions
      .map((a) => labelFor(a?.actionName))
      .filter((a): a is string => !!a)
      .slice(0, CARD_ACTION_LIMIT);
  }

  return card;
}
