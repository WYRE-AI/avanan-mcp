/**
 * Outbound call-shape tests for handleEventTool.
 *
 * card-attachment/normalization behavior (buildEventCard) and the
 * hec_get_event/_meta MCP Apps contract are already covered end-to-end in
 * ../mcp-apps.test.ts -- this file focuses on what that one doesn't check:
 * the exact apiRequest path/method/body each tool builds, in particular
 * hec_query_events' conditional requestData assembly (only fields the
 * caller actually provided should be forwarded).
 */
import { describe, it, expect, vi } from "vitest";
import { handleEventTool } from "./events.js";
import { apiRequest } from "../utils/client.js";
import type { ApiResponse, HecEvent } from "../utils/types.js";

vi.mock("../utils/client.js", () => ({ apiRequest: vi.fn() }));

const mockedApiRequest = vi.mocked(apiRequest);

function envelope(events: Partial<HecEvent>[] = []): ApiResponse<HecEvent> {
  return {
    responseEnvelope: { requestId: "req-1", responseCode: 200, responseText: "OK", recordsNumber: events.length },
    responseData: events as HecEvent[],
  };
}

describe("hec_query_events", () => {
  it("sends an empty requestData body when no filters are given", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope());
    await handleEventTool("hec_query_events", {});
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/event/query", {
      method: "POST",
      body: { requestData: {} },
    });
  });

  it("forwards only the filter fields actually provided", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope());
    await handleEventTool("hec_query_events", {
      eventTypes: ["phishing"],
      severities: ["Critical"],
      scrollId: "scroll-1",
    });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/event/query", {
      method: "POST",
      body: {
        requestData: {
          eventTypes: ["phishing"],
          severities: ["Critical"],
          scrollId: "scroll-1",
        },
      },
    });
  });

  it("forwards every supported filter field when all are given", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope());
    const args = {
      eventTypes: ["malware"],
      eventStates: ["new"],
      severities: ["High"],
      startDate: "2026-01-01T00:00:00Z",
      endDate: "2026-01-02T00:00:00Z",
      saas: ["email"],
      eventIds: ["e1"],
      scrollId: "scroll-2",
    };
    await handleEventTool("hec_query_events", args);
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/event/query", {
      method: "POST",
      body: { requestData: args },
    });
  });
});

describe("hec_get_event", () => {
  it("GETs the exact event id, URL-encoded", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([{ eventId: "e/1 2", type: "phishing" }]));
    await handleEventTool("hec_get_event", { eventId: "e/1 2" });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/event/e%2F1%202");
  });
});

describe("unknown event tool", () => {
  it("throws naming the unknown tool", async () => {
    await expect(handleEventTool("hec_not_a_real_tool", {})).rejects.toThrow(
      "Unknown event tool: hec_not_a_real_tool"
    );
  });
});
