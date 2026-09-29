/**
 * Handler-invocation tests for handleSearchTool -- previously zero test
 * coverage. Mocks ../utils/client.js's apiRequest so each test asserts the
 * exact outbound call shape and the resulting formatted summary.
 */
import { describe, it, expect, vi } from "vitest";
import { handleSearchTool } from "./search.js";
import { apiRequest } from "../utils/client.js";
import type { ApiResponse, HecEntity } from "../utils/types.js";

vi.mock("../utils/client.js", () => ({ apiRequest: vi.fn() }));

const mockedApiRequest = vi.mocked(apiRequest);

const sampleEntity: HecEntity = {
  entityInfo: {
    entityId: "ent-1",
    customerId: "acme",
    saas: "office365_emails",
    saasEntityType: "email",
    entityCreated: "2026-07-16T09:00:00Z",
    entityUpdated: "2026-07-16T09:00:00Z",
  },
  entityPayload: {
    subject: "Invoice overdue",
    fromEmail: "attacker@example.com",
    to: ["victim@acme.com"],
    isQuarantined: false,
    isRestored: false,
  },
  entitySecurityResult: { combinedVerdict: { malware: "clean" } },
  entityAvailableActions: [{ entityActionName: "quarantine", entityActionParam: "" }],
};

function envelope(data: HecEntity[]): ApiResponse<HecEntity> {
  return {
    responseEnvelope: { requestId: "req-1", responseCode: 200, responseText: "OK", recordsNumber: data.length },
    responseData: data,
  };
}

function summaryOf(text: string): Array<Record<string, unknown>> {
  return JSON.parse(text.slice(text.indexOf("["))) as Array<Record<string, unknown>>;
}

describe("hec_search_emails", () => {
  it("builds the minimal entityFilter/requestData when only the required fields are given", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([]));
    await handleSearchTool("hec_search_emails", { saas: "office365_emails", startDate: "2026-01-01T00:00:00Z" });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/search/query", {
      method: "POST",
      body: {
        requestData: {
          entityFilter: { saas: "office365_emails", startDate: "2026-01-01T00:00:00Z" },
        },
      },
    });
  });

  it("includes endDate, saasEntity, extended filters, and scrollId when provided", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([]));
    const filters = [{ saasAttrName: "isQuarantined", saasAttrOp: "is", saasAttrValue: true }];
    await handleSearchTool("hec_search_emails", {
      saas: "office365_emails",
      startDate: "2026-01-01T00:00:00Z",
      endDate: "2026-01-02T00:00:00Z",
      saasEntity: "email",
      filters,
      scrollId: "scroll-1",
    });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/search/query", {
      method: "POST",
      body: {
        requestData: {
          entityFilter: {
            saas: "office365_emails",
            startDate: "2026-01-01T00:00:00Z",
            endDate: "2026-01-02T00:00:00Z",
            saasEntity: "email",
          },
          entityExtendedFilter: filters,
          scrollId: "scroll-1",
        },
      },
    });
  });

  it("formats the entity summary with the flattened fields the tool advertises", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([sampleEntity]));
    const result = await handleSearchTool("hec_search_emails", {
      saas: "office365_emails",
      startDate: "2026-01-01T00:00:00Z",
    });
    expect(result.content[0].text).toContain("Found 1 email.");
    expect(summaryOf(result.content[0].text)[0]).toEqual({
      entityId: "ent-1",
      saas: "office365_emails",
      entityCreated: "2026-07-16T09:00:00Z",
      subject: "Invoice overdue",
      from: "attacker@example.com",
      to: ["victim@acme.com"],
      isQuarantined: false,
      isRestored: false,
      verdict: { malware: "clean" },
      availableActions: ["quarantine"],
    });
  });

  it("defaults availableActions to an empty array when none are present", async () => {
    mockedApiRequest.mockResolvedValueOnce(
      envelope([{ ...sampleEntity, entityAvailableActions: undefined }])
    );
    const result = await handleSearchTool("hec_search_emails", {
      saas: "office365_emails",
      startDate: "2026-01-01T00:00:00Z",
    });
    expect(summaryOf(result.content[0].text)[0].availableActions).toEqual([]);
  });
});

describe("hec_get_email", () => {
  it("GETs the exact entity id, URL-encoded", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([sampleEntity]));
    await handleSearchTool("hec_get_email", { entityId: "ent/1 2" });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/search/entity/ent%2F1%202");
  });
});

describe("unknown search tool", () => {
  it("throws naming the unknown tool", async () => {
    await expect(handleSearchTool("hec_not_a_real_tool", {})).rejects.toThrow(
      "Unknown search tool: hec_not_a_real_tool"
    );
  });
});
