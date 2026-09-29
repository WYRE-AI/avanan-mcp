/**
 * Handler-invocation tests for handleExceptionTool -- previously zero test
 * coverage. Mocks ../utils/client.js's apiRequest so each test asserts the
 * exact outbound call shape, the buildExceptionBody field allowlist, and
 * the resulting human-readable summary text.
 */
import { describe, it, expect, vi } from "vitest";
import { handleExceptionTool } from "./exceptions.js";
import { apiRequest } from "../utils/client.js";
import type { ApiResponse, HecException } from "../utils/types.js";

vi.mock("../utils/client.js", () => ({ apiRequest: vi.fn() }));

const mockedApiRequest = vi.mocked(apiRequest);

function envelope(data: HecException[]): ApiResponse<HecException> {
  return {
    responseEnvelope: { requestId: "req-1", responseCode: 200, responseText: "OK" },
    responseData: data,
  };
}

describe("hec_list_exceptions", () => {
  it("GETs the whitelist and formats a pluralized summary", async () => {
    mockedApiRequest.mockResolvedValueOnce(
      envelope([{ entityId: "x1", senderEmail: "a@b.com", addedBy: "admin" }])
    );
    const result = await handleExceptionTool("hec_list_exceptions", { excType: "whitelist" });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/exceptions/whitelist");
    expect(result.content[0].text).toContain("1 whitelist entry.");
  });

  it("GETs the blacklist and pluralizes for a zero/multi count", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([]));
    const result = await handleExceptionTool("hec_list_exceptions", { excType: "blacklist" });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/exceptions/blacklist");
    expect(result.content[0].text).toContain("0 blacklist entries.");
  });
});

describe("hec_add_exception", () => {
  it("POSTs only the recognized fields the caller provided, dropping unknown keys", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([{ entityId: "x1" }]));
    await handleExceptionTool("hec_add_exception", {
      excType: "whitelist",
      senderEmail: "a@b.com",
      comment: "trusted vendor",
      notARealField: "should be dropped",
    });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/exceptions/whitelist", {
      method: "POST",
      body: { requestData: { senderEmail: "a@b.com", comment: "trusted vendor" } },
    });
  });

  it("forwards the matching-mode fields when provided", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([{ entityId: "x2" }]));
    await handleExceptionTool("hec_add_exception", {
      excType: "blacklist",
      senderDomain: "evil.com",
      senderDomainMatching: "contains",
    });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/exceptions/blacklist", {
      method: "POST",
      body: { requestData: { senderDomain: "evil.com", senderDomainMatching: "contains" } },
    });
  });
});

describe("hec_update_exception", () => {
  it("PUTs to the exact excType/excId path with only the provided fields", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([{ entityId: "x/1 2" }]));
    await handleExceptionTool("hec_update_exception", {
      excType: "whitelist",
      excId: "x/1 2",
      comment: "updated",
    });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/exceptions/whitelist/x%2F1%202", {
      method: "PUT",
      body: { requestData: { comment: "updated" } },
    });
  });
});

describe("hec_delete_exception", () => {
  it("POSTs to the delete path and does not include a request body", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([]));
    const result = await handleExceptionTool("hec_delete_exception", {
      excType: "blacklist",
      excId: "x1",
    });
    expect(mockedApiRequest).toHaveBeenCalledExactlyOnceWith("/v1.0/exceptions/blacklist/delete/x1", {
      method: "POST",
    });
    expect(result.content[0].text).toBe("Exception x1 deleted from blacklist.");
  });

  it("URL-encodes the excId in the delete path", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([]));
    await handleExceptionTool("hec_delete_exception", { excType: "whitelist", excId: "x/1 2" });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/exceptions/whitelist/delete/x%2F1%202", {
      method: "POST",
    });
  });
});

describe("unknown exception tool", () => {
  it("throws naming the unknown tool", async () => {
    await expect(handleExceptionTool("hec_not_a_real_tool", { excType: "whitelist" })).rejects.toThrow(
      "Unknown exception tool: hec_not_a_real_tool"
    );
  });
});
