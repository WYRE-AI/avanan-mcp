/**
 * Handler-invocation tests for handleActionTool -- previously zero test
 * coverage. Mocks ../utils/client.js's apiRequest so each test asserts the
 * exact outbound call shape and the resulting human-readable summary text.
 */
import { describe, it, expect, vi } from "vitest";
import { handleActionTool } from "./actions.js";
import { apiRequest } from "../utils/client.js";
import type { ApiResponse } from "../utils/types.js";

vi.mock("../utils/client.js", () => ({ apiRequest: vi.fn() }));

const mockedApiRequest = vi.mocked(apiRequest);

function envelope<T>(data: T[]): ApiResponse<T> {
  return {
    responseEnvelope: { requestId: "req-1", responseCode: 200, responseText: "OK" },
    responseData: data,
  };
}

describe("hec_quarantine_events", () => {
  it("POSTs the event action with eventActionName=quarantine and summarizes the returned tasks", async () => {
    mockedApiRequest.mockResolvedValueOnce(
      envelope([{ eventId: "e1", entityId: "ent-1", taskId: "t1" }])
    );
    const result = await handleActionTool("hec_quarantine_events", { eventIds: ["e1"] });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/action/event", {
      method: "POST",
      body: { requestData: { eventIds: ["e1"], eventActionName: "quarantine" } },
    });
    expect(result.content[0].text).toContain("Quarantine initiated for 1 event(s).");
    expect(result.content[0].text).toContain('"taskId": "t1"');
  });
});

describe("hec_restore_events", () => {
  it("POSTs the event action with eventActionName=restore", async () => {
    mockedApiRequest.mockResolvedValueOnce(
      envelope([{ eventId: "e1", entityId: "ent-1", taskId: "t2" }])
    );
    const result = await handleActionTool("hec_restore_events", { eventIds: ["e1", "e2"] });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/action/event", {
      method: "POST",
      body: { requestData: { eventIds: ["e1", "e2"], eventActionName: "restore" } },
    });
    expect(result.content[0].text).toContain("Restore initiated for 1 event(s).");
  });
});

describe("hec_quarantine_emails", () => {
  it("POSTs the entity action defaulting entityType to 'email'", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([{ entityId: "ent-1", taskId: "t3" }]));
    const result = await handleActionTool("hec_quarantine_emails", { entityIds: ["ent-1"] });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/action/entity", {
      method: "POST",
      body: {
        requestData: { entityIds: ["ent-1"], entityType: "email", entityActionName: "quarantine" },
      },
    });
    expect(result.content[0].text).toContain("Quarantine initiated for 1 email(s).");
  });

  it("forwards an explicit entityType instead of the default", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([{ entityId: "ent-1", taskId: "t4" }]));
    await handleActionTool("hec_quarantine_emails", {
      entityIds: ["ent-1"],
      entityType: "onedrive_file",
    });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/action/entity", {
      method: "POST",
      body: {
        requestData: {
          entityIds: ["ent-1"],
          entityType: "onedrive_file",
          entityActionName: "quarantine",
        },
      },
    });
  });
});

describe("hec_restore_emails", () => {
  it("POSTs the entity action with entityActionName=restore", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope([{ entityId: "ent-1", taskId: "t5" }]));
    const result = await handleActionTool("hec_restore_emails", { entityIds: ["ent-1"] });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/action/entity", {
      method: "POST",
      body: {
        requestData: { entityIds: ["ent-1"], entityType: "email", entityActionName: "restore" },
      },
    });
    expect(result.content[0].text).toContain("Restore initiated for 1 email(s).");
  });
});

describe("hec_get_task_status", () => {
  it("GETs the exact task id, URL-encoded, and prints the raw response data", async () => {
    mockedApiRequest.mockResolvedValueOnce(envelope({ status: "complete" } as never));
    const result = await handleActionTool("hec_get_task_status", { taskId: "t/1 2" });
    expect(mockedApiRequest).toHaveBeenCalledWith("/v1.0/task/t%2F1%202");
    expect(result.content[0].text).toContain('"status": "complete"');
  });

  it("falls back to a 'not yet complete' message when responseData is empty/falsy", async () => {
    mockedApiRequest.mockResolvedValueOnce({
      responseEnvelope: { requestId: "req-1", responseCode: 200, responseText: "OK" },
      responseData: undefined as never,
    });
    const result = await handleActionTool("hec_get_task_status", { taskId: "t1" });
    expect(result.content[0].text).toBe("Task not yet complete.");
  });
});

describe("unknown action tool", () => {
  it("throws naming the unknown tool", async () => {
    await expect(handleActionTool("hec_not_a_real_tool", {})).rejects.toThrow(
      "Unknown action tool: hec_not_a_real_tool"
    );
  });
});
