import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import entry from "./index.js";
import { getToolPluginMetadata } from "openclaw/plugin-sdk/tool-plugin";

describe("plugin.vmga", () => {
  it("declares VMGA mail tools", () => {
    const metadata = getToolPluginMetadata(entry);
    expect(metadata?.tools.map((tool) => tool.name)).toEqual([
      "mail_search",
      "mail_get",
      "mail_get_attachment",
      "mail_create_draft",
      "mail_send",
    ]);
  });

  it("supports broker bearer tokens without shelling out", () => {
    const source = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
    expect(source).toContain("broker_token");
    expect(source).toContain("headers.Authorization");
    expect(source).not.toContain("child_process");
    expect(source).not.toContain("gmail.");
    expect(source).not.toContain("gog ");
  });
});
