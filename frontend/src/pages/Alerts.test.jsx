import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { api } from "../lib/api";
import Alerts from "./Alerts";

vi.mock("../lib/api", () => ({
  api: { ackAlert: vi.fn() },
}));

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const alerts = [
  {
    id: 10,
    flow_id: 100,
    confidence: "LOW",
    covert_type: "DNS",
    src_ip: "192.0.2.10",
    final_score: 0.2,
    reason: "Low-confidence DNS pattern",
    recommendation: "Review DNS traffic",
  },
  {
    id: 20,
    flow_id: 200,
    confidence: "HIGH",
    covert_type: "TIMING",
    src_ip: "192.0.2.20",
    final_score: 0.85,
    reason: "Periodic packet timing",
    recommendation: "Investigate the source",
  },
  {
    id: 30,
    flow_id: 300,
    confidence: "CRITICAL",
    covert_type: "DNS",
    src_ip: "192.0.2.30",
    final_score: 0.95,
    reason: "High-volume DNS tunnel",
    recommendation: "Isolate the source",
  },
];

describe("Alerts", () => {
  it("shows newest alerts first and filters by minimum confidence and covert type", () => {
    render(<Alerts alerts={alerts} />);

    const alertButtons = screen.getAllByRole("button").filter((button) =>
      button.textContent.includes("flow #"),
    );
    expect(alertButtons[0].textContent).toContain("flow #300");
    expect(alertButtons[1].textContent).toContain("flow #200");
    expect(alertButtons[2].textContent).toContain("flow #100");

    fireEvent.click(screen.getByRole("button", { name: /HIGH\s+1/ }));
    expect(screen.queryByText("flow #100")).toBeNull();
    expect(screen.getByText("flow #200")).not.toBeNull();
    expect(screen.getByText("flow #300")).not.toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "TIMING" }));
    expect(screen.getByText("flow #200")).not.toBeNull();
    expect(screen.queryByText("flow #300")).toBeNull();
    expect(screen.getByText("1 shown")).not.toBeNull();
  });

  it("expands alert reasoning and acknowledges only once", async () => {
    api.ackAlert.mockResolvedValue({});
    render(<Alerts alerts={alerts} />);

    fireEvent.click(screen.getByRole("button", { name: /flow #300/ }));
    expect(screen.getByText("High-volume DNS tunnel")).not.toBeNull();
    expect(screen.getByText("Isolate the source")).not.toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Acknowledge alert" }));
    expect(await screen.findByRole("button", { name: "Acknowledged" })).not.toBeNull();
    expect(api.ackAlert).toHaveBeenCalledOnce();
    expect(api.ackAlert).toHaveBeenCalledWith(30);
    expect(screen.getByRole("button", { name: "Acknowledged" }).disabled).toBe(true);
  });

  it("asks for block confirmation and sends the alert source and ID", () => {
    const onBlock = vi.fn();
    render(<Alerts alerts={alerts} onBlock={onBlock} />);

    fireEvent.click(screen.getByRole("button", { name: /flow #300/ }));
    fireEvent.click(screen.getByRole("button", { name: "Block 192.0.2.30" }));

    expect(onBlock).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "Block 192.0.2.30?" })).not.toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Confirm block" }));
    expect(onBlock).toHaveBeenCalledWith(
      "192.0.2.30",
      "DNS covert-channel alert, confidence CRITICAL",
      30,
    );
    expect(screen.queryByRole("heading", { name: "Block 192.0.2.30?" })).toBeNull();
  });

  it("unblocks a source already in the blocklist", () => {
    const onUnblock = vi.fn();
    render(
      <Alerts
        alerts={alerts}
        blockedIps={new Map([["192.0.2.30", { reason: "manual" }]])}
        onUnblock={onUnblock}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /flow #300/ }));
    fireEvent.click(screen.getByRole("button", { name: "Unblock 192.0.2.30" }));

    expect(onUnblock).toHaveBeenCalledWith("192.0.2.30");
  });

  it("shows an empty state when all alerts are filtered out", () => {
    render(<Alerts alerts={alerts} />);

    fireEvent.click(screen.getByRole("button", { name: "ICMP" }));

    expect(screen.getByText("No alerts match these filters")).not.toBeNull();
    expect(screen.getByText("0 shown")).not.toBeNull();
  });
});
