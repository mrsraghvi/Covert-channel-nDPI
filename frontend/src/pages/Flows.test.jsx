import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import Flows from "./Flows";

afterEach(cleanup);

const flows = [
  {
    id: 1,
    src: "192.0.2.10:41000",
    dst: "198.51.100.20:80",
    protocol: "HTTP",
    packets: 12,
    bytes: 2400,
    anomaly_score: 0.8,
    is_covert: true,
  },
  {
    id: 2,
    src: "192.0.2.30:42000",
    dst: "198.51.100.40:443",
    protocol: "TLS",
    packets: 8,
    bytes: 900,
    anomaly_score: 0.2,
    is_covert: false,
  },
];

describe("Flows", () => {
  it("shows newest flows first and filters by protocol, covert flag, and endpoint", () => {
    render(<Flows flows={flows} />);

    const rows = screen.getAllByRole("row");
    expect(rows[1].textContent).toContain("192.0.2.30:42000");
    expect(rows[2].textContent).toContain("192.0.2.10:41000");
    expect(screen.getByText("2 shown")).not.toBeNull();

    fireEvent.change(screen.getByRole("combobox"), { target: { value: "HTTP" } });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.change(screen.getByPlaceholderText("Search src / dst…"), {
      target: { value: "192.0.2.10" },
    });

    expect(screen.getByText("1 shown")).not.toBeNull();
    expect(screen.getByText("192.0.2.10:41000")).not.toBeNull();
    expect(screen.queryByText("192.0.2.30:42000")).toBeNull();
  });

  it("shows an empty state when no flows match the filters", () => {
    render(<Flows flows={[]} />);

    expect(screen.getByText("No matching flows")).not.toBeNull();
    expect(screen.getByText("0 shown")).not.toBeNull();
  });

  it("requires confirmation before blocking and submits the host IP and reason", () => {
    const onBlock = vi.fn();
    render(<Flows flows={flows} onBlock={onBlock} />);

    fireEvent.click(screen.getAllByRole("button", { name: "Block" })[0]);
    expect(onBlock).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "Block 192.0.2.30?" })).not.toBeNull();

    fireEvent.change(screen.getByLabelText("Reason (recorded with the block)"), {
      target: { value: "  suspicious TLS traffic  " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Confirm block" }));

    expect(onBlock).toHaveBeenCalledWith("192.0.2.30", "suspicious TLS traffic", null);
    expect(screen.queryByRole("heading", { name: "Block 192.0.2.30?" })).toBeNull();
  });

  it("unblocks an IP already on the blocklist", () => {
    const onUnblock = vi.fn();
    render(
      <Flows
        flows={flows}
        blockedIps={new Map([["192.0.2.30", { reason: "manual" }]])}
        onUnblock={onUnblock}
      />,
    );

    fireEvent.click(screen.getAllByRole("button", { name: "Unblock" })[0]);

    expect(onUnblock).toHaveBeenCalledWith("192.0.2.30");
  });

  it("closes block confirmation without changing the blocklist", () => {
    const onBlock = vi.fn();
    render(<Flows flows={flows} onBlock={onBlock} />);

    fireEvent.click(screen.getAllByRole("button", { name: "Block" })[0]);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(onBlock).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Confirm block" })).toBeNull();
  });
});
