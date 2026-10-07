import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import BlockConfirmModal from "./BlockConfirmModal";

afterEach(cleanup);

describe("BlockConfirmModal", () => {
  it("shows the target IP and explains that blocking is advisory", () => {
    render(
      <BlockConfirmModal
        ip="192.0.2.10"
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    );

    expect(screen.getByRole("heading", { name: "Block 192.0.2.10?" })).not.toBeNull();
    expect(screen.getByText(/it doesn't sit inline on the network path/i)).not.toBeNull();
    expect(screen.getByLabelText("Reason (recorded with the block)")).not.toBeNull();
  });

  it("submits a trimmed reason", () => {
    const onConfirm = vi.fn();
    render(
      <BlockConfirmModal
        ip="192.0.2.10"
        defaultReason="flow alert"
        onConfirm={onConfirm}
        onCancel={vi.fn()}
      />,
    );

    const reason = screen.getByLabelText("Reason (recorded with the block)");
    expect(reason.value).toBe("flow alert");

    fireEvent.change(reason, { target: { value: "  suspicious traffic  " } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm block" }));

    expect(onConfirm).toHaveBeenCalledOnce();
    expect(onConfirm).toHaveBeenCalledWith("suspicious traffic");
  });

  it("submits null when the reason contains only whitespace", () => {
    const onConfirm = vi.fn();
    render(
      <BlockConfirmModal
        ip="192.0.2.10"
        onConfirm={onConfirm}
        onCancel={vi.fn()}
      />,
    );

    fireEvent.change(screen.getByLabelText("Reason (recorded with the block)"), {
      target: { value: "   " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Confirm block" }));

    expect(onConfirm).toHaveBeenCalledWith(null);
  });

  it("calls cancel without confirming", () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    render(
      <BlockConfirmModal
        ip="192.0.2.10"
        onConfirm={onConfirm}
        onCancel={onCancel}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(onCancel).toHaveBeenCalledOnce();
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
