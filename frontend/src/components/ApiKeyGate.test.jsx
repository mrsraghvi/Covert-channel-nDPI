import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import ApiKeyGate from "./ApiKeyGate";

afterEach(() => {
  cleanup();
  window.sessionStorage.clear();
});

describe("ApiKeyGate", () => {
  it("requires a non-empty API key and submits the trimmed value", () => {
    const onSubmit = vi.fn();
    render(<ApiKeyGate onSubmit={onSubmit} onDismiss={vi.fn()} />);

    const input = screen.getByPlaceholderText("Paste API key");
    const connectButton = screen.getByRole("button", { name: "Connect" });

    expect(connectButton.disabled).toBe(true);

    fireEvent.change(input, { target: { value: "   " } });
    expect(connectButton.disabled).toBe(true);

    fireEvent.change(input, { target: { value: "  test-key  " } });
    expect(connectButton.disabled).toBe(false);
    fireEvent.click(connectButton);

    expect(window.sessionStorage.getItem("covertscope_api_key")).toBe("test-key");
    expect(onSubmit).toHaveBeenCalledWith("test-key");
  });

  it("lets the user switch to demo mode", () => {
    const onDismiss = vi.fn();
    render(<ApiKeyGate onSubmit={vi.fn()} onDismiss={onDismiss} />);

    fireEvent.click(screen.getByRole("button", { name: "Use demo mode instead" }));

    expect(onDismiss).toHaveBeenCalledOnce();
  });

  it("hides the demo-mode action when dismissal is disabled", () => {
    render(<ApiKeyGate onSubmit={vi.fn()} onDismiss={vi.fn()} dismissible={false} />);

    expect(screen.queryByRole("button", { name: "Use demo mode instead" })).toBeNull();
  });
});
