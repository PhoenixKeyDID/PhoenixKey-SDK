import { keyRoleFromClaim, keyRoleAtLeast, KeyRole } from "../src/types";

describe("keyRoleFromClaim — fail-safe read of a raw key_role claim", () => {
  it("returns 'viewer' for null", () => {
    expect(keyRoleFromClaim(null)).toBe("viewer");
  });

  it("returns 'viewer' for undefined", () => {
    expect(keyRoleFromClaim(undefined)).toBe("viewer");
  });

  it("returns 'viewer' for empty string", () => {
    expect(keyRoleFromClaim("")).toBe("viewer");
  });

  it("returns 'viewer' for whitespace-only string", () => {
    expect(keyRoleFromClaim("   ")).toBe("viewer");
  });

  it("returns 'viewer' for an unrecognized string", () => {
    expect(keyRoleFromClaim("superadmin")).toBe("viewer");
    expect(keyRoleFromClaim("owner; DROP TABLE users;")).toBe("viewer");
  });

  it("accepts the three valid roles as-is", () => {
    expect(keyRoleFromClaim("owner")).toBe("owner");
    expect(keyRoleFromClaim("manager")).toBe("manager");
    expect(keyRoleFromClaim("viewer")).toBe("viewer");
  });

  it("is case-insensitive (matches backend KeyRole.fromClaim behavior)", () => {
    expect(keyRoleFromClaim("OWNER")).toBe("owner");
    expect(keyRoleFromClaim("Manager")).toBe("manager");
    expect(keyRoleFromClaim("VIEWER")).toBe("viewer");
  });

  it("trims surrounding whitespace before matching", () => {
    expect(keyRoleFromClaim("  owner  ")).toBe("owner");
  });

  it("never throws, regardless of input shape", () => {
    // Deliberately passing wrong runtime types to prove the fail-safe holds
    // even when a caller ignores the TS signature (vd: JSON.parse() output
    // from an untyped 3rd-party call site).
    const asClaim = (v: unknown) => v as string | null | undefined;
    expect(() => keyRoleFromClaim(asClaim(123))).not.toThrow();
    expect(keyRoleFromClaim(asClaim(123))).toBe("viewer");
    expect(() => keyRoleFromClaim(asClaim({}))).not.toThrow();
  });

  it("never returns 'owner' for any input other than the exact literal 'owner' (case/whitespace aside)", () => {
    const attempts = [
      null,
      undefined,
      "",
      "Owner ",
      "owner2",
      "ownerx",
      "xowner",
      "OWNER!",
      "root",
      "admin",
    ];
    for (const raw of attempts) {
      const role = keyRoleFromClaim(raw as string | null | undefined);
      if (role === "owner") {
        // Only the clean, trimmed, case-insensitive literal is allowed through.
        expect(String(raw).trim().toLowerCase()).toBe("owner");
      }
    }
  });
});

describe("keyRoleAtLeast — hierarchy gate (viewer < manager < owner)", () => {
  const roles: KeyRole[] = ["viewer", "manager", "owner"];

  it("a role always meets its own minimum", () => {
    for (const r of roles) {
      expect(keyRoleAtLeast(r, r)).toBe(true);
    }
  });

  it("viewer does not meet manager or owner", () => {
    expect(keyRoleAtLeast("viewer", "manager")).toBe(false);
    expect(keyRoleAtLeast("viewer", "owner")).toBe(false);
  });

  it("manager meets viewer and manager, not owner", () => {
    expect(keyRoleAtLeast("manager", "viewer")).toBe(true);
    expect(keyRoleAtLeast("manager", "manager")).toBe(true);
    expect(keyRoleAtLeast("manager", "owner")).toBe(false);
  });

  it("owner meets every minimum", () => {
    expect(keyRoleAtLeast("owner", "viewer")).toBe(true);
    expect(keyRoleAtLeast("owner", "manager")).toBe(true);
    expect(keyRoleAtLeast("owner", "owner")).toBe(true);
  });
});
