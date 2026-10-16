import type { Frame } from "./frame";

// The one seam between the adapter and the network.
//
// Every command builder in command.ts returns a *body*: the command byte
// followed by its data bytes. Under 701Server that body was handed over as a
// `Hex` string inside `c_cmd 2000` and the server built the wire frame. Talking
// to a controller directly, we build the frame ourselves, so the wire owns
// framing and the adapter owns meaning.
export interface WireTarget {
  // SOYAL's Area (0-15). Carried because the extended frame stores it in the
  // high nibble of its length field; a standard frame has nowhere to put it.
  area: number;
  // The controller's node number. On a direct connection this is the frame's
  // DID. Measured: DID 0 and DID 1 get no reply, so DID really is addressing.
  // See docs/research/soyal-direct-probe-2026-09-14.md.
  node: number;
}

export interface SoyalWire {
  // Send one command body to one controller and return its parsed reply frame.
  // Implementations must serialise per controller: a controller answers one
  // client at a time, measured as two simultaneous sockets yielding one reply
  // and one connection closed before a complete frame.
  send(target: WireTarget, body: Uint8Array, signal?: AbortSignal): Promise<Frame>;

  // Run a sequence against one controller with nothing else interleaved. A
  // credential write is three round trips and must not be split by the event
  // poller's next tick.
  withExclusive?<ResultData>(target: WireTarget, operation: () => Promise<ResultData>): Promise<ResultData>;

  // Drop the connection to one controller so the next request starts fresh.
  reset?(target: WireTarget): void;

  // Release every connection. Called on shutdown.
  close?(): Promise<void>;
}

export type WireErrorCode = "timeout" | "connection" | "protocol" | "aborted";

export class SoyalWireError extends Error {
  public constructor(message: string, public readonly code: WireErrorCode) {
    super(message);
    this.name = "SoyalWireError";
  }
}
