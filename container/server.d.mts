import type { Server } from "node:http";

export interface LoopbackFixtureOptions {
  allowLoopback: true;
  allowedPorts: number[];
  ca: string;
  resolverUrl: string;
}

/** The fixture gate is accepted only in an explicitly controlled local test process. */
export function createEgressServer(options: { token: string; test?: LoopbackFixtureOptions }): Server;
