export const root: string;
export function mutablePath(input: string, purpose?: "state" | "file"): Promise<string>;
export function frontendAllocationRange(config: { frontendSubnet: string }): string;
