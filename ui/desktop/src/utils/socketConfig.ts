export const SOCKET_TOKEN_KEY = 'ACHILLES_SOCKET_API_TOKEN';
export const SOCKET_ORG_KEY = 'ACHILLES_SOCKET_ORG';
export const SOCKET_SIGNUP_URL = 'https://socket.dev/dashboard/create-organization';
export const SOCKET_PRICING_URL = 'https://socket.dev/pricing';
export const SOCKET_CLI_URL = 'https://docs.socket.dev/docs/socket-cli';
export const SOCKET_GITHUB_URL = 'https://docs.socket.dev/docs/github';

export function socketSecretIsSet(value: unknown): boolean {
  if (value == null) return false;
  if (typeof value === 'string') return value.trim().length > 0;
  if (typeof value === 'object' && 'maskedValue' in value) {
    const masked = (value as { maskedValue?: unknown }).maskedValue;
    return typeof masked === 'string' && masked.trim().length > 0;
  }
  return false;
}
