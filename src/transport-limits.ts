// Bound bytes before the SDK parses JSON or validates the request. Datto inputs
// are small scalar fields/string variable maps, not files. This ceiling does
// not limit tool responses. Both HTTP entrypoints must use the same value.
export const MAX_MCP_REQUEST_BODY_BYTES = 256 * 1024;
