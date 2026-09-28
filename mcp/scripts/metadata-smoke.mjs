// Post-deploy check of the OAuth protected-resource metadata on the loopback
// port: right resource, right issuer, and BOTH Hangar role scopes (ZITADEL only
// asserts the roles a client requested, so clients must see both).
const metadataUrl = process.env.MCP_METADATA_URL?.trim() || "";
const resourceUrl = process.env.MCP_RESOURCE_URL?.trim() || "";
const issuer = process.env.MCP_OIDC_ISSUER?.trim() || "";
const readerRole = process.env.MCP_OIDC_READER_ROLE?.trim() || "hangar_reader";
const writerRole = process.env.MCP_OIDC_WRITER_ROLE?.trim() || "hangar_writer";
const requiredScopes = [
  `urn:zitadel:iam:org:project:role:${readerRole}`,
  `urn:zitadel:iam:org:project:role:${writerRole}`,
];

if (!metadataUrl || !resourceUrl || !issuer) {
  throw new Error("MCP_METADATA_URL, MCP_RESOURCE_URL, and MCP_OIDC_ISSUER are required");
}

const response = await fetch(metadataUrl, { signal: AbortSignal.timeout(10_000) });
if (!response.ok) throw new Error(`metadata returned HTTP ${response.status}`);
const metadata = await response.json();
if (metadata.resource !== resourceUrl) throw new Error("metadata resource does not match MCP_RESOURCE_URL");
if (!Array.isArray(metadata.authorization_servers) || !metadata.authorization_servers.includes(issuer)) {
  throw new Error("metadata does not advertise the configured OIDC issuer");
}
const missing = requiredScopes.filter(
  (scope) => !Array.isArray(metadata.scopes_supported) || !metadata.scopes_supported.includes(scope)
);
if (missing.length > 0) throw new Error(`metadata does not advertise: ${missing.join(", ")}`);
console.log(
  JSON.stringify({
    ok: true,
    resource: metadata.resource,
    issuer: metadata.authorization_servers[0],
    scopes: metadata.scopes_supported,
  })
);
