import { test } from "node:test";
import assert from "node:assert/strict";
import { redactSecretsInText } from "./scanner.js";

function redactsAway(text: string, raw: string): boolean {
  const r = redactSecretsInText(text);
  return r.count > 0 && !r.text.includes(raw);
}
function unchanged(text: string): boolean {
  return redactSecretsInText(text).text === text;
}

// ── #3 whole PEM block ──────────────────────────────────────────────
test("#3 masks the whole private-key PEM body, not just the BEGIN line", () => {
  const body = "MIIEpAIBAAKCAQEA1234567890abcdefGHIJKLZmnopqRSTuvwxyz9876543210";
  const pem = `-----BEGIN RSA PRIVATE KEY-----\n${body}\nabcDEF9876543210zyxw\n-----END RSA PRIVATE KEY-----`;
  assert.ok(redactsAway(pem, body), "the key body must be masked");
});

test("#3 covers ENCRYPTED and PGP private-key blocks", () => {
  const enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFKjBfBgkqabcdef1234567890ABCDEF\n-----END ENCRYPTED PRIVATE KEY-----";
  assert.ok(redactsAway(enc, "MIIFKjBfBgkqabcdef1234567890ABCDEF"));
  const pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF9x7k2m5p8q3wZ8rT3vBqrstu\n-----END PGP PRIVATE KEY BLOCK-----";
  assert.ok(redactsAway(pgp, "lQOYBF9x7k2m5p8q3wZ8rT3vBqrstu"));
});

// ── #2 connection-string userinfo ───────────────────────────────────
test("#2 masks userinfo passwords in connection strings", () => {
  assert.ok(redactsAway("DATABASE_URL=postgres://admin:s3cr3tP4ss@db.internal:5432/app", "s3cr3tP4ss"));
  assert.ok(redactsAway("uri = mongodb+srv://root:hunter2xyz@cluster0.mongodb.net/test", "hunter2xyz"));
  assert.ok(redactsAway("mysql://appuser:MyR3alPwd@127.0.0.1/db", "MyR3alPwd"));
  assert.ok(redactsAway("https://ci:gH9xQ2mN7pL4@internal.example.com/repo.git", "gH9xQ2mN7pL4"));
});

test("#2 leaves placeholder / templated userinfo and plain URLs alone", () => {
  assert.ok(unchanged("postgres://user:${DB_PASS}@host/db"));
  assert.ok(unchanged("postgres://user:<password>@host/db"));
  assert.ok(unchanged("See https://example.com/docs for the setup guide."));
});

// ── #1 unquoted env / YAML / header assignments ─────────────────────
test("#1 masks unquoted .env-style credential assignments", () => {
  assert.ok(redactsAway("DB_PASSWORD=supersecret123value", "supersecret123value"));
  assert.ok(redactsAway("API_KEY=ab12CD34ef56GH78ij90", "ab12CD34ef56GH78ij90"));
  assert.ok(redactsAway("SECRET_KEY=django-insecure-9x7k2m5p8q3w", "django-insecure-9x7k2m5p8q3w"));
});

test("#1 masks unquoted YAML and bearer-token values", () => {
  assert.ok(redactsAway("password: Abc123Def456ghi", "Abc123Def456ghi"));
  assert.ok(redactsAway("  token: aK9xQ2mN7pL4wZ8r", "aK9xQ2mN7pL4wZ8r"));
  assert.ok(redactsAway("Authorization: Bearer aK9xQ2mN7pL4wZ8rT3vB", "aK9xQ2mN7pL4wZ8rT3vB"));
});

test("#1 does not flag placeholders, env refs, code, versions, or prose", () => {
  assert.ok(unchanged("const b = process.env.SECRET;"));
  assert.ok(unchanged("const password = getPassword();"));
  assert.ok(unchanged("API_KEY=your-key-here"));
  assert.ok(unchanged("DB_PASSWORD=xxxxxxxxxx"));
  assert.ok(unchanged("APP_SECRET=1.2.3"));
  assert.ok(unchanged("token: abc"));
  assert.ok(unchanged("Remember my password: is kept in the vault safely"));
  assert.ok(unchanged("name: my-service-handler-component"));
});
