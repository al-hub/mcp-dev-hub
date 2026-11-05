import test from "node:test";
import assert from "node:assert/strict";
import { safeBearer } from "../src/dashboard/read-only-server.mjs";

const VALID_TOKEN = "synthetic-token-0123456789abcdef";

test("safeBearer authenticates only exact Bearer prefix and synthetic 32-character token", () => {
  assert.equal(VALID_TOKEN.length, 32);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN, VALID_TOKEN), true);
});

test("safeBearer rejects missing or non-string header and expected token", () => {
  assert.equal(safeBearer(undefined, VALID_TOKEN), false);
  assert.equal(safeBearer(null, VALID_TOKEN), false);
  assert.equal(safeBearer(12345, VALID_TOKEN), false);
  assert.equal(safeBearer({}, VALID_TOKEN), false);
  assert.equal(safeBearer(["Bearer " + VALID_TOKEN], VALID_TOKEN), false);
  assert.equal(safeBearer("", VALID_TOKEN), false);

  assert.equal(safeBearer("Bearer " + VALID_TOKEN, undefined), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN, null), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN, 12345), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN, {}), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN, [VALID_TOKEN]), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN, ""), false);
});

test("safeBearer rejects expected tokens shorter than 24 characters", () => {
  const short23 = "synthetic-short-0123456";
  const short1 = "x";
  assert.equal(short23.length, 23);
  assert.equal(safeBearer("Bearer " + short23, short23), false);
  assert.equal(safeBearer("Bearer " + short1, short1), false);
});

test("safeBearer rejects wrong Bearer prefix casing and spacing", () => {
  assert.equal(safeBearer("bearer " + VALID_TOKEN, VALID_TOKEN), false);
  assert.equal(safeBearer("BEARER " + VALID_TOKEN, VALID_TOKEN), false);
  assert.equal(safeBearer("BeArEr " + VALID_TOKEN, VALID_TOKEN), false);
  assert.equal(safeBearer("Basic " + VALID_TOKEN, VALID_TOKEN), false);
  assert.equal(safeBearer("Bearer" + VALID_TOKEN, VALID_TOKEN), false);
  assert.equal(safeBearer("Bearer  " + VALID_TOKEN, VALID_TOKEN), false);
  assert.equal(safeBearer("Bearer\t" + VALID_TOKEN, VALID_TOKEN), false);
  assert.equal(safeBearer(" Bearer " + VALID_TOKEN, VALID_TOKEN), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN + " ", VALID_TOKEN), false);
  assert.equal(safeBearer(VALID_TOKEN, VALID_TOKEN), false);
});

test("safeBearer rejects wrong token content, length, unicode, and newline corruption", () => {
  assert.equal(safeBearer("Bearer synthetic-token-0123456789abcdeg", VALID_TOKEN), false);
  assert.equal(safeBearer("Bearer Synthetic-token-0123456789abcdef", VALID_TOKEN), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN.slice(0, 31), VALID_TOKEN), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN + "0", VALID_TOKEN), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN + "\n", VALID_TOKEN), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN + "\r", VALID_TOKEN), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN.slice(0, 31) + "\n", VALID_TOKEN), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN.slice(0, 31) + "\0", VALID_TOKEN), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN.slice(0, 31) + "é", VALID_TOKEN), false);
  assert.equal(safeBearer("Bearer " + VALID_TOKEN.slice(0, 28) + "🔒", VALID_TOKEN), false);
});
