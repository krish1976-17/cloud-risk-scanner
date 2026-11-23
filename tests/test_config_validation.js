"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { validateResources } = require("../config-validation.js");

test("accepts supported resource objects with optional fields", () => {
  assert.equal(validateResources([
    { type: "s3_bucket", name: "uploads", public_access: false },
    { type: "security_group", ingress: [{ port: 443, cidr: "0.0.0.0/0" }] }
  ]), "");
});

test("rejects unsupported types rather than silently scanning zero rules", () => {
  assert.match(validateResources([{ type: "azure_storage" }]), /unsupported type 'azure_storage'/);
});

test("validates booleans, ages, and ingress rules", () => {
  assert.match(validateResources([{ type: "rds_instance", encryption_enabled: "false" }]), /encryption_enabled/);
  assert.match(validateResources([{ type: "iam_user", access_key_age_days: -1 }]), /non-negative number/);
  assert.match(validateResources([{ type: "iam_user", access_key_age_days: true }]), /non-negative number/);
  assert.match(validateResources([{ type: "security_group", ingress: [{ port: "" }] }]), /invalid port/);
  assert.match(validateResources([{ type: "security_group", ingress: [{ port: 70000 }] }]), /invalid port/);
});

test("rejects malformed arrays and resource entries", () => {
  assert.match(validateResources({ type: "s3_bucket" }), /must contain an array/);
  assert.match(validateResources([null]), /Resource 1 must be an object/);
  assert.match(validateResources([{ type: "" }]), /needs a string 'type'/);
});
