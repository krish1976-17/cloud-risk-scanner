"use strict";

(function (root) {
  const booleanFields = {
    s3_bucket: ["public_access", "encryption_enabled", "logging_enabled"],
    rds_instance: ["publicly_accessible", "encryption_enabled", "backup_enabled"],
    iam_user: ["mfa_enabled"],
    iam_identity: ["mfa_enabled"],
    cloudtrail: ["logging_enabled", "multi_region"],
    ebs_volume: ["encryption_enabled"]
  };
  const supportedTypes = new Set([
    "s3_bucket", "security_group", "rds_instance", "iam_user",
    "iam_identity", "cloudtrail", "ebs_volume"
  ]);

  function validateResources(resources) {
    if (!Array.isArray(resources)) return "Your JSON must contain an array of resource objects.";
    if (resources.length > 10000) return "This demo accepts up to 10,000 resources at a time.";
    for (const [index, resource] of resources.entries()) {
      const label = "Resource " + (index + 1);
      if (!resource || typeof resource !== "object" || Array.isArray(resource)) return label + " must be an object.";
      if (typeof resource.type !== "string" || !resource.type.trim()) return label + " needs a string 'type' property.";
      if (!supportedTypes.has(resource.type)) return label + " has unsupported type '" + resource.type + "'. Supported types: " + [...supportedTypes].join(", ") + ".";
      if (resource.name !== undefined && typeof resource.name !== "string") return label + ": 'name' must be a string.";
      for (const field of booleanFields[resource.type] || []) {
        if (resource[field] !== undefined && typeof resource[field] !== "boolean") return label + ": '" + field + "' must be true or false.";
      }
      if (resource.type === "s3_bucket" && resource.acl !== undefined && typeof resource.acl !== "string") return label + ": 'acl' must be a string.";
      if (["iam_user", "iam_identity"].includes(resource.type) && resource.access_key_age_days !== undefined &&
          (typeof resource.access_key_age_days === "boolean" ||
           (typeof resource.access_key_age_days === "string" && !resource.access_key_age_days.trim()) ||
           !Number.isFinite(Number(resource.access_key_age_days)) || Number(resource.access_key_age_days) < 0)) {
        return label + ": 'access_key_age_days' must be a non-negative number.";
      }
      if (resource.type === "security_group" && resource.ingress !== undefined) {
        if (!Array.isArray(resource.ingress)) return label + ": 'ingress' must be an array.";
        for (const [ruleIndex, rule] of resource.ingress.entries()) {
          const ruleLabel = label + ": ingress rule " + (ruleIndex + 1);
          if (!rule || typeof rule !== "object" || Array.isArray(rule)) return ruleLabel + " must be an object.";
          const portIsValid = typeof rule.port === "number" ? Number.isInteger(rule.port) :
            typeof rule.port === "string" && /^\d+$/.test(rule.port.trim());
          if (rule.port !== undefined && (!portIsValid || Number(rule.port) < 0 || Number(rule.port) > 65535)) return ruleLabel + " has an invalid port (use 0–65535).";
          if (rule.cidr !== undefined && typeof rule.cidr !== "string") return ruleLabel + " 'cidr' must be a string.";
        }
      }
    }
    return "";
  }

  root.validateResources = validateResources;
  if (typeof module !== "undefined" && module.exports) module.exports = { validateResources };
})(typeof globalThis !== "undefined" ? globalThis : this);
