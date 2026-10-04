// Process-wide SSO configuration, shared by the Express routes (index.js) and Parse triggers.
import { loadSsoConfig } from './config.js';

let current;
export function getSsoConfig() {
  if (!current) current = loadSsoConfig();
  return current;
}

// Test helper: override (or reset with undefined) the process-wide configuration.
export function setSsoConfigForTests(config) {
  current = config;
}
