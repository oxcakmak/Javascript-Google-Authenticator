// crypto.js
import { createHmac, WordArray } from "./crypto-js/hmac";
import { SHA1 } from "./crypto-js/sha1";

/**
 * Calculates an HMAC-SHA1 hash for the provided message using the given secret key.
 *
 * @param {string} secretKey The secret key used for HMAC generation.
 * @param {string} message The message to be hashed.
 * @returns {string} The HMAC-SHA1 hash as a string (choose desired output format).
 * @throws {Error} If either secretKey or message is missing.
 */
export function hmacSHA1(secretKey, message) {
  if (!secretKey || !message) {
    throw new Error("Missing required parameters: secretKey and message");
  }

  const messageBytes = WordArray.create(message);
  const hmac = createHmac(SHA1, secretKey);
  hmac.update(messageBytes);
  return hmac.finalize().toString(); // Choose desired output format (e.g., Base64, Hex)
}
