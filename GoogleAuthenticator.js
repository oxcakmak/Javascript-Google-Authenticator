// Import necessary libraries (assuming Base32 is a separate module)
import Base32 from "./Base32.js"; // Replace with your preferred Base32 library

class GoogleAuthenticator {
  constructor(
    skew = Math.round(
      window.navigator.userAgent.match(/Chrome\/(\d+)/)?.[1] || 5
    )
  ) {
    // Validate and potentially adjust skew based on environment or security policy
    if (skew < 0 || skew > 15) {
      console.warn("Invalid skew value provided. Using default of 5.");
      this.skew = 5;
    } else {
      this.skew = skew;
    }
  }

  /**
   * Verifies a user-provided code against a time-based one-time password (TOTP) generated using the secret key.
   *
   * @param {string} secretkey Base32-encoded secret key
   * @param {string} code User-provided code (typically 6 digits)
   * @returns {Promise<boolean>} Resolves to true if the code is valid, false otherwise. Rejects with an Error if an issue occurs.
   */
  async verifyCode(secretkey, code) {
    if (!secretkey || !code) {
      return Promise.reject(
        new Error("Missing required parameters: secretkey and code")
      );
    }

    const base32 = new Base32(Base32.csRFC3548);
    let decodedKey;
    try {
      decodedKey = await base32.decodeAsync(secretkey);
    } catch (error) {
      return Promise.reject(
        new Error("Failed to decode secret key: " + error.message)
      );
    }

    if (code.length !== 6) {
      return Promise.reject(
        new Error("Invalid code length. Expected 6 digits.")
      );
    }

    const timestamp = Math.floor(Date.now() / 30000); // Time in 30-second intervals
    for (let i = -this.skew; i <= this.skew; i++) {
      const checkTime = timestamp + i;
      const calculatedCode = await this.generateHOTP(decodedKey, checkTime);

      if (calculatedCode === code) {
        return true;
      }
    }
    return false;
  }

  /**
   * Generates a time-based one-time password (HOTP) using the provided secret key and timestamp.
   *
   * @param {Uint8Array} key Secret key as a byte array
   * @param {number} counter Time-based counter value
   * @returns {Promise<string>} Resolves to the generated HOTP code (6 digits). Rejects with an Error if an issue occurs.
   */
  async generateHOTP(key, counter) {
    const counterBytes = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) {
      counterBytes[i] = counter & 0xff;
      counter >>= 8;
    }

    // **Important Security Note:**
    // Replace with a secure HMAC-SHA1 implementation that considers key handling and secure random number generation.
    const hash = await secureHMACSHA1(key, counterBytes);

    return this.truncateHOTP(hash);
  }

  /**
   * Truncates the generated HOTP hash to a 6-digit code.
   *
   * @param {Uint8Array} hash HMAC-SHA1 hash of the counter value
   * @returns {string} The truncated HOTP code (6 digits)
   */
  truncateHOTP(hash) {
    const offset = hash[19] & 0xf;
    const binary =
      ((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff);
    return String(binary % Math.pow(10, 6)).padStart(6, "0");
  }
}

module.exports = GoogleAuthenticator;
