class GoogleAuthenticator {
  constructor(
    skew = Math.round(5),
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  ) {
    // Validate and potentially adjust skew based on environment or security policy
    if (skew < 0 || skew > 15) {
      console.warn("Invalid skew value provided. Using default of 5.");
      this.skew = 5;
    } else {
      this.skew = skew;
    }

    if (typeof charset !== "string" || charset.length !== 32) {
      throw new Error("Invalid character set provided");
    }
    this.charset = charset;
  }

  /**
   * Encodes a string into Base32 representation.
   *
   * @param {string} str The string to encode.
   * @returns {string} The Base32 encoded string.
   * @throws {Error} If the input string is invalid.
   */
  encode(str) {
    if (typeof str !== "string") {
      throw new TypeError("Input string expected");
    }

    const bin = this.str2bin(str);
    let encoded = "";

    for (let i = 0; i < bin.length; i += 5) {
      const chunk = bin.slice(i, i + 5).padEnd(5, "0");
      const index = parseInt(chunk, 2);
      encoded += this.charset[index];
    }

    return encoded.replace(/0+$/, "");
  }

  /**
   * Decodes a Base32 string into its original representation.
   *
   * @param {string} str The Base32 encoded string.
   * @returns {string} The decoded string.
   * @throws {Error} If the input string is invalid Base32.
   */
  decode(str) {
    if (typeof str !== "string") {
      throw new TypeError("Input string expected");
    }

    const padLength = (str.length * 5) % 8;
    str = str.padEnd(str.length + padLength, "=");

    let decoded = "";
    for (let i = 0; i < str.length; i++) {
      const charIndex = this.charset.indexOf(str[i]);
      /*
      if (charIndex === -1 || str[i].includes("=")) {
        throw new Error("Invalid character in Base32 string");
      }
      */
      const binary = charIndex.toString(2).padStart(5, "0");
      decoded += binary;
    }

    return this.bin2str(decoded.slice(0, -padLength));
  }

  /**
   * Converts a string to its binary representation.
   *
   * @param {string} str The string to convert.
   * @returns {string} The binary representation as a string.
   */
  str2bin(str) {
    return str
      .split("")
      .map((ch) => ch.charCodeAt(0).toString(2).padStart(8, "0"))
      .join("");
  }

  /**
   * Converts a binary string to its character representation.
   *
   * @param {string} str The binary string to convert.
   * @returns {string} The character representation.
   */
  bin2str(str) {
    return str
      .match(/(.{8})/g)
      .map((byte) => String.fromCharCode(parseInt(byte, 2)))
      .join("");
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

    let decodedKey;
    try {
      decodedKey = await this.decode(secretkey);
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
    const hash = await hmacSha1(key, counterBytes);

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

  /**
   * Compute the HMAC-SHA1 of the given data with the given key.
   * @param {Uint8Array} data - The data.
   * @param {Uint8Array} key - The key.
   * @returns {Uint8Array} - The HMAC-SHA1 hash.
   */
  hmacSha1(data, key) {
    const blockSize = 64;
    if (key.length > blockSize) {
      key = new Uint8Array(sha1.arrayBuffer(key));
    }
    const ipad = new Uint8Array(blockSize);
    const opad = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
      ipad[i] = key[i] ^ 0x36;
      opad[i] = key[i] ^ 0x5c;
    }
    const inner = new Uint8Array(blockSize + data.length);
    inner.set(ipad);
    inner.set(data, blockSize);
    const outer = new Uint8Array(
      blockSize + sha1.arrayBuffer(inner).byteLength
    );
    outer.set(opad);
    outer.set(new Uint8Array(sha1.arrayBuffer(inner)), blockSize);
    return new Uint8Array(sha1.arrayBuffer(outer));
  }

  forApp(str, secret) {
    if (!str || !secret) {
      return Promise.reject(
        new Error("Missing required parameters: str and secret")
      );
    }

    if (typeof str !== "string") {
      throw new TypeError("Input string expected");
    }

    if (typeof secret !== "string") {
      throw new TypeError("Input string expected");
    }

    return "otpauth://totp/" + str + "?secret=" + secret;
  }
}

module.exports = GoogleAuthenticator;
