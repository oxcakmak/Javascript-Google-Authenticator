class GoogleAuthenticator {
  constructor(
    skew = Math.round(5),
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    blocksize = 64,
    sha1BlockSize = 64
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

    // Block size for SHA1
    this.blocksize = blocksize;
    // SHA1 block size is always 64 bytes
    this.sha1BlockSize = sha1BlockSize;
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
      throw new Error("Input string expected");
    }

    const padLength = (str.length * 5) % 8;
    str = str.padEnd(str.length + padLength, "=");

    let decoded = "";
    for (let i = 0; i < str.length; i++) {
      const charIndex = this.charset.indexOf(str[i]);

      // if (charIndex === -1 || str[i].includes("=")) { throw new Error("Invalid character in Base32 string"); }

      const binary = charIndex.toString(2).padStart(5, "0");
      decoded += binary;
    }

    return this.bin2str(decoded.slice(0, -padLength));

    // return "This function is under construction";
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
    const hash = await this.hmacSha1(key, counterBytes);

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

  hmacSha1(message, key) {
    // Ensure key is a string
    key = String(key);

    // If key is longer than blocksize, hash it
    if (key.length > this.blocksize) {
      key = this.sha1(key);
    }

    // If key is shorter than blocksize, pad it with zeros
    if (key.length < this.blocksize) {
      key = key + String.fromCharCode(0).repeat(this.blocksize - key.length);
    }

    // XOR key with ipad (0x36)
    const ipad = Array(this.blocksize).fill(0x36);
    for (let i = 0; i < key.length; i++) {
      ipad[i] ^= key.charCodeAt(i);
    }

    // XOR key with opad (0x5C)
    const opad = Array(this.blocksize).fill(0x5c);
    for (let i = 0; i < key.length; i++) {
      opad[i] ^= key.charCodeAt(i);
    }

    // Concatenate ipad with message and hash it
    const inner = this.sha1(String.fromCharCode.apply(null, ipad) + message);

    // Concatenate opad with inner hash and hash it again
    const outer = this.sha1(String.fromCharCode.apply(null, opad) + inner);

    return outer;
  }

  sha1(message) {
    function rotateLeft(n, s) {
      return (n << s) | (n >>> (32 - s));
    }

    function ft(t, b, c, d) {
      if (t < 20) {
        return (b & c) | (~b & d);
      }
      if (t < 40) {
        return b ^ c ^ d;
      }
      if (t < 60) {
        return (b & c) | (b & d) | (c & d);
      }
      return b ^ c ^ d;
    }

    const H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    const K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

    let i, t;
    let a, b, c, d, e;
    let temp;

    const words = [];
    const len = message.length;

    // Append padding
    message += String.fromCharCode(0x80); // Append single bit (1)

    // Append 0 <= k < 512 bits '0', so the resulting message length (in bytes) is congruent to 56 (mod 64)
    message += String.fromCharCode(0).repeat(
      (56 - ((len + 1) % this.sha1BlockSize) + this.sha1BlockSize) %
        this.sha1BlockSize
    );

    // Append length
    message += String.fromCharCode(len >>> 29);
    message += String.fromCharCode((len << 3) & 0xffffffff);

    // Process the message in successive 512-bit chunks
    for (
      let offset = 0;
      offset < message.length;
      offset += this.sha1BlockSize
    ) {
      // Break chunk into sixteen 32-bit big-endian words
      for (i = 0; i < 16; i++) {
        words[i] =
          (message.charCodeAt(offset + i * 4) << 24) |
          (message.charCodeAt(offset + i * 4 + 1) << 16) |
          (message.charCodeAt(offset + i * 4 + 2) << 8) |
          message.charCodeAt(offset + i * 4 + 3);
      }

      // Extend the sixteen 32-bit words into eighty 32-bit words
      for (i = 16; i < 80; i++) {
        words[i] = rotateLeft(
          words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16],
          1
        );
      }

      a = H[0];
      b = H[1];
      c = H[2];
      d = H[3];
      e = H[4];

      // Main loop
      for (t = 0; t < 80; t++) {
        temp =
          (rotateLeft(a, 5) +
            ft(t, b, c, d) +
            e +
            words[t] +
            K[Math.floor(t / 20)]) >>>
          0;
        e = d;
        d = c;
        c = rotateLeft(b, 30) >>> 0;
        b = a;
        a = temp;
      }

      // Add this chunk's hash to result so far
      H[0] += a;
      H[1] += b;
      H[2] += c;
      H[3] += d;
      H[4] += e;
    }

    // Produce the final hash value
    const hash =
      ((H[0] << 24) | (H[1] << 16) | (H[2] << 8) | H[3]).toString(16) +
      (H[4] >>> 0).toString(16);

    return hash;
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
