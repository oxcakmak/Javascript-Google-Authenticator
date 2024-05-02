class Base32 {
  static csRFC3548 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  constructor(charset = Base32.csRFC3548) {
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
      if (charIndex === -1 || str[i] === "=") {
        throw new Error("Invalid character in Base32 string");
      }
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
}
