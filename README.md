# Javascript-Google-Authenticator

Javascript Google Authenticator

2 step verification function library with Google Authenticator

### İmportant!

```js
/*
 * Since the verifyCode function accepts every code...
 * ...entered, it is under maintenance.
 * @
 * Other functions are working.
 */
```

### Call the package first

```js
const authenticator = require("js-google-authenticator");

const authenticator = new GoogleAuthenticator();
```

### Define keys

```js
// Use the GoogleAuthenticator class methods
const secretKey = "YOUR_SECRET_KEY";
const code = "123456";
```

### How to create a secret key?

```js
const secretKey = authenticator.encode(text);
```

### How to validate a key?

```js
const isValid = authenticator.verifyCode(secretKey, code);
console.log(`Code valid: ${isValid}`);
```

### How to create a otp key?

```js
// not neccessary actually
const hotpCode = authenticator.generateHOTP(secretKey, 1234567890);
console.log(`HOTP code: ${hotpCode}`);

// for qr code:
const app = authenticator.forApp(string, secretKey);
console.log(`Google Authenticator App Otp Link: ${app}`);
```

**You wanna support me?**
[https://buymeacoffee.com/oxcakmak](https://buymeacoffee.com/oxcakmak)
