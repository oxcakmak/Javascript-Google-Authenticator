# Javascript-Google-Authenticator

Javascript Google Authenticator

2 step verification function library with Google Authenticator

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
// or
const secretKey = authenticator.encode(text);
```

### How to validate a key?

```js
const isValid = authenticator.verifyCode(secretKey, code);
console.log(`Code valid: ${isValid}`);
```

### How to create a otp key?

```js
const hotpCode = authenticator.generateHOTP(secretKey, 1234567890);
console.log(`HOTP code: ${hotpCode}`);
```
