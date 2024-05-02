# Javascript-Google-Authenticator
Javascript Google Authenticator

2 step verification function library with Google Authenticator

### Call the package first
```js
const authenticator = require("google-authenticator");
```

### How to create a key?
```js
authenticator.encode(text);
```

### How to verify a key?
```js
authenticator.verify(encodedText, authenticatorCode);
```
