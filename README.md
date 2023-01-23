# Xumm OAuth2 Authorization Code PKCE flow

#### Part of the "Xumm Universal SDK", which is the preferred way of interacting with the Xumm ecosystem from JS/TS environments: https://www.npmjs.com/package/xumm - https://github.com/XRPL-Labs/Xumm-Universal-SDK

Xumm JS SDK for client side only OAuth2 PKCE (Authorization Code flow) auth [![npm version](https://badge.fury.io/js/xumm-oauth2-pkce.svg)](https://badge.fury.io/js/xumm-oauth2-pkce)

Questions? https://xumm.readme.io/discuss

Demo? https://oauth2-pkce-demo.xumm.dev

NPM:
[https://www.npmjs.com/package/xumm-oauth2-pkce](https://www.npmjs.com/package/xumm-oauth2-pkce)

## Constructor

```
new XummPkce('api-key-uuidv4', { options })
```

#### Options

```
interface XummPkceOptions {
  redirectUrl: string;      // Defaults to `document.location.href`, e.g. to add state params.
  rememberJwt: boolean;     // Defaults to `true`
  storage: Storage;         // Defaults to window.localStorage
  implicit: boolean;        // Defaults to `false`, `true` allows x-browser sign in, but it less secure
}
```

## Samples:

#### Event based

Please note: please use the Event based sample (above) if possible: this is more compatible with future
releases than the promise-based (await/async) method as displayed below.

### See [this example (source code)](https://github.com/XRPL-Labs/XummPkce/blob/main/sample/jsmodule.html) :)

#### Events (emitted)

- `success` = User signed in successfully, `sdk.state()` returns `.me` and `.sdk` objects
- `retrieved` = Retrieved existing session after e.g. browser refresh or mobile redirect, `sdk.state()` returns `.me` and `.sdk` objects
- `error` = Error, expected (e.g. user cancelled) or unexpected (...), returns argument `error` with an `Error()` object, `sdk.state()` returns null


#### Promise based sample

```javascript
const xumm = new XummPkce("uuid-uuid-uuid-uuid");

const xummSignInHandler = (state) => {
  if (state.me) {
    const { sdk, me } = state;
    console.log("state", me);
    // Also: sdk » xumm-sdk (npm)
  }
};
// To pick up on mobile client redirects:
xumm.on("retrieved", async () => {
  console.log("Retrieved: from localStorage or mobile browser redirect");
  xummSignInHandler(await xumm.state());
});

// E.g. when clicking a button:
document.getElementById("somebutton").onclick = () => {
  xumm.authorize().then((session) => {
    xummSignInHandler(session);
  });
};
```


### CDN (browser):

A browserified version (latest) is available at [JSDelivr](https://cdn.jsdelivr.net/npm/xumm-oauth2-pkce/dist/browser.min.js) & direclty from the `xumm.app` domain:

```html
<script src="https://xumm.app/assets/cdn/xumm-oauth2-pkce.min.js"></script>
```
