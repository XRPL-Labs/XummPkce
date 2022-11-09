# Xumm OAuth2 Authorization Code PKCE flow

Xumm JS SDK for client side only OAuth2 PKCE (Authorization Code flow) auth [![npm version](https://badge.fury.io/js/xumm-oauth2-pkce.svg)](https://badge.fury.io/js/xumm-oauth2-pkce)

Questions? https://xumm.readme.io/discuss

Demo? https://oauth2-pkce-demo.xumm.dev

NPM:
[https://www.npmjs.com/package/xumm-oauth2-pkce](https://www.npmjs.com/package/xumm-oauth2-pkce)

## Sample:

#### Promise based sample

```javascript
const xumm = new XummPkce("uuid-uuid-uuid-uuid");

const xummSignInHandler = (state) => {
  const { sdk, me } = state;
  console.log("state", me);
  // Also: sdk » xumm-sdk (npm)
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

#### Event based sample

```javascript
const xumm = new XummPkce("uuid-uuid-uuid-uuid");

xumm.on("error", (error) => {
  console.log("error", error);
});

xumm.on("success", async () => {
  const state = await xumm.state();
  console.log("success:", state.me);
  // Also: state.sdk » xumm-sdk (npm)
});

xumm.on("retrieved", async () => {
  console.log("Retrieved: from localStorage or mobile browser redirect");
  const state = await xumm.state();
  console.log("retrieved:", state.me);
  // Also: state.sdk » xumm-sdk (npm)
});
```

### CDN (browser):

A browserified version (latest) is available at [JSDelivr](https://cdn.jsdelivr.net/npm/xumm-oauth2-pkce/dist/browser.min.js) & direclty from the `xumm.app` domain:

```html
<script src="https://xumm.app/assets/cdn/xumm-oauth2-pkce.min.js"></script>
```
