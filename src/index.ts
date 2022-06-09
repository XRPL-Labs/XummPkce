import { debug as Debug } from "debug";
import { XummSdkJwt } from "xumm-sdk";
import PKCE from "js-pkce";

localStorage.debug = "xummpkce*";

Debug.log = console.log.bind(console);
const log = Debug("xummpkce");

log("Xumm OAuth2 PKCE Authorization Code Flow lib.");

interface ResolvedFlow {
  sdk: XummSdkJwt;
  jwt: string;
  me: {
    sub: string;
    picture: string;
    account: string;
    name?: string;
    domain?: string;
    blocked: boolean;
    source: string;
    kycApproved: boolean;
    proSubscription: boolean;
  };
}

export class XummPkce {
  private pkce: PKCE;
  private popup: Window | null = null;

  private jwt?: string;

  private resolvePromise?: (result: ResolvedFlow) => void;
  private rejectPromise?: (error: Error) => void;
  private promise?: Promise<ResolvedFlow>;

  constructor(xummApiKey: string, redirectUrl?: string) {
    this.pkce = new PKCE({
      client_id: xummApiKey,
      redirect_uri: redirectUrl || document.location.href,
      authorization_endpoint: "https://oauth2.xumm.app/auth",
      token_endpoint: "https://oauth2.xumm.app/token",
      requested_scopes: "XummPkce",
      storage: localStorage,
    });

    window.addEventListener(
      "message",
      (event) => {
        if (event.data.slice(0, 1) === "{" && event.data.slice(-1) === "}") {
          log("Got PostMessage with JSON");
          if (
            event.origin === "https://xumm.app" ||
            event.origin === "https://oauth2.xumm.app"
          ) {
            log(
              "Got PostMessage from https://xumm.app / https://oauth2.xumm.app"
            );
            try {
              const postMessage = JSON.parse(event.data);
              if (
                postMessage?.source === "xumm_sign_request" &&
                postMessage?.payload
              ) {
                log("Payload opened:", postMessage.payload);
              } else if (
                postMessage?.source === "xumm_sign_request_resolved" &&
                postMessage?.options
              ) {
                // log("Payload resolved:", postMessage.options);
                log("Payload resolved");
                this.pkce
                  .exchangeForAccessToken(postMessage.options.full_redirect_uri)
                  .then((resp) => {
                    this.jwt = resp.access_token;
                    // if (this.resolvePromise) {
                    //   this.resolvePromise({
                    //     jwt: this.jwt,
                    //     sdk: new XummSdkJwt(this.jwt),
                    //   });
                    // }
                    fetch("https://oauth2.xumm.app/userinfo", {
                      headers: {
                        Authorization: "Bearer " + resp.access_token,
                      },
                    })
                      .then((r) => r.json())
                      .then((me) => {
                        if (this.resolvePromise) {
                          this.resolvePromise({
                            jwt: resp.access_token,
                            sdk: new XummSdkJwt(resp.access_token),
                            me,
                          });
                        }
                      });

                    // Do stuff with the access token.
                  });
              } else if (postMessage?.source === "xumm_sign_request_rejected") {
                log("Payload rejected", postMessage?.options);
                if (this.rejectPromise) {
                  this.rejectPromise(
                    new Error(
                      postMessage?.options?.error_description ||
                        "Payload rejected"
                    )
                  );
                }
              } else {
                log("Unexpected message, skipping");
              }
            } catch (e: unknown) {
              log("Error parsing message", (e as Error)?.message || e);
            }
          }
        }
      },
      false
    );
  }

  // Todo: document, e.g. custom flow, plugin
  public authorizeUrl() {
    return this.pkce.authorizeUrl();
  }

  public async authorize() {
    const popup = window.open(
      this.authorizeUrl(),
      "XummPkceLogin",
      "directories=no,titlebar=no,toolbar=no,location=no,status=no," +
        "menubar=no,scrollbars=no,resizable=no,width=600,height=790"
    );

    this.popup = popup;
    log("Popup opened...");

    this.promise = new Promise((resolve, reject) => {
      this.resolvePromise = resolve;
      this.rejectPromise = reject;
    });

    return this.promise;
  }

  public getPopup() {
    return this.popup;
  }
}
