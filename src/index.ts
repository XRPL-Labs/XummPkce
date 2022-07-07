import { debug as Debug } from "debug";
import { EventEmitter } from "events";
import { XummSdkJwt } from "xumm-sdk";
import PKCE from "js-pkce";

localStorage.debug = "xummpkce*";

Debug.log = console.log.bind(console);
const log = Debug("xummpkce");

// If everything else fails:
// const log = (...args: any[]) => {
//   alert(args.map((a) => JSON.stringify(a, null, 2)).join(" "));
// };

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

export interface XummPkceEvent {
  // Result returns nothing, just a trigger, the authorize() method should be called later to handle based on Promise()
  // result: (data: ResolvedFlow) => void;
  result: () => void;
}

export declare interface XummPkce {
  on<U extends keyof XummPkceEvent>(event: U, listener: XummPkceEvent[U]): this;
  off<U extends keyof XummPkceEvent>(
    event: U,
    listener: XummPkceEvent[U]
  ): this;
  // emit<U extends keyof xAppEvent>(
  //   event: U,
  //   ...args: Parameters<xAppEvent[U]>
  // ): boolean;
}

export class XummPkce extends EventEmitter {
  private pkce: PKCE;
  private popup: Window | null = null;

  private jwt?: string;

  private resolvePromise?: (result: ResolvedFlow) => void;
  private rejectPromise?: (error: Error) => void;
  private promise?: Promise<ResolvedFlow>;

  private mobileRedirectFlow: boolean = false;
  private urlParams?: URLSearchParams;

  constructor(xummApiKey: string, redirectUrl?: string) {
    super();

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
        log("Received Event from ", event.origin);
        if (String(event?.data || '').slice(0, 1) === "{" && String(event?.data || '').slice(-1) === "}") {
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
                log(
                  "Payload resolved, mostmessage containing options containing redirect URL: ",
                  postMessage
                );
                this.pkce
                  .exchangeForAccessToken(postMessage.options.full_redirect_uri)
                  .then((resp) => {
                    this.jwt = resp.access_token;

                    if ((resp as any)?.error_description) {
                      throw new Error((resp as any)?.error_description);
                    }
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
                  })
                  .catch((e) => {
                    if (this.rejectPromise) {
                      this.rejectPromise(e?.error ? new Error(e.error) : e);
                    }
                    log(e?.error || e);
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

    const params = new URLSearchParams(document?.location?.search || "");
    if (params.get("authorization_code") || params.get("error_description")) {
      this.mobileRedirectFlow = true;
      this.urlParams = params;

      document.addEventListener("readystatechange", (event) => {
        if (document.readyState === "complete") {
          log("(readystatechange: [ " + document.readyState + " ])");
          this.handleMobileGrant();
          this.emit("result");
        }
      });
    }
  }

  // Todo: document, e.g. custom flow, plugin
  public authorizeUrl() {
    return this.pkce.authorizeUrl();
  }

  private handleMobileGrant() {
    // log(document?.location?.search);
    if (this.urlParams && this.mobileRedirectFlow) {
      log("Send message event");
      const messageEventData = {
        data: JSON.stringify(
          this.urlParams.get("authorization_code")
            ? {
                source: "xumm_sign_request_resolved",
                options: {
                  full_redirect_uri: document.location.href,
                },
              }
            : {
                source: "xumm_sign_request_rejected",
                options: {
                  error: this.urlParams.get("error"),
                  error_code: this.urlParams.get("error_code"),
                  error_description: this.urlParams.get("error_description"),
                },
              }
        ),
        origin: "https://oauth2.xumm.app",
      };

      // log(messageEventData);
      const event = new MessageEvent("message", messageEventData);
      window.dispatchEvent(event);
      return true;
    }
    return false;
  }

  public async authorize() {
    if (!this.mobileRedirectFlow) {
      const url = this.authorizeUrl();
      const popup = window.open(
        url,
        "XummPkceLogin",
        "directories=no,titlebar=no,toolbar=no,location=no,status=no," +
          "menubar=no,scrollbars=no,resizable=no,width=600,height=790"
      );

      this.popup = popup;
      log("Popup opened...", url);
    }

    this.promise = new Promise((resolve, reject) => {
      this.resolvePromise = resolve;
      this.rejectPromise = reject;
    });

    return this.promise;
  }

  public getPopup() {
    return this?.popup;
  }
}
