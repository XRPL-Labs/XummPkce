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

interface XummPkceOptions {
  redirectUrl: string;
  rememberJwt: boolean;
  storage: Storage;
}

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
  retrieved: () => void;
  error: (error: Error) => void;
  success: () => void;
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
  private options: XummPkceOptions;
  private popup: Window | null = null;

  private jwt?: string;

  private resolved = false;
  private resolvePromise?: (result: ResolvedFlow) => void;
  private rejectPromise?: (error: Error) => void;
  private promise?: Promise<ResolvedFlow>;
  private autoResolvedFlow?: ResolvedFlow;

  private mobileRedirectFlow: boolean = false;
  private urlParams?: URLSearchParams;

  constructor(
    xummApiKey: string,
    optionsOrRedirectUrl?: string | XummPkceOptions
  ) {
    super();

    this.options = {
      redirectUrl: document.location.href,
      rememberJwt: true,
      storage: localStorage,
    };

    /**
     * Apply options
     */
    if (typeof optionsOrRedirectUrl === "string") {
      this.options.redirectUrl = optionsOrRedirectUrl;
    } else if (
      typeof optionsOrRedirectUrl === "object" &&
      optionsOrRedirectUrl
    ) {
      if (typeof this.options.redirectUrl === "string") {
        this.options.redirectUrl = this.options.redirectUrl;
      }
      if (typeof this.options.rememberJwt === "boolean") {
        this.options.rememberJwt = this.options.rememberJwt;
      }
      if (typeof this.options.storage === "object") {
        this.options.storage = this.options.storage;
      }
    }

    /**
     * Construct
     */
    this.pkce = new PKCE({
      client_id: xummApiKey,
      redirect_uri: this.options.redirectUrl,
      authorization_endpoint: "https://oauth2.xumm.app/auth",
      token_endpoint: "https://oauth2.xumm.app/token",
      requested_scopes: "XummPkce",
      storage: this.options.storage,
    });

    /**
     * Check if there is already a valid JWT to be used
     */
    if (this.options.rememberJwt) {
      log("Remember JWT");
      try {
        const existingJwt = JSON.parse(
          this.options.storage?.getItem("XummPkceJwt") || "{}"
        );

        if (existingJwt?.jwt && typeof existingJwt.jwt === "string") {
          const sdk = new XummSdkJwt(existingJwt.jwt);
          sdk
            .ping()
            .then(async (pong) => {
              /**
               * Pretend mobile so no window.open is triggered
               */
              if (pong?.jwtData?.sub) {
                // Yay, user still signed in, JWT still valid!
                this.autoResolvedFlow = Object.assign(existingJwt, { sdk });
                await this.authorize();
                this.emit("retrieved");
              } else {
                this.logout();
              }
            })
            .catch((e) => {
              // That didn't work
              this.logout();
            });
        }
      } catch (e) {
        // Do nothing
      }
    }

    window.addEventListener(
      "message",
      (event) => {
        log("Received Event from ", event.origin);
        if (
          String(event?.data || "").slice(0, 1) === "{" &&
          String(event?.data || "").slice(-1) === "}"
        ) {
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

                /**
                 * Beat the 750ms timing for the window close as the exchange
                 * may still take a whil (async HTTP call). We don't know YET
                 * if we resolved successfully but we sure did resolve.
                 */
                this.resolved = true;

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
                          if (this.options.rememberJwt) {
                            log("Remembering JWT");
                            try {
                              this.options.storage?.setItem(
                                "XummPkceJwt",
                                JSON.stringify({ jwt: resp.access_token, me })
                              );
                            } catch (e) {
                              log("Could not persist JWT to local storage", e);
                            }
                          }

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
              } else if (
                postMessage?.source === "xumm_sign_request_popup_closed"
              ) {
                log("Popup closed, wait 750ms");
                // Wait, maybe the real reason comes in later (e.g. explicitly rejected)
                setTimeout(() => {
                  if (!this.resolved && this.rejectPromise) {
                    this.rejectPromise(new Error("Sign In window closed"));
                  }
                }, 750);
              } else {
                log("Unexpected message, skipping", postMessage?.source);
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

      document.addEventListener("readystatechange", async (event) => {
        if (document.readyState === "complete") {
          log("(readystatechange: [ " + document.readyState + " ])");
          this.handleMobileGrant();
          await this.authorize();
          this.emit("retrieved");
        }
      });
    }
  }

  // Todo: document, e.g. custom flow, plugin
  public authorizeUrl() {
    return this.pkce.authorizeUrl();
  }

  private handleMobileGrant() {
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

      const event = new MessageEvent("message", messageEventData);
      window.dispatchEvent(event);

      return true;
    }
    return false;
  }

  public async authorize() {
    if (!this.mobileRedirectFlow && !this.autoResolvedFlow) {
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

    this.resolved = false;

    const clearUrlParams = () => {
      if (this.urlParams && this.mobileRedirectFlow) {
        const newUrlParams = new URLSearchParams(
          document?.location?.search || ""
        );
        newUrlParams.delete("authorization_code");
        newUrlParams.delete("code");
        newUrlParams.delete("state");
        const newSearchParamsString = newUrlParams.toString();

        history.replaceState(
          {},
          "",
          document.location.href.split("?")[0] +
            (newSearchParamsString !== "" ? "?" : "") +
            newSearchParamsString
        );
      }
    };

    clearUrlParams();

    if (this.autoResolvedFlow) {
      if (!this.resolved) {
        this.resolved = true;
        this.promise = Promise.resolve(this.autoResolvedFlow);
        this.rejectPromise = this.resolvePromise = () => {};
        log("Auto resolved");
        this.emit("success");
      }
    } else {
      this.promise = new Promise((resolve, reject) => {
        this.resolvePromise = (_) => {
          const resolved = resolve(_);
          this.resolved = true;
          log("Xumm Sign in RESOLVED");
          this.emit("success");
          return resolved;
        };
        this.rejectPromise = (_) => {
          const rejected = reject(_);
          this.resolved = true;
          this.emit("error", typeof _ === "string" ? new Error(_) : _);
          log("Xumm Sign in REJECTED");
          return rejected;
        };
      });
    }

    return this.promise;
  }

  public async state() {
    return this.promise;
  }

  public logout() {
    try {
      this.resolved = false;
      this.autoResolvedFlow = undefined;
      this.options.storage?.removeItem("XummPkceJwt");
    } catch (e) {
      // Nothing to do
    }
    return;
  }

  public getPopup() {
    return this?.popup;
  }
}
