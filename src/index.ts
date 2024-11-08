// import { debug as Debug } from "debug";
import { EventEmitter } from "events";
import { XummSdkJwt } from "xumm-sdk";
import PKCE from "xumm-js-pkce";

const log = function (...args: any[]) {
  if (typeof localStorage !== "undefined") {
    if (localStorage?.debug) {
      console.log(...args);
    }
  }
};

// localStorage.debug = "xummpkce*";
// Debug.log = log.bind(console);
// const log = Debug("xummpkce");

// If everything else fails:
// const log = (...args: any[]) => {
//   alert(args.map((a) => JSON.stringify(a, null, 2)).join(" "));
// };

if (typeof window !== "undefined") {
  log("Xumm OAuth2 PKCE Authorization Code Flow lib.");
}

interface XummPkceOptions {
  redirectUrl: string;
  rememberJwt: boolean;
  storage: Storage;
  implicit: boolean;
}

export interface XummProfile {
  slug: string;
  profileUrl: string;
  accountSlug: string | null;
  payString: string | null;
}

export interface ResolvedFlow {
  sdk: XummSdkJwt;
  jwt: string;
  me: {
    sub: string;
    picture: string;
    account: string;
    name?: string | null;
    domain?: string | null;
    blocked: boolean;
    source: string;
    kycApproved: boolean;
    proSubscription: boolean;
    profile?: XummProfile;
    networkType?: string;
    networkId?: number;
    networkEndpoint?: string;
    email?: string;
  };
}

export interface XummPkceEvent {
  retrieved: () => void;
  error: (error: Error) => void;
  success: () => void;
  loggedout: () => void;
}

export declare interface XummPkceThread {
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

const EventReadyPromise = (event: keyof XummPkceEvent) => {
  let _resolve = (value?: unknown): void => {};
  const promise = new Promise((resolve) => {
    _resolve = resolve;
  });
  return {
    promise,
    resolve: (value?: unknown) => {
      // log("XummPKCE <Resolving eventReadyPromise>", event);
      return _resolve(value);
    },
  };
};

export class XummPkceThread extends EventEmitter {
  private pkce: PKCE;
  private options: XummPkceOptions;
  private popup: Window | null = null;

  private jwt?: string;

  private ping?: ReturnType<XummSdkJwt['ping']>;
  private resolved = false;
  private resolvedSuccessfully?: boolean;
  private resolvePromise?: (result: ResolvedFlow) => void;
  private rejectPromise?: (error: Error) => void;
  private promise?: Promise<ResolvedFlow>;
  private autoResolvedFlow?: ResolvedFlow;

  private mobileRedirectFlow: boolean = false;
  private urlParams?: URLSearchParams;

  private eventPromises = {
    retrieved: EventReadyPromise("retrieved"),
    error: EventReadyPromise("error"),
    success: EventReadyPromise("success"),
    loggedout: EventReadyPromise("loggedout"),
  };

  constructor(
    xummApiKey: string,
    optionsOrRedirectUrl?: string | Partial<XummPkceOptions>
  ) {
    super();

    this.options = {
      redirectUrl: document.location.href,
      rememberJwt: true,
      storage: localStorage,
      implicit: false,
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
      if (typeof optionsOrRedirectUrl.redirectUrl === "string") {
        this.options.redirectUrl = optionsOrRedirectUrl.redirectUrl;
      }
      if (typeof optionsOrRedirectUrl.rememberJwt === "boolean") {
        this.options.rememberJwt = optionsOrRedirectUrl.rememberJwt;
      }
      if (typeof optionsOrRedirectUrl.storage === "object") {
        this.options.storage = optionsOrRedirectUrl.storage;
      }
      if (typeof optionsOrRedirectUrl.implicit === "boolean") {
        this.options.implicit = optionsOrRedirectUrl.implicit;
      }
    }

    /**
     * Construct
     */
    const pkceOptions = {
      client_id: xummApiKey,
      redirect_uri: this.options.redirectUrl,
      authorization_endpoint: "https://oauth2.xumm.app/auth",
      token_endpoint: "https://oauth2.xumm.app/token",
      requested_scopes: "XummPkce",
      storage: this.options.storage,
      implicit: this.options.implicit,
    };
    // log(JSON.stringify(pkceOptions, null, 2));
    this.pkce = new PKCE(pkceOptions);

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
          this.ping = sdk.ping()
          this.ping
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
        } else {
          this.logout();
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
            } catch (e) {
              log("Error parsing message", (e as Error)?.message || e);
            }
          }
        }
      },
      false
    );

    const params = new URLSearchParams(document?.location?.search || "");
    if (
      params.get("authorization_code") ||
      params.get("access_token") ||
      params.get("error_description")
    ) {
      this.mobileRedirectFlow = true;
      this.urlParams = params;

      let documentReadyExecuted = false;
      const onDocumentReady = async (event?: Event) => {
        log("onDocumentReady", document.readyState);
        if (!documentReadyExecuted && document.readyState === "complete") {
          documentReadyExecuted = true;
          log("(readystatechange: [ " + document.readyState + " ])");
          this.handleMobileGrant();
          await this.authorize();
          this.emit("retrieved");
        }
      };

      onDocumentReady();
      document.addEventListener("readystatechange", onDocumentReady);
    }
  }

  public emit<U extends keyof XummPkceEvent>(event: U, ...args: any[]) {
    // log("emitting event", event, ...args);
    // log("subscribers for event", event, this.listenerCount(event));
    this.eventPromises[event].promise.then(() => {
      // Emit when subscribed
      return super.emit(event, ...args);
    });
    return true;
  }

  public on<U extends keyof XummPkceEvent>(
    event: U,
    listener: XummPkceEvent[U]
  ) {
    // log("event added, on", event);
    this.eventPromises[event].resolve();
    return super.on(event, listener);
  }

  public off<U extends keyof XummPkceEvent>(
    event: U,
    listener: XummPkceEvent[U]
  ) {
    // log("event removed, off", event);
    // Reset promise
    this.eventPromises[event] = EventReadyPromise(event);
    return super.off(event, listener);
  }

  // Todo: document, e.g. custom flow, plugin
  public authorizeUrl() {
    return this.pkce.authorizeUrl();
  }

  private handleMobileGrant() {
    if (this.urlParams && this.mobileRedirectFlow) {
      // log("Send message event");

      const messageEventData = {
        data: JSON.stringify(
          this.urlParams.get("authorization_code") ||
            this.urlParams.get("access_token")
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
    // Do not authorize twice
    if (this.resolvedSuccessfully) {
      return this.promise;
    }
    
    this.resolved = false;
    
    try {
      await this.ping
    } catch (e) {
      // Nope (prevent 401 error from API to bleed into auth flow)
    }

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
      const newUrlParams = new URLSearchParams(
        document?.location?.search || ""
      );
      // PKCE
      newUrlParams.delete("authorization_code");
      newUrlParams.delete("code");
      newUrlParams.delete("scope");
      newUrlParams.delete("state");
      // Implicit
      newUrlParams.delete("access_token");
      newUrlParams.delete("refresh_token");
      newUrlParams.delete("token_type");
      newUrlParams.delete("expires_in");
      const newSearchParamsString = newUrlParams.toString();

      const url =
        document.location.href.split("?")[0] +
        (newSearchParamsString !== "" ? "?" : "") +
        newSearchParamsString;

      (window as any).history.replaceState({ path: url }, "", url);
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
          this.resolvedSuccessfully = true;
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
    // log("PKCE Logout");
    setTimeout(() => this.emit("loggedout"), 0);
    try {
      this.resolved = false;
      this.resolvedSuccessfully = undefined;
      this.autoResolvedFlow = undefined;
      this.options.storage?.removeItem("XummPkceJwt");
      this.mobileRedirectFlow = false;
      this.promise = undefined
    } catch (e) {
      // Nothing to do
    }
    return;
  }

  public getPopup() {
    return this?.popup;
  }
}

const thread = (_XummPkce?: XummPkceThread): XummPkceThread => {
  let attached = false;
  if (_XummPkce) {
    if (typeof window === "object") {
      if (typeof (window as any)._XummPkce === "undefined") {
        (window as any)._XummPkce = _XummPkce;
        attached = true;
      }
    }
  }

  const instance = (window as any)?._XummPkce;

  if (instance && attached) {
    log("XummPkce attached to window");
  }

  return instance;
};

export class XummPkce {
  constructor(
    xummApiKey: string,
    optionsOrRedirectUrl?: string | Partial<XummPkceOptions>
  ) {
    if (typeof window === "undefined" || typeof document === "undefined") {
      return;
    }
    if (!thread()) {
      thread(new XummPkceThread(xummApiKey, optionsOrRedirectUrl));
    }
  }

  on<U extends keyof XummPkceEvent>(event: U, listener: XummPkceEvent[U]) {
    const t = thread();
    if (!t) {
      return;
    }
    t.on(event, listener);
    return this;
  }

  off<U extends keyof XummPkceEvent>(event: U, listener: XummPkceEvent[U]) {
    const t = thread();
    if (!t) {
      return;
    }
    t.off(event, listener);
    return this;
  }

  authorize() {
    const t = thread();
    if (!t) {
      return;
    }
    return t.authorize();
  }

  state() {
    const t = thread();
    if (!t) {
      return;
    }
    return t.state();
  }

  logout() {
    const t = thread();
    if (!t) {
      return;
    }
    return t.logout();
  }
}
