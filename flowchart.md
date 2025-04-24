# Flowchart

```mermaid
graph TD
    subgraph Client_Side [Client Side Logic]
        A[Page Load with Form + Hidden Field] --> B(WP Enqueues JS + pchData);
        B --> C{DOM Ready?};
        C -- Yes --> D[Start Timer, Listen for Interaction];
        D --> E{Wait 3s+ and Interaction?};
        E -- No / Bot Signal --> F[Set Hidden Field = no_interaction];
        E -- Yes --> G[Calculate Token Time-Hash];
        G --> H[Set Hidden Field = Token];
        H --> I[Inject Nonce/Session/IPHash Fields];
        I --> J(Ready to Submit);
        F --> J;
    end

    subgraph Server_Side [Server Side Logic]
        K[User Submits Form POST] --> L(WP Routes to Custom Form Handler);
        L --> M[Handler Calls pch_verify_submission];
        M --> N{PCH IP Blacklisted?};
        N -- Yes --> RET_ERROR_BLACKLIST[Return WP_Error ip_blacklisted];
        N -- No --> O{PCH IP Whitelisted?};
        O -- Yes --> RET_SUCCESS[Return true];
        O -- No --> P{PCH JA3 Header OK?};
        P -- No --> Q[PCH Register Failure];
        Q --> R(PCH Send JA3 Webhook);
        R --> RET_ERROR_JA3[Return WP_Error ja3_invalid];
        P -- Yes --> S{PCH Rate Limit Exceeded?};
        S -- Yes --> RET_ERROR_RATE[Return WP_Error rate_limit_exceeded];
        S -- No --> T{PCH Nonce Valid?};
        T -- No --> U[PCH Register Failure];
        U --> RET_ERROR_NONCE[Return WP_Error nonce_invalid];
        T -- Yes --> V{PCH Session Valid? Check Transient};
        V -- No --> W[PCH Register Failure];
        W --> RET_ERROR_SESSION[Return WP_Error session_invalid];
        V -- Yes --> X{PCH IP-UA Hash Matches?};
        X -- No --> Y[PCH Register Failure];
        Y --> Z[PCH Delete Session Transient];
        Z --> RET_ERROR_IPUA[Return WP_Error ip_ua_mismatch];
        X -- Yes --> AA{PCH Token Value OK? no_interaction or empty};
        AA -- No --> BB[PCH Register Failure];
        BB --> CC[PCH Delete Session Transient];
        CC --> RET_ERROR_INTERACTION[Return WP_Error no_interaction];
        AA -- Yes --> DD{PCH Token Format OK? Decode-Colon};
        DD -- No --> EE[PCH Register Failure];
        EE --> FF[PCH Delete Session Transient];
        FF --> RET_ERROR_FORMAT[Return WP_Error token_invalid_format];
        DD -- Yes --> GG{PCH Timing and Hash Length OK?};
        GG -- No --> HH[PCH Register Failure];
        HH --> II[PCH Delete Session Transient];
        II --> RET_ERROR_TIMEHASH[Return WP_Error timing_or_fingerprint_invalid];
        GG -- Yes --> JJ[PCH Delete Session Transient];
        JJ --> RET_SUCCESS;
    end

    subgraph Outcome [Form Processing Outcome]
        RET_ERROR_BLACKLIST --> HandleError{Handler Handles WP_Error e.g. Show Message};
        RET_ERROR_JA3 --> HandleError;
        RET_ERROR_RATE --> HandleError;
        RET_ERROR_NONCE --> HandleError;
        RET_ERROR_SESSION --> HandleError;
        RET_ERROR_IPUA --> HandleError;
        RET_ERROR_INTERACTION --> HandleError;
        RET_ERROR_FORMAT --> HandleError;
        RET_ERROR_TIMEHASH --> HandleError;
        RET_SUCCESS --> ProcessForm{Handler Processes Form Data Email DB etc};
        ProcessForm --> FinalSuccess{Show Confirmation or Redirect};
        HandleError --> End{Stop Processing or Show Error Page};
    end

     J --> K;```
