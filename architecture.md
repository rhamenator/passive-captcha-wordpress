# Architecture

```mermaid
graph TD
    subgraph UserSystem [User System]
        B[Users Browser]
        JS(passive-captcha js)
    end

    subgraph WordPressSite [WordPress Site]
        WP[WordPress Core - APIs Hooks]
        CFH[Custom Form Handler Theme-Plugin]
        PCH_PHP[Passive Captcha Plugin PHP]
        WS[Webserver JA3]
    end

    subgraph ExternalServices [External Services]
        WH((Webhook Receiver))
    end

    B -- Interacts --> JS;
    B -- Loads Page Submits Form --> CFH;
    JS -- Modifies DOM Reads pchData --> B;
    JS -- Adds Hidden Fields --> CFH;

    PCH_PHP -- Hooks into --> WP;
    PCH_PHP -- Uses --> WP;
    PCH_PHP -- Reads Settings --> WP;
    PCH_PHP -- Uses Transients --> WP;

    CFH -- Handles Form Submission --> WP;
    CFH -- Calls Function --> PCH_PHP;

    WS -- Passes Header JA3 --> PCH_PHP;
    PCH_PHP -- Sends Alert --> WH;

    style PCH_PHP fill:#ccf,stroke:#333,stroke-width:2px;
    style CFH fill:#ffc,stroke:#333,stroke-width:1px,stroke-dasharray: 5 5;
```
