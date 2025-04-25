/**
 * Passive CAPTCHA Hardened - Client-Side Logic (Generic Version - Configurable)
 * Version: 4.2
 */
document.addEventListener('DOMContentLoaded', function() {

    // --- Configuration ---
    const captchaFieldName = 'pch_captcha_token';
    const minTimeMs = 3000; // Base minimum time (server-side check is now configurable)

    // --- Find the target field ---
    const field = document.querySelector(`input[name="${captchaFieldName}"]`);

    // Exit if the field isn't found or if the necessary PHP data isn't available
    // pchData should now include enableWebGL and enableMath flags
    if (!field || typeof pchData === 'undefined') {
        // console.warn('Passive CAPTCHA field or pchData not found.');
        return;
    }

    // --- Initialization ---
    const startTime = Date.now();
    let interacted = false;

    // --- Interaction Detection ---
    ['mousemove', 'keydown', 'scroll', 'touchstart'].forEach(evt =>
        document.addEventListener(evt, () => interacted = true, { once: true, passive: true })
    );

    // --- Bot Detection Functions ---
    function isHeadless() { /* ... same as before ... */
        return navigator.webdriver ||
               /HeadlessChrome/.test(navigator.userAgent) ||
               /slimerjs/i.test(navigator.userAgent) ||
               /phantomjs/i.test(navigator.userAgent) ||
               !('chrome' in window) ||
               ('languages' in navigator && navigator.languages.length === 0);
    }
    function hasMissingNavigatorProps() { /* ... same as before ... */
        return !navigator.plugins || navigator.plugins.length === 0 ||
               !navigator.languages || navigator.languages.length === 0;
    }

    // --- Conditionally Enabled Functions ---
    function getWebGLFingerprint() {
        // Only run if enabled via pchData
        if (!pchData.enableWebGL) {
            return 'webgl_disabled';
        }
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) { return 'no_webgl_support'; }
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown_vendor';
            const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown_renderer';
            return btoa(vendor + '|' + renderer);
        } catch (e) {
            return 'webgl_error';
        }
    }

    function invisibleMathChallenge() {
        // Only run if enabled via pchData
        if (!pchData.enableMath) {
            return 'math_disabled';
        }
        const a = Math.floor(Math.random() * 10) + 1;
        const b = Math.floor(Math.random() * 10) + 1;
        return (a * b).toString();
    }

    // --- Hash Building ---
    function buildNavigatorHash() {
        const data = [
            navigator.userAgent,
            navigator.language,
            navigator.languages ? navigator.languages.join(',') : '',
            navigator.platform,
            // Conditionally include WebGL and Math results
            getWebGLFingerprint(),
            invisibleMathChallenge()
        ].join('|');
        return btoa(data);
    }

    // --- Token Generation and Field Update ---
    setTimeout(() => {
        if (!interacted || isHeadless() || hasMissingNavigatorProps()) {
            field.value = 'no_interaction';
            return;
        }

        const timeSpent = Date.now() - startTime;
        // Basic client-side time check (server check is now configurable and primary)
        if (timeSpent < minTimeMs) {
             field.value = 'no_interaction';
             return;
        }

        const navHash = buildNavigatorHash();
        const token = btoa(timeSpent.toString() + ':' + navHash);
        field.value = token;

        const form = field.closest('form');
        if (form) {
            // Inject other fields needed for server validation
            form.insertAdjacentHTML('beforeend', `
                <input type="hidden" name="pch_nonce" value="${pchData.nonce}">
                <input type="hidden" name="pch_session" value="${pchData.sessionToken}">
                <input type="hidden" name="pch_iphash" value="${pchData.ipHash}">
            `);
        } else {
            // console.warn('Passive CAPTCHA field is not inside a <form> element.');
        }

    }, minTimeMs); // Delay execution

});
```

// --- End of Script ---
// This script is designed to be included in the HTML of a page where the Passive CAPTCHA is implemented.
// It should be loaded after the pchData variable is defined and the target input field is present in the DOM.