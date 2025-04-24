/**
 * Passive CAPTCHA Hardened - Client-Side Logic (Generic Version)
 * Version: 4.0
 */
document.addEventListener('DOMContentLoaded', function() {

    // --- Configuration ---
    // The name attribute of the hidden input field you manually add to your form.
    const captchaFieldName = 'pch_captcha_token';
    // Minimum time (in milliseconds) required on page before generating a real token.
    const minTimeMs = 3000;

    // --- Find the target field ---
    // This selector now targets the specific field name required by the generic version.
    const field = document.querySelector(`input[name="${captchaFieldName}"]`);

    // Exit if the field isn't found or if the necessary PHP data isn't available
    if (!field || typeof pchData === 'undefined') {
        // console.warn('Passive CAPTCHA field or pchData not found.');
        return;
    }

    // --- Initialization ---
    const startTime = Date.now();
    let interacted = false; // Flag to track user interaction

    // --- Interaction Detection ---
    // Listen for common user interaction events, once per type.
    ['mousemove', 'keydown', 'scroll', 'touchstart'].forEach(evt =>
        document.addEventListener(evt, () => interacted = true, { once: true, passive: true })
    );

    // --- Bot Detection Functions ---

    // Check for signs of headless browsers (WebDriver, HeadlessChrome string, etc.)
    function isHeadless() {
        return navigator.webdriver ||
               /HeadlessChrome/.test(navigator.userAgent) || // Standard Headless Chrome UA
               /slimerjs/i.test(navigator.userAgent) || // SlimerJS
               /phantomjs/i.test(navigator.userAgent) || // PhantomJS
               !('chrome' in window) || // Check if Chrome specific objects are missing
               ('languages' in navigator && navigator.languages.length === 0); // Often empty in headless envs
    }

    // Check for missing or unusual navigator properties common in bots/emulators
    function hasMissingNavigatorProps() {
        return !navigator.plugins || navigator.plugins.length === 0 || // Missing plugins array
               !navigator.languages || navigator.languages.length === 0; // Missing languages array
    }

    // Attempt to get a WebGL fingerprint
    function getWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            // Try both standard and experimental contexts
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) {
                return 'no_webgl_support';
            }
            // Get renderer information if available
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown_vendor';
            const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown_renderer';
            // Create a simple hash (Base64 encoded)
            return btoa(vendor + '|' + renderer);
        } catch (e) {
            // console.error('WebGL fingerprinting error:', e);
            return 'webgl_error';
        }
    }

    // Perform a simple, invisible math calculation
    function invisibleMathChallenge() {
        const a = Math.floor(Math.random() * 10) + 1; // Random numbers 1-10
        const b = Math.floor(Math.random() * 10) + 1;
        // Return the result as a string
        return (a * b).toString();
    }

    // Build a combined hash from various browser properties
    function buildNavigatorHash() {
        const data = [
            navigator.userAgent,
            navigator.language,
            navigator.languages ? navigator.languages.join(',') : '', // Comma-separated languages
            navigator.platform,
            getWebGLFingerprint(), // Include WebGL hash
            invisibleMathChallenge() // Include math challenge result
        ].join('|'); // Join properties with a pipe delimiter
        // Encode the combined string in Base64
        return btoa(data);
    }

    // --- Token Generation and Field Update ---
    // Use setTimeout to delay token generation, ensuring min time and allowing interaction checks.
    setTimeout(() => {
        // Check for interaction and bot signals
        if (!interacted || isHeadless() || hasMissingNavigatorProps()) {
            // If checks fail, set the field value to 'no_interaction'
            field.value = 'no_interaction';
            // console.log('Passive CAPTCHA: Bot signal detected or no interaction.');
            return; // Stop further processing
        }

        // Calculate time spent on page
        const timeSpent = Date.now() - startTime;

        // Check minimum time requirement
        if (timeSpent < minTimeMs) {
             field.value = 'no_interaction'; // Treat as failed if too fast
             // console.log('Passive CAPTCHA: Submission too fast.');
             return;
        }

        // Generate the navigator hash
        const navHash = buildNavigatorHash();

        // Create the final token: Base64 encoded "timeSpent:navigatorHash"
        const token = btoa(timeSpent.toString() + ':' + navHash);
        field.value = token; // Update the hidden field value

        // Find the parent form of the hidden field
        const form = field.closest('form');
        if (form) {
            // Inject the nonce, session, and IP hash fields into the form just before submission might occur.
            // These fields are necessary for server-side validation.
            form.insertAdjacentHTML('beforeend', `
                <input type="hidden" name="pch_nonce" value="${pchData.nonce}">
                <input type="hidden" name="pch_session" value="${pchData.sessionToken}">
                <input type="hidden" name="pch_iphash" value="${pchData.ipHash}">
            `);
            // console.log('Passive CAPTCHA: Token and fields generated.');
        } else {
            // console.warn('Passive CAPTCHA field is not inside a <form> element.');
        }

    }, minTimeMs); // Delay execution by the minimum required time

});