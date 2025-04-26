/**
 * Passive CAPTCHA Hardened - Client-Side Logic (Configurable w/ Debug Logging)
 * Version: 3.3 / 4.3
 */
document.addEventListener('DOMContentLoaded', function() {
    console.log('PCH DEBUG: DOMContentLoaded event fired.'); // Log script start

    // --- Configuration ---
    const captchaFieldName = 'pch_captcha_token'; // Name for generic version
    const captchaFieldLabel = 'CAPTCHA Token'; // Label for GF version
    const minTimeMs = 3000; // Base minimum time (server-side check is now configurable)

    // --- Find the target field ---
    // Try generic selector first, then GF label-based lookup
    let field = document.querySelector(`input[name="${captchaFieldName}"]`);

    if (!field) {
        console.log('PCH DEBUG: Generic field selector failed. Trying GF label lookup...');
        // Fallback for Gravity Forms: Find hidden input associated with the label
        const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
        hiddenInputs.forEach(input => {
            let labelElement = null;
            const gfieldDiv = input.closest('.gfield'); // Standard GF field container
            if (gfieldDiv) {
                labelElement = gfieldDiv.querySelector('.gfield_label');
            }
            // Check label text content if found
            if (labelElement && labelElement.textContent && labelElement.textContent.includes(captchaFieldLabel)) {
                field = input;
                console.log('PCH DEBUG: Found GF field via label:', field);
            }
        });
    } else {
         console.log('PCH DEBUG: Found generic field via name:', field);
    }


    // Exit if the field isn't found or if the necessary PHP data isn't available
    if (!field || typeof pchData === 'undefined') {
        if (!field) {
             console.warn('PCH DEBUG: Passive CAPTCHA field not found using either method.');
        }
        if (typeof pchData === 'undefined') {
             console.warn('PCH DEBUG: pchData object not found. Check wp_localize_script.');
        }
        return;
    } else {
         console.log('PCH DEBUG: CAPTCHA field found. pchData exists:', typeof pchData !== 'undefined');
    }

    // --- Initialization ---
    const startTime = Date.now();
    let interacted = false;
    console.log('PCH DEBUG: Initializing checks. Start time:', startTime);

    // --- Interaction Detection ---
    ['mousemove', 'keydown', 'scroll', 'touchstart'].forEach(evt =>
        document.addEventListener(evt, () => {
            if (!interacted) {
                 console.log(`PCH DEBUG: Interaction detected (${evt}).`);
                 interacted = true;
            }
        }, { once: true, passive: true })
    );

    // --- Bot Detection Functions ---
    function isHeadless() {
        const headless = navigator.webdriver ||
               /HeadlessChrome/.test(navigator.userAgent) ||
               /slimerjs/i.test(navigator.userAgent) ||
               /phantomjs/i.test(navigator.userAgent) ||
               !('chrome' in window) ||
               ('languages' in navigator && navigator.languages.length === 0);
        // console.log('PCH DEBUG: isHeadless check:', headless); // Optional: uncomment for detailed checks
        return headless;
    }
    function hasMissingNavigatorProps() {
        const missingProps = !navigator.plugins || navigator.plugins.length === 0 ||
               !navigator.languages || navigator.languages.length === 0;
        // console.log('PCH DEBUG: hasMissingNavigatorProps check:', missingProps); // Optional: uncomment
        return missingProps;
    }

    // --- Conditionally Enabled Functions ---
    function getWebGLFingerprint() {
        if (!pchData.enableWebGL) { return 'webgl_disabled'; }
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) { return 'no_webgl_support'; }
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown_vendor';
            const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown_renderer';
            return btoa(vendor + '|' + renderer);
        } catch (e) { return 'webgl_error'; }
    }

    function invisibleMathChallenge() {
        if (!pchData.enableMath) { return 'math_disabled'; }
        const a = Math.floor(Math.random() * 10) + 1;
        const b = Math.floor(Math.random() * 10) + 1;
        return (a * b).toString();
    }

    // --- Hash Building ---
    function buildNavigatorHash() {
        const data = [
            navigator.userAgent, navigator.language,
            navigator.languages ? navigator.languages.join(',') : '', navigator.platform,
            getWebGLFingerprint(), invisibleMathChallenge()
        ].join('|');
        const hash = btoa(data);
        // console.log('PCH DEBUG: Built navigator hash:', hash); // Optional: uncomment
        return hash;
    }

    // --- Token Generation and Field Update ---
    console.log(`PCH DEBUG: Setting timeout for ${minTimeMs}ms.`);
    setTimeout(() => {
        console.log('PCH DEBUG: Timeout executed.');

        const headlessCheck = isHeadless();
        const missingPropsCheck = hasMissingNavigatorProps();

        if (!interacted || headlessCheck || missingPropsCheck) {
            field.value = 'no_interaction';
            console.log(`PCH DEBUG: Bot signal detected or no interaction. interacted=${interacted}, headless=${headlessCheck}, missingProps=${missingPropsCheck}. Setting value to 'no_interaction'.`);
            return; // Stop further processing
        }

        const timeSpent = Date.now() - startTime;
        console.log(`PCH DEBUG: Time spent: ${timeSpent}ms.`);

        // Basic client-side time check (server check is primary)
        if (timeSpent < minTimeMs) {
             field.value = 'no_interaction';
             console.log(`PCH DEBUG: Submission too fast (${timeSpent}ms < ${minTimeMs}ms). Setting value to 'no_interaction'.`);
             return;
        }

        const navHash = buildNavigatorHash();
        const token = btoa(timeSpent.toString() + ':' + navHash);
        field.value = token;
        console.log('PCH DEBUG: Token generated and field value set:', token);

        // Find the parent form of the hidden field
        const form = field.closest('form');
        if (form) {
            console.log('PCH DEBUG: Parent form found:', form);
            console.log('PCH DEBUG: Attempting to inject hidden fields...');

            // Inject the nonce field if it doesn't exist
            if (!form.querySelector('input[name="pch_nonce"]')) {
                 form.insertAdjacentHTML('beforeend', `<input type="hidden" name="pch_nonce" value="${pchData.nonce}">`);
                 console.log('PCH DEBUG: Nonce field injected.');
            } else {
                 console.log('PCH DEBUG: Nonce field already exists.');
            }

            // Inject the session token field if it doesn't exist
            if (!form.querySelector('input[name="pch_session"]')) {
                 form.insertAdjacentHTML('beforeend', `<input type="hidden" name="pch_session" value="${pchData.sessionToken}">`);
                 console.log('PCH DEBUG: Session field injected.');
            } else {
                 console.log('PCH DEBUG: Session field already exists.');
            }

             // Inject the IP hash field if it doesn't exist
             if (!form.querySelector('input[name="pch_iphash"]')) {
                 form.insertAdjacentHTML('beforeend', `<input type="hidden" name="pch_iphash" value="${pchData.ipHash}">`);
                 console.log('PCH DEBUG: IPhash field injected.');
            } else {
                console.log('PCH DEBUG: IPhash field already exists.');
            }
             console.log('PCH DEBUG: Field injection process complete.');

        } else {
            // This is a critical warning if the hidden field isn't within a form
            console.warn('PCH DEBUG: CAPTCHA field is not inside a <form> element. Cannot inject helper fields.');
        }

    }, minTimeMs); // Delay execution

});
