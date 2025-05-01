/**
 * Passive CAPTCHA Hardened - Client-Side Logic (Configurable w/ Debug Logging & Visible Token Display)
 * Version: 3.3.3 / 4.3.3
 */
document.addEventListener('DOMContentLoaded', function() {
    console.log('PCH DEBUG: DOMContentLoaded event fired.');

    // --- Configuration ---
    const captchaFieldName = 'pch_captcha_token'; // Name for generic version hidden field
    const captchaFieldLabel = 'CAPTCHA Token'; // Label for GF version hidden field
    const debugDisplayFieldSelector = '.pch-debug-token-display input'; // Selector targets input inside the debug div class
    const minTimeMs = 3000;

    // --- Find the target fields ---
    let field = null; // The actual hidden CAPTCHA field
    let debugField = null; // The visible debug field

    // Try generic selector first for hidden field
    field = document.querySelector(`input[name="${captchaFieldName}"]`);
    if (field) {
        console.log('PCH DEBUG: Found generic hidden field via name:', field);
    } else {
        // Fallback for Gravity Forms label lookup (Refined)
        console.log('PCH DEBUG: Generic hidden field selector failed. Trying REFINED GF label lookup...');
        const gfLabels = document.querySelectorAll('.gfield_label'); // Find all potential labels first
        gfLabels.forEach(label => {
            // Check if field already found in a previous iteration
            if (field) return;

            // Trim whitespace and check if label text *exactly* matches
            if (label.textContent && label.textContent.trim() === captchaFieldLabel) {
                const container = label.closest('.gfield'); // Find the parent container
                if (container) {
                    // Find the input within this container (GF uses name attribute starting with input_)
                    const inputElement = container.querySelector('input[name^="input_"]');
                    if (inputElement) {
                        field = inputElement;
                        console.log('PCH DEBUG: Found GF field via REFINED label lookup:', field);
                    }
                }
            }
        });

         if (!field) {
             console.log('PCH DEBUG: REFINED GF label lookup also failed.');
         }
    }

    // Find the visible debug field using its selector
    debugField = document.querySelector(debugDisplayFieldSelector);
    if (debugField) {
        console.log('PCH DEBUG: Found visible debug field:', debugField);
    } else {
        console.log('PCH DEBUG: Visible debug field not found (selector: "' + debugDisplayFieldSelector + '"). Token will not be displayed visibly.');
    }


    // Exit if the main hidden field isn't found or if pchData is missing
    if (!field || typeof pchData === 'undefined') {
        if (!field) { console.warn('PCH DEBUG: Main CAPTCHA field could not be found.'); }
        if (typeof pchData === 'undefined') { console.warn('PCH DEBUG: pchData object not found.'); }
        return; // Stop script execution
    } else {
        console.log('PCH DEBUG: Main CAPTCHA field found. pchData exists:', typeof pchData !== 'undefined');
    }

    // --- Initialization ---
    const startTime = Date.now();
    let interacted = false;
    console.log('PCH DEBUG: Initializing checks. Start time:', startTime);

    // --- Interaction Detection ---
    ['mousemove', 'keydown', 'scroll', 'touchstart'].forEach(evt =>
        document.addEventListener(evt, () => {
            if (!interacted) { console.log(`PCH DEBUG: Interaction detected (${evt}).`); interacted = true; }
        }, { once: true, passive: true })
    );

    // --- Bot Detection Functions ---
    function isHeadless() { return navigator.webdriver || /HeadlessChrome/.test(navigator.userAgent) || /slimerjs/i.test(navigator.userAgent) || /phantomjs/i.test(navigator.userAgent) || !('chrome' in window) || ('languages' in navigator && navigator.languages.length === 0); }
    function hasMissingNavigatorProps() { return !navigator.plugins || navigator.plugins.length === 0 || !navigator.languages || navigator.languages.length === 0; }

    // --- Conditionally Enabled Functions ---
    function getWebGLFingerprint() { if (!pchData.enableWebGL) { return 'webgl_disabled'; } try { const canvas = document.createElement('canvas'); const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl'); if (!gl) { return 'no_webgl_support'; } const debugInfo = gl.getExtension('WEBGL_debug_renderer_info'); const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown_vendor'; const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown_renderer'; return btoa(vendor + '|' + renderer); } catch (e) { return 'webgl_error'; } }
    function invisibleMathChallenge() { if (!pchData.enableMath) { return 'math_disabled'; } const a = Math.floor(Math.random() * 10) + 1; const b = Math.floor(Math.random() * 10) + 1; return (a * b).toString(); }

    // --- Hash Building ---
    function buildNavigatorHash() { const data = [ navigator.userAgent, navigator.language, navigator.languages ? navigator.languages.join(',') : '', navigator.platform, getWebGLFingerprint(), invisibleMathChallenge() ].join('|'); return btoa(data); }

    // --- Token Generation and Field Update ---
    console.log(`PCH DEBUG: Setting timeout for ${minTimeMs}ms.`);
    setTimeout(() => {
        console.log('PCH DEBUG: Timeout executed.');

        const headlessCheck = isHeadless();
        const missingPropsCheck = hasMissingNavigatorProps();
        let finalTokenValue = 'no_interaction'; // Default value if checks fail

        if (!interacted || headlessCheck || missingPropsCheck) {
            console.log(`PCH DEBUG: Bot signal or no interaction. interacted=${interacted}, headless=${headlessCheck}, missingProps=${missingPropsCheck}.`);
            // finalTokenValue remains 'no_interaction'
        } else {
            const timeSpent = Date.now() - startTime;
            console.log(`PCH DEBUG: Time spent: ${timeSpent}ms.`);

            if (timeSpent < minTimeMs) {
                 console.log(`PCH DEBUG: Submission too fast (${timeSpent}ms < ${minTimeMs}ms).`);
                 // finalTokenValue remains 'no_interaction'
            } else {
                // All checks passed, generate the real token
                const navHash = buildNavigatorHash();
                finalTokenValue = btoa(timeSpent.toString() + ':' + navHash);
                console.log('PCH DEBUG: Token generated:', finalTokenValue);

                // Inject helper fields only if a valid token was generated
                const form = field.closest('form');
                if (form) {
                    console.log('PCH DEBUG: Parent form found:', form);
                    console.log('PCH DEBUG: Attempting to inject hidden fields...');
                    if (!form.querySelector('input[name="pch_nonce"]')) { form.insertAdjacentHTML('beforeend', `<input type="hidden" name="pch_nonce" value="${pchData.nonce}">`); console.log('PCH DEBUG: Nonce field injected.'); } else { console.log('PCH DEBUG: Nonce field already exists.'); }
                    if (!form.querySelector('input[name="pch_session"]')) { form.insertAdjacentHTML('beforeend', `<input type="hidden" name="pch_session" value="${pchData.sessionToken}">`); console.log('PCH DEBUG: Session field injected.'); } else { console.log('PCH DEBUG: Session field already exists.'); }
                    if (!form.querySelector('input[name="pch_iphash"]')) { form.insertAdjacentHTML('beforeend', `<input type="hidden" name="pch_iphash" value="${pchData.ipHash}">`); console.log('PCH DEBUG: IPhash field injected.'); } else { console.log('PCH DEBUG: IPhash field already exists.'); }
                    console.log('PCH DEBUG: Field injection process complete.');
                } else {
                    console.warn('PCH DEBUG: CAPTCHA field is not inside a <form> element. Cannot inject helper fields.');
                }
            }
        }

        // Update the ACTUAL hidden field (found via label lookup)
        field.value = finalTokenValue;
        console.log('PCH DEBUG: Set hidden field (', field.name, ') value to:', finalTokenValue);

        // Update the VISIBLE debug field if it exists
        if (debugField) {
            debugField.value = finalTokenValue;
            console.log('PCH DEBUG: Set visible debug field (', debugField.name, ') value to:', finalTokenValue);
        }

    }, minTimeMs); // Delay execution

});
