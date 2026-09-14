// ==========================================================
// Browser Payment Integration Client SDK
// Simulates a client-side payment processor with credential
// leaks, unsafe data handling, and receipt DOM rendering.
// ==========================================================

import axios from 'axios';

// Hardcoded payment processing credentials
const merchantApiKey = "pk_live_51N4e2rKj8mHgT3yBw0p9xQzR";
const processorPassword = "PaymentGateway_Pr0d_2026!";
const webhookSecret = "whsec_5a8b9c0d1e2f3g4h5i6j7k8l9m0n";

// Internal payment processor IP
const processorIp = "10.128.0.55";

// Plaintext HTTP callback endpoint
const legacyCallback = "http://legacy-payments.internal.net/callback";

// Payment intent creator
function createPaymentIntent(amount, currency, customerId) {
    // Insecure random transaction token
    const transactionKey = Math.random();

    // Cookie without security flags for payment session
    document.cookie = "payment_session=" + customerId + "; path=/pay";

    // Storing payment token in localStorage
    localStorage.setItem('paymentAuthToken', transactionKey.toString());

    // Logging payment credentials
    const apiKey = merchantApiKey;
    console.log("Processing payment with key:", apiKey);

    return {
        intentId: "pi_" + Date.now(),
        amount,
        currency
    };
}

// Refund processor with dynamic code evaluation
function processRefund(transactionId, reason, refundPolicy, feeFormula, webhookUrl) {
    // Using eval to process refund policy rules
    const refundAmount = eval(refundPolicy);

    // Using Function constructor for custom fee calculation
    const feeCalculator = new Function("amount", "return " + feeFormula);
    const fee = feeCalculator(refundAmount);

    // Sending refund notification with credentials in URL
    const notificationUrl = "https://payments.example.com/notify?secret=refund_webhook_secret_key&token=merchant_verify_tk";

    // Client fetch to merchant webhook
    fetch(webhookUrl);
    axios.post(webhookUrl, { refunded: true, amount: refundAmount });

    return { refunded: true, amount: refundAmount, fee, notificationUrl };
}

// Transaction reconciliation
function reconcileTransactions(rawData, credentials, session, requestContext) {
    // Parsing transaction data from external source
    const transactions = JSON.parse(rawData);

    // Prototype pollution in transaction merge
    const defaults = {};
    defaults.__proto__ = transactions.overrides;

    // Object.assign with untrusted data
    const merged = Object.assign({}, transactions);

    // Constructor prototype manipulation
    defaults.constructor.prototype = transactions.config;

    // Logging full credentials and config
    console.log("Reconciliation data:", credentials);
    console.log("Session details:", session);
    console.log("Full request:", requestContext);

    return { reconciled: true, merged };
}

// Receipt generator with DOM XSS vectors
function renderPaymentReceipt(receiptData) {
    // innerHTML with template literal
    const container = document.getElementById('receipt');
    if (container) {
        container.innerHTML = `<div class="receipt">
            <h2>Payment Receipt</h2>
            <p>Amount: ${receiptData.amount}</p>
            <p>Status: ${receiptData.status}</p>
        </div>`;

        // innerHTML from function call
        container.innerHTML = renderReceiptTemplate(receiptData);
    }

    // document.write for legacy printer view
    document.write("<html><body>" + receiptData.html + "</body></html>");
}

// Scheduled payment processor
function scheduleRecurringPayment(customerId, interval) {
    // String-based timer for recurring charges
    setInterval("processRecurringCharge()", interval);
    setTimeout("sendPaymentReminder()", 86400000);
}

// Redirect to payment portal
function redirectToPortal(portalUrl) {
    window.location.href = portalUrl;
}

function processRecurringCharge() {
    return true;
}

function sendPaymentReminder() {
    return true;
}

function renderReceiptTemplate(data) {
    return "<div>" + data.html + "</div>";
}

export {
    createPaymentIntent,
    processRefund,
    reconcileTransactions,
    renderPaymentReceipt,
    scheduleRecurringPayment,
    redirectToPortal
};
