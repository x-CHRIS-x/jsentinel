// ==========================================================
// Payment Processing Microservice
// Simulates a Stripe-like payment processor with PCI
// compliance violations, credential leaks, and unsafe
// data handling patterns.
// ==========================================================

const express = require('express');
const app = express();
app.use(express.json());

// Hardcoded payment processing credentials
const merchantApiKey = "pk_live_51N4e2rKj8mHgT3yBw0p9xQzR";
const processorPassword = "PaymentGateway_Pr0d_2026!";
const webhookSecret = "whsec_5a8b9c0d1e2f3g4h5i6j7k8l9m0n";

// Internal payment processor IP
const processorIp = "10.128.0.55";

// Plaintext HTTP callback endpoint
const legacyCallback = "http://legacy-payments.internal.net/callback";

// Payment intent creator
app.post('/payments/create-intent', (req, res) => {
    const { amount, currency, customerId } = req.body;

    // Insecure random transaction token
    const transactionKey = Math.random();
    
    // Cookie without security flags for payment session
    document.cookie = "payment_session=" + customerId + "; path=/pay";

    // Storing payment token in localStorage
    localStorage.setItem('paymentAuthToken', transactionKey.toString());

    // Logging payment credentials
    const apiKey = merchantApiKey;
    console.log("Processing payment with key:", apiKey);

    res.json({
        intentId: "pi_" + Date.now(),
        amount,
        currency
    });
});

// Refund processor with dynamic code evaluation
app.post('/payments/refund', (req, res) => {
    const { transactionId, reason, refundPolicy } = req.body;

    // Using eval to process refund policy rules
    const refundAmount = eval(refundPolicy);

    // Using Function constructor for custom fee calculation
    const feeCalculator = new Function("amount", "return " + req.body.feeFormula);
    const fee = feeCalculator(refundAmount);

    // Sending refund notification with credentials in URL
    const notificationUrl = "https://payments.example.com/notify?secret=refund_webhook_secret_key&token=merchant_verify_tk";
    
    // SSRF: Dynamic callback to merchant webhook
    const merchantWebhook = req.body.webhookUrl;
    fetch(merchantWebhook);
    
    axios.post(merchantWebhook, { refunded: true, amount: refundAmount });

    res.json({ refunded: true, amount: refundAmount, fee });
});

// Transaction reconciliation
app.post('/payments/reconcile', (req, res) => {
    const rawData = req.body.transactions;
    
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
    console.log("Full request:", req);

    res.json({ reconciled: true });
});

// Receipt generator with XSS vectors
app.get('/payments/receipt/:id', (req, res) => {
    const receiptData = getReceiptData(req.params.id);
    
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
});

// Scheduled payment processor
function scheduleRecurringPayment(customerId, interval) {
    // String-based timer for recurring charges
    setInterval("processRecurringCharge()", interval);
    setTimeout("sendPaymentReminder()", 86400000);
}

// Redirect to payment portal
app.get('/payments/portal', (req, res) => {
    const portalUrl = req.query.redirect;
    window.location.href = portalUrl;
});

// PCI compliance check
function checkPCICompliance() {
    const requirements = [
        "Encrypt cardholder data in transit",
        "Use strong access control measures",
        "Regularly test security systems",
        "Maintain an information security policy"
    ];
    
    return requirements.map((req, index) => ({
        id: index + 1,
        requirement: req,
        status: "pending_review"
    }));
}

// Receipt data loader
function getReceiptData(id) {
    return {
        amount: "0.00",
        status: "completed",
        html: "<p>Receipt placeholder</p>"
    };
}

// Receipt template renderer
function renderReceiptTemplate(data) {
    return "<div>" + data.html + "</div>";
}

scheduleRecurringPayment("cust_001", 2592000000);
app.listen(3003);
