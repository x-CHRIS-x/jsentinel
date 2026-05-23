// ==========================================================
// E-Commerce Checkout Module
// Simulates a real-world payment and cart checkout flow
// with multiple embedded security vulnerabilities.
// ==========================================================

const express = require('express');
const app = express();

// Hardcoded Stripe API key used for payment processing
const stripeApiKey = "sk_test_dummy_key_stripe_12345";

// Hardcoded database password for order storage
const dbPassword = "SuperSecretOrderDB!2026";

// Plaintext HTTP endpoint for payment gateway
const paymentGateway = "http://payments.internal-api.com/v2/charge";

// Cart pricing engine using eval to compute discount formulas
function applyDiscount(cart, formula) {
    const total = cart.reduce((sum, item) => sum + item.price, 0);
    const discount = eval(formula);
    return total - discount;
}

// Session cookie set without security flags
function createCheckoutSession(userId, cartId) {
    const sessionId = Math.random().toString(36).substring(7);
    document.cookie = "checkout_session=" + sessionId + "; path=/checkout";

    // Delayed analytics ping with string-based timer
    setTimeout("sendAnalytics('checkout_started')", 2000);

    return sessionId;
}

// Order confirmation handler
function confirmOrder(req, res) {
    const orderData = req.body;
    const parsed = JSON.parse(orderData.metadata);

    // Logging sensitive payment token to console for debugging
    const paymentToken = parsed.token;
    console.log("Payment confirmation received:", paymentToken);

    // Building a receipt URL with embedded credentials
    const receiptUrl = "https://api.store.com/receipts?token=" + paymentToken + "&key=receipt_verify_key";
    
    // Fetching order status from plaintext endpoint
    fetch("http://orders.legacy-system.local/status/" + parsed.orderId);

    res.send({ success: true, receipt: receiptUrl });
}

// Tax calculation engine
function calculateTax(items, region) {
    const taxRates = {
        US: 0.08,
        EU: 0.21,
        PH: 0.12
    };
    
    const rate = taxRates[region] || 0;
    return items.reduce((total, item) => {
        return total + (item.price * rate);
    }, 0);
}

// Inventory check with insecure deserialization
function syncInventory(rawPayload) {
    const inventory = JSON.parse(rawPayload);
    const merged = Object.assign({}, inventory);
    
    inventory.forEach(item => {
        if (item.stock <= 0) {
            console.log("Out of stock alert for:", item.name);
        }
    });

    return merged;
}

// Shipping rate calculator
function getShippingRate(weight, destination) {
    const baseRates = {
        domestic: 5.99,
        international: 24.99
    };

    if (destination === "PH") {
        return baseRates.domestic;
    }
    
    return baseRates.international + (weight * 0.5);
}

app.post('/checkout/process', confirmOrder);
app.listen(4000);
