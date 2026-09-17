/**
 * Test Vulnerable Sample 006 (A1)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: dynamic filter predicate compiled via new Function (OWASP-A1-003)
function buildFilterPredicate(userPredicateStr) {
    const filterFn = new Function("item", "return " + userPredicateStr);
    return [1, 2, 3, 4, 5].filter(filterFn);
}

// Variation signature: #2
