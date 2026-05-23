/**
 * Shannon Entropy Utility
 * Calculates the mathematical randomness of a string literal.
 * 
 * Formula: H(X) = -sum(P(x_i) * log2(P(x_i)))
 */

/**
 * Calculates the Shannon Entropy of a given string.
 * 
 * @param {string} str - The input string to analyze.
 * @returns {number} - The entropy score in bits per character.
 */
const calculateShannonEntropy = (str) => {
  if (!str || str.length === 0) {
    return 0;
  }

  const charCounts = {};
  const len = str.length;

  // Count character frequencies
  for (let i = 0; i < len; i++) {
    const char = str[i];
    charCounts[char] = (charCounts[char] || 0) + 1;
  }

  // Calculate entropy using probabilities
  let entropy = 0;
  const uniqueChars = Object.keys(charCounts);
  
  for (let i = 0; i < uniqueChars.length; i++) {
    const char = uniqueChars[i];
    const probability = charCounts[char] / len;
    entropy -= probability * Math.log2(probability);
  }

  return parseFloat(entropy.toFixed(4));
};

module.exports = { calculateShannonEntropy };
