import * as Babel from '@babel/standalone';

/**
 * Main scanning engine that coordinates file parsing and rule execution.
 * 
 * @param {File} file - Browser File object.
 * @param {Array} rules - Array of security rule objects.
 * @returns {Promise<Object>} - Results including AST and any vulnerabilities.
 */
export const scanFile = async (file, rules) => {
  let hasError = false;
  try {
    const code = await file.text();
    const issues = [];

    // Run rules via @babel/standalone parser
    for (const rule of rules) {
      try {
        Babel.transform(code, {
          filename: file.name,
          ast: false,
          code: false,
          highlightCode: false,
          parserOpts: {
            errorRecovery: true // Allows partial scans of broken files
          },
          presets: [
            file.name.endsWith('.ts') || file.name.endsWith('.tsx') ? 'typescript' : null,
            ['react', { runtime: 'automatic' }]
          ].filter(Boolean),
          plugins: [
            () => ({
              visitor: rule.visitor(issues)
            })
          ]
        });
      } catch (ruleError) {
        console.error(`Error running rule ${rule.name} on ${file.name}:`, ruleError);
        hasError = true;
      }
    }

    return {
      fileName: file.webkitRelativePath || file.name,
      issues,
      rawCode: code,
      success: true,
      hasError, // Track if any rule execution failed
    };
  } catch (error) {
    console.error("Scanner Error:", error);
    return {
      fileName: file.webkitRelativePath || file.name,
      error: error.message,
      success: false,
      hasError: true
    };
  }
};
