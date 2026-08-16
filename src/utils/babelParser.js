import * as Babel from '@babel/standalone';

/**
 * Parses JavaScript/TypeScript code into an Abstract Syntax Tree (AST).
 * Using @babel/standalone for browser compatibility.
 * 
 * @param {string} code - Raw source code as text.
 * @param {string} fileName - File name to determine if the target is TS or JS.
 * @returns {Object} - Babel AST object.
 */
export const parseToAST = (code, fileName) => {
  const isTypeScript = fileName.endsWith('.ts') || fileName.endsWith('.tsx');
  
  try {
    // In @babel/standalone, developers cannot just call parse(), 
    // but can use transform with a custom plugin or access the internal parser if available.
    // However, the cleanest way in the browser is often using the 'parse' method if it exists in the version,
    // or Babel.transform(code, { ast: true }).ast
    
    const result = Babel.transform(code, {
      ast: true,
      code: false,
      filename: fileName,
      presets: [
        isTypeScript ? 'typescript' : null,
        ['react', { runtime: 'automatic' }]
      ].filter(Boolean),
    });

    return result.ast;
  } catch (error) {
    console.error(`Error parsing ${fileName}:`, error.message);
    throw new Error(`Failed to parse ${fileName}: ${error.message}`);
  }
};
