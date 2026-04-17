import { readFile } from "node:fs/promises";
import path from "node:path";
import { parse } from "@babel/parser";
import traverse, { NodePath } from "@babel/traverse";
import type {
  CallExpression,
  File,
  Identifier,
  ImportDeclaration,
  StringLiteral,
} from "@babel/types";
import { Finding, Plugin, PluginContext } from "../types/plugin";

const SUPPORTED_EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
]);

type ScannerRuleConfig = {
  detectEval: boolean;
  detectConsoleLog: boolean;
  detectHardcodedSecrets: boolean;
  detectUnsafeImports: boolean;
};

type ScannerConfig = {
  scanner?: Partial<ScannerRuleConfig>;
};

type FindingBuilder = Omit<Finding, "plugin">;

export class ScannerPlugin implements Plugin {
  meta = {
    name: "scanner",
    version: "1.0.0",
    description:
      "Parses JavaScript and TypeScript files with Babel and reports baseline security findings.",
    tags: ["ast", "security", "javascript", "typescript"],
  };

  capabilities = {
    type: "AST" as const,
    languages: ["js", "jsx", "ts", "tsx"],
    fileTypes: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  };

  defaultConfig: ScannerRuleConfig = {
    detectEval: true,
    detectConsoleLog: true,
    detectHardcodedSecrets: true,
    detectUnsafeImports: true,
  };

  schema = {
    input: {
      files: ["string[]"],
      config: {
        scanner: {
          detectEval: "boolean",
          detectConsoleLog: "boolean",
          detectHardcodedSecrets: "boolean",
          detectUnsafeImports: "boolean",
        },
      },
    },
    output: {
      findings: [],
    },
  };

  async run(context: PluginContext): Promise<Finding[]> {
    const config = this.resolveConfig(context.config);
    const findings: Finding[] = [];
    const filesToScan = context.files.filter((file) =>
      SUPPORTED_EXTENSIONS.has(path.extname(file).toLowerCase()),
    );

    for (const filePath of filesToScan) {
      const absolutePath = path.isAbsolute(filePath)
        ? filePath
        : path.join(context.projectRoot, filePath);

      let source: string;

      try {
        source = await readFile(absolutePath, "utf8");
      } catch (error) {
        findings.push(
          this.createFinding({
            id: "scanner-file-read-error",
            title: "Unable to read source file",
            description: `The scanner could not read "${filePath}": ${this.getErrorMessage(
              error,
            )}`,
            severity: "MEDIUM",
            file: filePath,
            fix: "Ensure the file exists and is readable before running the scanner.",
          }),
        );
        continue;
      }

      let ast: File;

      try {
        ast = parse(source, {
          sourceType: "unambiguous",
          sourceFilename: filePath,
          errorRecovery: false,
          plugins: [
            "jsx",
            "typescript",
            "classProperties",
            "classPrivateProperties",
            "classPrivateMethods",
            "decorators-legacy",
            "dynamicImport",
            "importMeta",
            "optionalChaining",
            "nullishCoalescingOperator",
            "objectRestSpread",
            "topLevelAwait",
          ],
        });
      } catch (error) {
        findings.push(
          this.createFinding({
            id: "scanner-parse-error",
            title: "Unable to parse source file",
            description: `Babel could not parse "${filePath}": ${this.getErrorMessage(
              error,
            )}`,
            severity: "HIGH",
            file: filePath,
            fix: "Fix the syntax error or update parser settings for this file type.",
          }),
        );
        continue;
      }

      this.collectFindingsFromAst(ast, filePath, config, findings, context);
    }

    return findings;
  }

  private collectFindingsFromAst(
    ast: File,
    filePath: string,
    config: ScannerRuleConfig,
    findings: Finding[],
    context: PluginContext,
  ): void {
    traverse(ast, {
      CallExpression: (nodePath: NodePath<CallExpression>) => {
        if (config.detectEval && this.isEvalCall(nodePath)) {
          this.pushFinding(
            findings,
            context,
            this.createFinding({
              id: "scanner-eval-usage",
              title: "Use of eval detected",
              description:
                "Dynamic code execution through eval can introduce code injection risks.",
              severity: "HIGH",
              file: filePath,
              line: nodePath.node.loc?.start.line,
              column: nodePath.node.loc?.start.column,
              fix: "Replace eval with explicit parsing or safer control-flow logic.",
              reference:
                "https://owasp.org/www-community/attacks/Direct_Dynamic_Code_Evaluation_Eval%20Injection",
            }),
          );
        }

        if (config.detectConsoleLog && this.isConsoleLogCall(nodePath)) {
          this.pushFinding(
            findings,
            context,
            this.createFinding({
              id: "scanner-console-log",
              title: "Console logging detected",
              description:
                "Debug logging can accidentally expose sensitive data in CI output or runtime logs.",
              severity: "LOW",
              file: filePath,
              line: nodePath.node.loc?.start.line,
              column: nodePath.node.loc?.start.column,
              fix: "Remove the log or replace it with a structured logger that redacts secrets.",
            }),
          );
        }
      },
      StringLiteral: (nodePath: NodePath<StringLiteral>) => {
        if (
          config.detectHardcodedSecrets &&
          this.looksLikeHardcodedSecret(nodePath.node)
        ) {
          this.pushFinding(
            findings,
            context,
            this.createFinding({
              id: "scanner-hardcoded-secret",
              title: "Potential hardcoded secret detected",
              description:
                "A string literal appears to contain a secret or credential embedded in source code.",
              severity: "CRITICAL",
              file: filePath,
              line: nodePath.node.loc?.start.line,
              column: nodePath.node.loc?.start.column,
              fix: "Move the secret into environment variables or a secure secret manager.",
            }),
          );
        }
      },
      ImportDeclaration: (nodePath: NodePath<ImportDeclaration>) => {
        if (
          config.detectUnsafeImports &&
          this.isUnsafeImport(nodePath.node)
        ) {
          this.pushFinding(
            findings,
            context,
            this.createFinding({
              id: "scanner-unsafe-import",
              title: "Potentially unsafe child process import detected",
              description:
                "Importing child process APIs may lead to command execution risks if inputs are not validated.",
              severity: "MEDIUM",
              file: filePath,
              line: nodePath.node.loc?.start.line,
              column: nodePath.node.loc?.start.column,
              fix: "Review the command execution flow and validate or constrain all untrusted input.",
            }),
          );
        }
      },
    });
  }

  private resolveConfig(config: ScannerConfig): ScannerRuleConfig {
    return {
      ...this.defaultConfig,
      ...config.scanner,
    };
  }

  private pushFinding(
    findings: Finding[],
    context: PluginContext,
    finding: Finding,
  ): void {
    findings.push(finding);
    context.report(finding);
  }

  private createFinding(finding: FindingBuilder): Finding {
    return {
      ...finding,
      plugin: this.meta.name,
    };
  }

  private isEvalCall(nodePath: NodePath<CallExpression>): boolean {
    return (
      nodePath.get("callee").isIdentifier() &&
      (nodePath.get("callee").node as Identifier).name === "eval"
    );
  }

  private isConsoleLogCall(nodePath: NodePath<CallExpression>): boolean {
    const callee = nodePath.get("callee");
    return (
      callee.isMemberExpression() &&
      callee.get("object").isIdentifier() &&
      (callee.get("object").node as Identifier).name === "console" &&
      callee.get("property").isIdentifier() &&
      (callee.get("property").node as Identifier).name === "log"
    );
  }

  private looksLikeHardcodedSecret(node: StringLiteral): boolean {
    const value = node.value.trim();
    if (value.length < 12) {
      return false;
    }

    const secretPatterns = [
      /api[_-]?key/i,
      /secret/i,
      /token/i,
      /password/i,
      /passwd/i,
      /AKIA[0-9A-Z]{16}/,
      /ghp_[A-Za-z0-9]{20,}/,
      /sk_(live|test)_[A-Za-z0-9]{16,}/,
    ];

    return secretPatterns.some((pattern) => pattern.test(value));
  }

  private isUnsafeImport(node: ImportDeclaration): boolean {
    return node.source.value === "child_process";
  }

  private getErrorMessage(error: unknown): string {
    if (error instanceof Error) {
      return error.message;
    }

    return String(error);
  }
}
