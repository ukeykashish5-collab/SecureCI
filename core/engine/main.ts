import { readdir } from "node:fs/promises";
import path from "node:path";
import { getPlugins, registerPlugin } from "../loader/main";
import { Finding, Plugin, PluginContext } from "../../types/plugin";
import { ScannerPlugin } from "../../plugins/scanner.plugin";

const IGNORED_DIRECTORIES = new Set([
  ".git",
  "dist",
  "node_modules",
]);

const scannerPlugin = new ScannerPlugin();
registerPlugin(scannerPlugin);

export async function main(): Promise<void> {
  const plugins: Plugin[] = getPlugins();
  const projectRoot = process.cwd();
  const files = await collectProjectFiles(projectRoot);
  const findings: Finding[] = [];

  const context: PluginContext = {
    projectRoot,
    files,
    config: {},
    report: (finding) => {
      findings.push(finding);
    },
  };

  console.log(`Loaded ${plugins.length} plugins.`);

  for (const plugin of plugins) {
    try {
      const pluginFindings = await plugin.run(context);

      if (pluginFindings.length > 0) {
        console.log(
          `[${plugin.meta.name}] Reported ${pluginFindings.length} findings.`,
        );
      }
    } catch (error) {
      console.error(
        `Error running plugin "${plugin.meta.name}": ${getErrorMessage(error)}`,
      );
    }
  }

  if (findings.length > 0) {
    console.log(`Total findings: ${findings.length}`);
  }
}

async function collectProjectFiles(rootDir: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(currentDir: string): Promise<void> {
    const entries = await readdir(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name)) {
          await walk(fullPath);
        }
        continue;
      }

      files.push(path.relative(rootDir, fullPath));
    }
  }

  await walk(rootDir);

  return files;
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}
