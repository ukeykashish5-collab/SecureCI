// Severity assigned to a finding reported by a plugin.
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

// High-level strategy a plugin uses to inspect project files.
export type PluginType = "AST" | "REGEX" | "CONFIG" | "DEPENDENCY";

// A single issue, warning, or recommendation emitted by a plugin run.
export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  file?: string;
  line?: number;
  column?: number;
  fix?: string;
  reference?: string;
  plugin: string;
}

// Human-readable metadata used to identify and describe a plugin.
export interface PluginMeta {
  name: string;
  version: string;
  description: string;
  author?: string;
  tags?: string[];
}

// Declares what a plugin can analyze and how it operates.
export interface PluginCapabilities {
  type: PluginType;
  // Language identifiers the plugin knows how to analyze, such as "js", "ts", or "py".
  languages?: string[];
  // File extensions or special config filenames the plugin targets, such as ".js" or ".env".
  fileTypes?: string[];
}

// Optional contract describing the shape of data a plugin expects and returns.
export interface PluginSchema {
  input: {
    files?: string[];
    astMap?: Record<string, unknown>;
    config?: Record<string, unknown>;
  };
  output: {
    findings: Finding[];
  };
}

// Runtime data and helpers passed into the plugin during execution.
export interface PluginContext {
  projectRoot: string;
  files: string[];
  astMap?: Record<string, unknown>;
  config: Record<string, any>;
  env?: Record<string, string>;
  report: (finding: Finding) => void; // optional streaming reporting
}

// Optional hooks that let a plugin prepare, coordinate, and clean up around `run`.
export interface PluginLifecycle {
  init?: (context: PluginContext) => Promise<void> | void;
  beforeRun?: (context: PluginContext) => Promise<void> | void;
  afterRun?: (findings: Finding[]) => Promise<void> | void;
  cleanup?: () => Promise<void> | void;
}

// Full plugin definition consumed by the SecureCI plugin system.
export interface Plugin {
  meta: PluginMeta;
  capabilities: PluginCapabilities;
  schema?: PluginSchema;
  defaultConfig?: Record<string, any>;
  lifecycle?: PluginLifecycle;

  run: (context: PluginContext) => Promise<Finding[]> | Finding[];
}
