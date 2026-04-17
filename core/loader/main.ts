import { Plugin, PluginContext } from "../../types/plugin";

const plugins: Plugin[] = [];

export function registerPlugin(plugin: Plugin): void {
  plugins.push(plugin);
}

export async function runPlugins(context: PluginContext): Promise<void> {
  for (const plugin of plugins) {
    await plugin.run(context);
  }
}

export function getPlugins(): Plugin[] {
  return plugins;
}
