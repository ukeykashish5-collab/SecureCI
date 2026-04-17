import { Plugin } from "../types/plugin";

interface PluginRegistry {
  register(plugin: Plugin): void;
  getPlugins(): Plugin[];
}
