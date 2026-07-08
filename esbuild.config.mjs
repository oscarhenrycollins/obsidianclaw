import esbuild from "esbuild";
import process from "process";
import { builtinModules } from "node:module";

const prod = process.argv[2] === "production";

esbuild.build({
  entryPoints: ["src/main.ts"],
  bundle: true,
  external: [
    "obsidian",
    "electron",
    "@codemirror/autocomplete",
    "@codemirror/collab",
    "@codemirror/commands",
    "@codemirror/language",
    "@codemirror/lint",
    "@codemirror/search",
    "@codemirror/state",
    "@codemirror/view",
    "@lezer/common",
    "@lezer/highlight",
    "@lezer/lr",
    ...builtinModules,
  ],
  format: "cjs",
  target: "es2018",
  logLevel: "info",
  sourcemap: prod ? false : "inline",
  treeShaking: true,
  outfile: "main.js",
  minify: prod,
}).then(async () => {
  // Optionally copy built files to a local Obsidian plugin folder for development.
  // This is skipped in CI / production unless OCO_COPY_TO_OBSIDIAN is set.
  if (!prod || process.env.OCO_COPY_TO_OBSIDIAN) {
    const fs = await import("fs");
    const path = await import("path");
    // Try multiple possible vault locations
    const scriptDir = path.dirname(new URL(import.meta.url).pathname);
    const candidates = [
      path.join(scriptDir, "../../.obsidian/plugins/openclaw"),          // old: repo at vault root
      path.join(scriptDir, "../../../.obsidian/plugins/openclaw"),        // new: repo in AGENT-OSCAR/Code/
      path.join(scriptDir, "../../../../.obsidian/plugins/openclaw"),     // vault is parent of workspace
    ];
    const pluginDir = candidates.find(p => fs.existsSync(p)) || candidates[0];
    if (fs.existsSync(pluginDir)) {
      fs.copyFileSync("main.js", path.join(pluginDir, "main.js"));
      fs.copyFileSync("styles.css", path.join(pluginDir, "styles.css"));
      fs.copyFileSync("manifest.json", path.join(pluginDir, "manifest.json"));
      console.log("Copied to .obsidian/plugins/openclaw/");
    }
  }
}).catch(() => process.exit(1));
