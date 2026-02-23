import esbuild from "esbuild";
import process from "process";
import builtins from "builtin-modules";

const prod = process.argv[2] === "production";

esbuild.build({
  entryPoints: ["main.ts"],
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
    ...builtins,
  ],
  format: "cjs",
  target: "es2018",
  logLevel: "info",
  sourcemap: prod ? false : "inline",
  treeShaking: true,
  outfile: "main.js",
  minify: prod,
}).then(async () => {
  // Copy built files to Obsidian plugin folder
  const fs = await import("fs");
  const path = await import("path");
  const pluginDir = path.join(path.dirname(new URL(import.meta.url).pathname), "../../.obsidian/plugins/openclaw");
  if (fs.existsSync(pluginDir)) {
    fs.copyFileSync("main.js", path.join(pluginDir, "main.js"));
    fs.copyFileSync("styles.css", path.join(pluginDir, "styles.css"));
    fs.copyFileSync("manifest.json", path.join(pluginDir, "manifest.json"));
    console.log("Copied to .obsidian/plugins/openclaw/");
  }
}).catch(() => process.exit(1));
