import obsidian from "eslint-plugin-obsidianmd";
import tseslint from "@typescript-eslint/eslint-plugin";
import tsparser from "@typescript-eslint/parser";

export default [
  {
    files: ["main.ts"],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        project: "./tsconfig.json",
        sourceType: "module",
      },
    },
    plugins: {
      obsidianmd: obsidian,
      "@typescript-eslint": tseslint,
    },
    rules: {
      // Obsidian plugin rules
      ...Object.fromEntries(
        Object.entries(obsidian.configs.recommended).map(([key, value]) => [key, value])
      ),
      // Override sentence-case: brand names (OpenClaw, Tailscale) trigger false positives
      "obsidianmd/ui/sentence-case": "off",

      // TypeScript rules the bot enforces
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unnecessary-type-assertion": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],

      // General rules
      "no-console": ["error", { allow: ["warn", "error", "debug"] }],
      "no-undef": "off",
    },
  },
];
