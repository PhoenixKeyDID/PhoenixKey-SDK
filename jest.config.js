/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/test"],
  testMatch: ["**/*.test.ts"],
  transform: {
    "^.+\\.ts$": [
      "ts-jest",
      {
        tsconfig: {
          // Tests are not part of the published `rootDir: src` build; relax
          // the build-only constraints so ts-jest can compile them standalone.
          rootDir: ".",
          isolatedModules: true,
          verbatimModuleSyntax: false,
        },
      },
    ],
  },
};
