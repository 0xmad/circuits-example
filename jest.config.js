module.exports = {
  testTimeout: 10000,
  transform: {
    "\\.(ts|tsx)$": ["ts-jest", { tsconfig: "tsconfig.json" }],
  },
  testMatch: ["**/?(*.)+(spec|test).[t|j]s"],
  moduleFileExtensions: ["ts", "js"],
  coverageReporters: ["clover", "lcov", "json", "json-summary", "text", "text-summary"],
  coveragePathIgnorePatterns: ["/node_modules/", "/tests/"],
  coverageThreshold: {
    global: {
      statements: 90,
      branches: 90,
      functions: 90,
      lines: 90,
    },
  },
};
