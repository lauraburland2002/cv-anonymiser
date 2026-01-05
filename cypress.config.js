const { defineConfig } = require("cypress");

module.exports = defineConfig({
    e2e: {
        defaultCommandTimeout: 8000,
        pageLoadTimeout: 60000,
        retries: {
            runMode: 1,
            openMode: 0
        }
    }
});