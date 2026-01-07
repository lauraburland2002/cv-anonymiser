describe("CV Anonymiser - CloudFront smoke tests", () => {
    it("loads the homepage", () => {
      cy.visit("/");
      // Page contains your main CTA button
      cy.get("#anonymiseBtn", { timeout: 20000 }).should("be.visible");
    });
  
    it("anonymises sample text (redacts email + phone)", () => {
      cy.visit("/");
  
      const input =
        "Contact me at test.user@example.com or +44 7700 900123. Thanks!";
  
      cy.get("#cvText").clear().type(input, { delay: 0 });
      cy.get("#anonymiseBtn").click();
  
      // Output should contain redactions
      cy.get("#output", { timeout: 20000 })
        .should("contain.text", "[REDACTED_EMAIL]")
        .and("contain.text", "[REDACTED_PHONE]");
  
      // Should NOT leak the raw values
      cy.get("#output")
        .should("not.contain.text", "test.user@example.com")
        .and("not.contain.text", "+44 7700 900123");
    });
  });