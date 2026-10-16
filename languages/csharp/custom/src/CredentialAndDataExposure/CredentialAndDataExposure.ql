/**
 * @name Credential and sensitive data exposure
 * @description Passwords, signing keys and payment-card data that are transmitted, rendered,
 *              logged or stored without adequate protection can be recovered by attackers.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id cs/credential-and-data-exposure
 * @tags security
 *       external/cwe/cwe-200
 *       external/cwe/cwe-256
 *       external/cwe/cwe-257
 *       external/cwe/cwe-312
 *       external/cwe/cwe-315
 *       external/cwe/cwe-319
 *       external/cwe/cwe-523
 *       external/cwe/cwe-532
 *       external/cwe/cwe-798
 */

import csharp
import CredentialAndDataExposure

from Element alert, string message, Element related, string relatedText
where credentialAndDataExposure(alert, message, related, relatedText)
select alert, message, related, relatedText
