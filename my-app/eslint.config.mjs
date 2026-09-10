{
  "extends": [
    "next/core-web-vitals",
    "plugin:security/recommended"
  ],
  "plugins": [
    "security",
    "no-unsanitized"
  ],
  "rules": {
    "security/detect-object-injection": "warn",
    "security/detect-non-literal-require": "error",
    "no-unsanitized/method": "error",
    "no-unsanitized/property": "error"
  }
}