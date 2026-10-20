export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    // Dependabot and release-plz write long body/footer lines.
    'body-max-line-length': [0],
    'footer-max-line-length': [0],
  },
};
