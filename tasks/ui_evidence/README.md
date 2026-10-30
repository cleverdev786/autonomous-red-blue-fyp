# Retained UI-24 / UI-25 evidence

`before-*.png` and `after-*.png` pair the loading and Manual workspace surfaces at 390/1440px, light/dark. Before production source is commit `2c413db`; both versions use the same synthetic fixture harness. These compare this verification slice's contrast, heading and table fixes. They are not real assessments or reconstructed historical redesign screenshots.

- `visual-manifest.json`: hashes for all 16 retained comparison images.
- `browser-results.json`: 143 Firefox layout/media/axe cases and five keyboard journeys.
- `keyboard-results.json`: targeted rerun of the keyboard journeys.
- `contrast-review.json`: detailed review of axe's clipped-cell/overlapping-layer incomplete results. The full run additionally asserts dialog computed contrast.

The complete screenshot matrix and execution logs are retained at the artifact path in `../ui_acceptance_report.md`. See that report for reproduction, test scope and remaining audible screen-reader/human acceptance limits.
