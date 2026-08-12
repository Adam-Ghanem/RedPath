# Record the RedPath walkthrough

This guide creates the product walkthrough referenced in the README. The recording should show the public seeded demo as it behaves in the browser.

## Target output

Create `assets/demo/redpath-walkthrough.gif` with a maximum file size of **10 MB**. Use 1440×900 or 1280×800, capture at 12–15 fps, and keep the final loop between 15 and 22 seconds.

## Storyboard

| Time | Screen action | What the viewer learns |
| --- | --- | --- |
| 0–6 seconds | Open [redpath-sec.vercel.app](https://redpath-sec.vercel.app) and hold on the forensic dashboard plus attack-path board. | RedPath turns attack-path evidence into an explainable case file. |
| 6–12 seconds | Scroll to the detection coverage view and pause on the tactic-level coverage or a visible gap. | The console connects exposure paths to a defensible detection verdict. |
| 12–18 seconds | Open the case-file/report area, invoke the browser print dialog, and choose **Save to PDF**. | The analyst can take the evidence briefing into a shareable report without an external service. |

## Free recording workflow

1. Use **ScreenToGif** on Windows, **Kap** on macOS, or **OBS Studio** on any desktop platform. Record the three beats above with the browser zoom at 100%.
2. Trim pauses and cursor travel. Keep only one deliberate interaction per beat so the visual story is readable with the GIF muted.
3. Export as an MP4 first. Convert it to GIF with [Gifski](https://gif.ski/) using 12–15 fps and a 10 MB maximum, or use the export compressor built into your recorder.
4. Place the final file at `assets/demo/redpath-walkthrough.gif`, then add it to the README with:

   ```md
   ![RedPath walkthrough: attack path, coverage, and report workflow](assets/demo/redpath-walkthrough.gif)
   ```

## Quality checklist

- [ ] The attack-path board is readable at normal GitHub README width.
- [ ] The coverage view visibly shows a technique, verdict, or coverage gap.
- [ ] The recording uses only RedPath’s synthetic seeded data.
- [ ] The final file is under 10 MB and loops cleanly.
- [ ] The browser print dialog is shown only as a PDF-save workflow.
