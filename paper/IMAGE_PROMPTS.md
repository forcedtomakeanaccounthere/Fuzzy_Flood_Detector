# Image prompts for AI-generated illustrations

Every figure in `main.tex` is already drawn in TikZ/pgfplots, so the paper builds
without any image files. The prompts below are for optional illustrations, such as
a graphical abstract, slides, a poster or the thesis report. You can also use them
to replace a TikZ diagram with a more visual version.

**Before you start**

- Image models often garble small text. Ask for *minimal or no text*, then add
  labels yourself in PowerPoint, Canva, Figma or Inkscape.
- IEEE prints in colour online but often in greyscale on paper. Keep strong shape
  contrast and do not rely on colour alone.
- To put an image in the paper, save it as `figures/<name>.png`. Then, at the place
  marked `OPTIONAL IMAGE` in `main.tex`, swap the TikZ block for
  `\includegraphics[width=\textwidth]{figures/<name>.png}`.
- Shared style suffix (append it to every prompt for a consistent look):
  > Flat vector illustration, clean technical infographic style, white background,
  > thin dark-grey outlines, muted palette: teal (#1F6F8B) for fuzzy logic,
  > green (#2E8B57) for normal/allow, amber (#D4A017) for suspicious/throttle,
  > red (#C0392B) for attack/block, soft grey for infrastructure. No photorealism,
  > no gradients, no drop shadows, generous whitespace, suitable for an IEEE paper.

---

## 1. Graphical abstract (hero image), 16:9 or 3:1

**Use:** graphical abstract, first slide, poster header.

> A left-to-right story in four panels connected by arrows. Panel 1: a smart home
> with small IoT devices (camera, smart speaker, thermostat, bulb) sending network
> packets as small dots along a line; a few red dots are mixed in to represent a
> flood. Panel 2: a small Raspberry Pi board labelled as an edge device, with a
> magnifying glass over a sliding window of 50 packets. Panel 3: a compact decision
> tree whose nodes are drawn as overlapping triangular fuzzy membership curves
> (low / medium / high), glowing teal. Panel 4: a traffic-light style verdict
> gauge with three zones (green ALLOW, amber THROTTLE, red BLOCK); the needle
> points to red. Next to it is a small "evidence card" with three horizontal bars
> of different lengths, representing fired rules. Bottom strip: a tiny 9 KB chip
> next to a much larger 1.1 MB block, to emphasise lightweight. [style suffix]

## 2. System architecture (alternative to Fig. 1), 3:1

> Two horizontal swim-lanes stacked vertically. Top lane, labelled "laptop", has
> a light blue background and eight rounded rectangles connected by arrows. Their
> icons are: a packet-capture waveform, a tag/label icon, a two-way arrow with a
> filter (direction-aware relabeling), a timeline split into a long blue part and
> a short orange part, a table of features, three overlapping triangles (fuzzy
> sets), a rule list with checkmarks, and a pruned tree. The last box is a small
> glowing chip (the 9 KB model). A dashed arrow drops from the chip into the bottom
> lane, labelled "Raspberry Pi", which has a light green background and shows: an
> antenna/sniffer, a queue, a sliding window, the same fuzzy triangles, the tree,
> a three-state traffic light, a firewall brick wall, and a dashboard screen.
> [style suffix]

## 3. SYN-flood concept, 4:3

> Left: a single server icon with a stack of "connection slots" drawn as small
> boxes, most of them filled red with question marks (half-open connections).
> Right: many attacker laptops wearing masks (spoofed identities) sending arrows
> labelled SYN toward the server. Dashed grey reply arrows from the server go back
> into empty space and fade out. A normal user on the bottom is blocked by a
> "queue full" barrier. Minimal text. [style suffix]

## 4. Crisp threshold vs fuzzy "grey zone", 16:9

> Split image. Left half is titled "crisp": a single vertical threshold line
> divides a horizontal axis into green and red halves. A congested-but-benign
> traffic icon sits just over the line and is wrongly coloured red. Right half is
> titled "fuzzy": three smooth overlapping triangular curves (green LOW, amber
> MEDIUM, red HIGH) over the same axis. The same traffic icon sits in the overlap
> and is shaded half amber and half red, with a small gauge showing a partial
> degree such as 0.43 and 0.33. [style suffix]

## 5. Explainability: anatomy of a verdict, 16:9

> A decision tree drawn on the left with most branches faded light grey and one
> root-to-leaf path highlighted in bold teal, ending in a red leaf node. On the
> right is a dark code-editor style card showing an IF / AND / THEN rule as
> placeholder lines, plus a small horizontal bar chart of eight rule activations
> where three bars are long and red. Below is a lock icon with the note "attacker
> direction only". Leave text areas as blank rounded bars so labels can be added
> later. [style suffix]

## 6. Edge deployment scene (semi-realistic), 16:9

**Use:** demo or poster. Isometric style instead of flat.

> Isometric illustration of a lab desk: a Raspberry Pi 4 with a small fan and an
> Ethernet cable, a Wi-Fi router, an attacker laptop on the left shown with red
> packet streams, two benign IoT devices shown with green packet streams, and a
> second laptop on the right displaying a web dashboard with a threat gauge, a
> packet stream list and a table of blocked IPs. A translucent shield appears
> above the Raspberry Pi. Clean isometric vector style, soft colours, white
> background, no brand logos.

## 7. Data hygiene: relabeling and leakage-free split, 16:9

> Top half: a long horizontal bar made of packet icons inside an "attack window".
> Half of them are red arrows pointing right (attacker to victim) and half are
> green arrows pointing left (victim replies). A magic-wand icon turns the green
> ones from red tags to green tags. Bottom half shows two timelines. The first,
> "random split", has blue and orange squares randomly interleaved, with
> overlapping brackets showing that neighbouring windows share packets, and a
> warning icon. The second, "chronological split", is a long blue block, a thin
> black gap, then a short orange block, repeated per segment, with a checkmark
> icon. [style suffix]

## 8. Size comparison (9 KB vs 1.1 MB), 1:1

> A tiny teal square chip (the 9 KB fuzzy decision tree) next to a huge grey cube
> (the 1.1 MB neural network) at true area scale, about 125 times larger. A small
> human-readable rule card floats next to the tiny chip; a black box with a
> question mark floats next to the large cube. Minimal text. [style suffix]

---

### Tips for best results

- Generate at the largest size available, then downscale. Use 300 dpi PNG for print.
- If the model adds unwanted text, add "no text, no letters, no labels" to the prompt.
- Ask for a "transparent or pure white background" so the image sits cleanly on
  the page.
- Keep a consistent style by reusing the same style suffix and asking for "the
  same visual style as the previous image" in follow-up prompts.
