// Patchright. Usage: node patchright_client.mjs URL PROFILE_DIR best|headless|form|form-jitter|form-careful
//   best      the settings its README shows for best concealment: persistent context, headed, no_viewport,
//             no custom User-Agent (the README uses channel "chrome"; here executablePath is the local Chromium)
//   headless  headless, otherwise defaults
//   form      "best" settings, then what a short automation script does on a form page:
//             click a button, fill a field, click submit, each with the library's defaults.
//             Nothing is added to look human and nothing is added to look scripted.
//   form-jitter the same form, by a script that makes the cheapest effort to hide: it clicks a
//             random point inside each element and types with a random delay between keys.
//   form-careful the same form, by a script that makes a more careful effort: before each click it moves the
//             pointer along a curved path (at least 12 intermediate points, 5 to 25 ms random pauses) to a random
//             point inside the element and presses there with page.mouse.down()/up(); it types one key at a time
//             with a fresh random delay per key (60 to 260 ms); it waits a random 400 to 1200 ms between actions.
import { chromium } from "patchright";

const [url, profile, mode] = process.argv.slice(2);
const executablePath = process.env.CHROME_BIN;
const acts = mode === "form" || mode === "form-jitter" || mode === "form-careful";
const options = mode === "best" || acts
  ? { executablePath, headless: false, viewport: null, ignoreHTTPSErrors: true }
  : { executablePath, headless: true, ignoreHTTPSErrors: true };

const context = await chromium.launchPersistentContext(profile, options);
try {
  const page = context.pages()[0] ?? (await context.newPage());
  await page.goto(acts ? url.replace("/lab/start", "/lab/form") : url, { timeout: 20000 }).catch(() => {});
  if (mode === "form-jitter") {
    const within = async (selector) => {
      const box = await page.locator(selector).boundingBox();
      return { x: 4 + Math.random() * (box.width - 8), y: 4 + Math.random() * (box.height - 8) };
    };
    await page.locator("#agree").click({ position: await within("#agree") });
    await page.locator("#name").click({ position: await within("#name") });
    await page.locator("#name").pressSequentially("lab visitor", { delay: 60 + Math.random() * 80 });
    await page.locator("#send").click({ position: await within("#send") });
  }
  if (mode === "form-careful") {
    const rand = (lo, hi) => lo + Math.random() * (hi - lo);
    const pause = (lo, hi) => new Promise((r) => setTimeout(r, rand(lo, hi)));
    let at = { x: rand(100, 400), y: rand(100, 300) };
    const clickCarefully = async (selector) => {
      const box = await page.locator(selector).boundingBox();
      const to = { x: box.x + rand(4, box.width - 4), y: box.y + rand(4, box.height - 4) };
      // Quadratic Bezier from the last pointer position through a random off-line control point.
      const mid = { x: (at.x + to.x) / 2 + rand(-120, 120), y: (at.y + to.y) / 2 + rand(-120, 120) };
      const steps = 12 + Math.floor(rand(0, 10));
      await page.mouse.move(at.x, at.y);
      for (let i = 1; i <= steps; i++) {
        const t = i / (steps + 1), u = 1 - t;
        await page.mouse.move(u * u * at.x + 2 * u * t * mid.x + t * t * to.x, u * u * at.y + 2 * u * t * mid.y + t * t * to.y);
        await pause(5, 25);
      }
      await page.mouse.move(to.x, to.y);
      await pause(5, 25);
      await page.mouse.down();
      await pause(30, 90);
      await page.mouse.up();
      at = to;
    };
    await pause(400, 1200);
    await clickCarefully("#agree");
    await pause(400, 1200);
    await clickCarefully("#name");
    await pause(400, 1200);
    for (const ch of "lab visitor") {
      await page.keyboard.press(ch === " " ? "Space" : ch, { delay: rand(20, 60) });
      await pause(60, 260);
    }
    await pause(400, 1200);
    await clickCarefully("#send");
  }
  if (mode === "form") {
    await page.locator("#agree").click();
    await page.locator("#name").fill("lab visitor");
    await page.locator("#send").click();
  }
  await new Promise((r) => setTimeout(r, 40000)); // the runner kills this process once it has seen the follow-up request
} finally {
  await context.close();
}
