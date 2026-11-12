"""nodriver with default settings. Usage: nodriver_client.py URL PROFILE_DIR [headless|form]
CHROME_BIN is the local Chromium."""
import asyncio
import os
import sys

import nodriver as uc

url, profile = sys.argv[1], sys.argv[2]
mode = sys.argv[3] if len(sys.argv) > 3 else ""
headless = mode == "headless"
form = mode == "form"


async def main():
    # user_data_dir: throwaway profile the runner deletes. --ignore-certificate-errors: the self-signed lab certificate.
    browser = await uc.start(
        headless=headless,
        user_data_dir=profile,
        browser_executable_path=os.environ["CHROME_BIN"],
        browser_args=["--ignore-certificate-errors", "--use-mock-keychain"],
    )
    try:
        if form:
            # What a short nodriver script does, with the library's ordinary API and defaults.
            page = await browser.get(url.replace("/lab/start", "/lab/form"))
            await (await page.select("#agree")).click()
            await (await page.select("#name")).send_keys("lab visitor")
            await (await page.select("#send")).click()
        else:
            await browser.get(url)
        await asyncio.sleep(40)  # the runner kills this process as soon as it has seen the follow-up request
    finally:
        browser.stop()


asyncio.run(main())
