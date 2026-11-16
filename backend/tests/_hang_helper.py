"""Stand-in for pipeline._featurize, importable by worker processes: URLs containing "hang" never finish."""
import time


def featurize(html, url, hint):
    if "hang" in url:
        time.sleep(120)
    return {"title": url}, None
