"""
Test /u/<user_url_slug/following/ URLs.

EECS 485 Project 2

Andrew DeOrio <awdeorio@umich.edu>
"""
import re
import bs4


def test_awdeorio(client):
    """Check default content at /u/awdeorio/following/ URL."""
    # Login
    response = client.post(
        "/accounts/login/",
        data={"username": "awdeorio", "password": "password"},
    )
    assert response.status_code == 302

    # Load and parse following page
    response = client.get("/u/awdeorio/following/")
    assert response.status_code == 200
    soup = bs4.BeautifulSoup(response.data, "html.parser")
    text = soup.get_text()
    text = re.sub(r"\s+", " ", text)
    links = [x.get("href") for x in soup.find_all("a")]
    srcs = [x.get("src") for x in soup.find_all('img')]

    # Verify text
    assert text.lower().count("following") == 3
    assert "not following" not in text.lower()

    # Verify images: Mike, Jason, Jag
    assert "/uploads/5ecde7677b83304132cb2871516ea50032ff7a4f.jpg" in srcs
    assert "/uploads/505083b8b56c97429a728b68f31b0b2a089e5113.jpg" in srcs
    assert "/uploads/73ab33bd357c3fd42292487b825880958c595655.jpg" not in srcs

    # Verify links
    assert "/u/jflinn/" in links
    assert "/u/michjc/" in links
    assert "/u/jag/" not in links


def test_unfollow(client):
    """Click unfollow.  Verify user is removed."""
    # Log in
    response = client.post(
        "/accounts/login/",
        data={"username": "awdeorio", "password": "password"},
    )
    assert response.status_code == 302

    # Click unfollow and parse result
    response = client.post(
        "/u/awdeorio/following/",
        data={"unfollow": "unfollow", "username": "jflinn"},
    )
    assert response.status_code == 200
    soup = bs4.BeautifulSoup(response.data, "html.parser")
    text = soup.get_text()
    text = re.sub(r"\s+", " ", text)
    links = [x.get("href") for x in soup.find_all("a")]
    srcs = [x.get("src") for x in soup.find_all('img')]

    # Verify text
    assert "not following" not in text.lower()
    assert text.lower().count("following") == 2

    # Verify images: Mike, Jason, Jag
    assert "/uploads/5ecde7677b83304132cb2871516ea50032ff7a4f.jpg" in srcs
    assert "/uploads/505083b8b56c97429a728b68f31b0b2a089e5113.jpg" not in srcs
    assert "/uploads/73ab33bd357c3fd42292487b825880958c595655.jpg" not in srcs

    # Verify links
    assert "/u/michjc/" in links
    assert "/u/jflinn/" not in links
    assert "/u/jag/" not in links
