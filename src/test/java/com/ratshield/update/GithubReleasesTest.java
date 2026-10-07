package com.ratshield.update;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GithubReleasesTest {

    @Test
    void releaseJsonIsParsedWithDigestResolution() {
        String json = "{"
                + "  \"tag_name\": \"v1.4.2\","
                + "  \"body\": \"## Notes\\nsha256: ratshield-setup.exe abcdef0123456789\\n\","
                + "  \"assets\": ["
                + "    {\"name\": \"ratshield-setup.exe\", " +
                "     \"browser_download_url\": \"https://example.com/setup.exe\", \"size\": 4242},"
                + "    {\"name\": \"README.md\", " +
                "     \"browser_download_url\": \"https://example.com/readme.md\", \"size\": 10}"
                + "  ]"
                + "}";
        GithubReleases.Release release = GithubReleases.parse(json);
        assertEquals("v1.4.2", release.tag());
        assertEquals("1.4.2", release.version());
        assertEquals(2, release.assets().size());
        assertEquals("abcdef0123456789", release.assets().get(0).sha256());
        assertEquals("", release.assets().get(1).sha256());
    }

    @Test
    void installAssetPrefersSetupExeOverPortableZip() {
        GithubReleases.Release release = release(
                new GithubReleases.Asset("ratshield-1.4.2.zip", "https://example.com/p.zip", 1, ""),
                new GithubReleases.Asset("ratshield-setup.exe", "https://example.com/s.exe", 1, ""),
                new GithubReleases.Asset("LICENSE.txt", "https://example.com/license.txt", 1, ""));
        assertEquals("ratshield-setup.exe",
                GithubReleases.installAsset(release).name());
    }

    @Test
    void installAssetFallsBackToPortableZipWhenNoInstallerExists() {
        GithubReleases.Release release = release(
                new GithubReleases.Asset("ratshield-1.4.2.zip", "https://example.com/p.zip", 1, ""),
                new GithubReleases.Asset("LICENSE.txt", "https://example.com/license.txt", 1, ""));
        assertEquals("ratshield-1.4.2.zip",
                GithubReleases.installAsset(release).name());
    }

    @Test
    void versionFromTagStripsLeadingV() {
        assertEquals("1.2.3", GithubReleases.versionFromTag("v1.2.3"));
        assertEquals("1.2.3", GithubReleases.versionFromTag("V1.2.3"));
        assertEquals("1.2.3", GithubReleases.versionFromTag("1.2.3"));
        assertEquals("", GithubReleases.versionFromTag(" v ") );
    }

    @Test
    void versionComparisonRejectsOlderAndAcceptsNewerTags() {
        assertTrue(UpdateChecker.isNewer("1.4.0", "1.3.9"));
        assertTrue(UpdateChecker.isNewer("1.2.0", "1.1.9"));
    }

    private static GithubReleases.Release release(GithubReleases.Asset... assets) {
        return new GithubReleases.Release("v1.4.2", "1.4.2", "notes", java.util.List.of(assets));
    }
}