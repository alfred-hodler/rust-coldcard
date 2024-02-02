use regex::Regex;
use semver::Version;

pub const DOWNLOADS: &str = "https://www.coldcard.com/downloads";

/// A single firmware release.
#[derive(Debug)]
pub struct Release {
    /// The raw name of the firmware file as defined by the vendor.
    pub name: String,
    /// The version of the release in the semver format.
    pub version: Version,
    /// Whether the release is "edge" (experimental).
    pub is_edge: bool,
}

impl Release {
    /// Attempts to find a list of firmware releases on the official website.
    pub fn find() -> Result<Vec<Self>, ureq::Error> {
        let page = fetch_download_page()?;

        let mut found: Vec<_> = firmware_regex()
            .captures_iter(&page)
            .map(|m| {
                let name = m.get(0).unwrap();
                let version = m.get(1).unwrap();
                let edge_marker = version.as_str().find('X');
                let (version, is_edge) = match edge_marker {
                    Some(pos) => (Version::parse(&version.as_str()[1..pos]), true),
                    None => (Version::parse(&version.as_str()[1..]), false),
                };

                Release {
                    name: name.as_str().to_owned(),
                    version: version.unwrap(),
                    is_edge,
                }
            })
            .collect();

        found.sort_by(|a, b| a.version.cmp(&b.version));
        found.reverse();

        Ok(found)
    }

    /// Downloads a firmware release.
    pub fn download<F: FnMut(usize, usize)>(
        &self,
        mut progress: F,
    ) -> Result<Vec<u8>, ureq::Error> {
        let url = format!("{DOWNLOADS}/{}", self.name);
        let response = ureq::get(&url).call()?;

        let size: usize = response
            .header("Content-Length")
            .and_then(|h| h.parse().ok())
            .unwrap_or_default();

        let mut reader = response.into_reader();
        let mut downloaded = 0;
        let mut bytes = Vec::with_capacity(size);
        let mut buffer = [0_u8; 4096];

        while downloaded < 20 * 1024 * 1024 {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            downloaded += read;
            bytes.extend_from_slice(&buffer[..read]);
            progress(downloaded, size);
        }

        Ok(bytes)
    }
}

pub fn best_match<'a>(releases: &'a [Release], our_model: Option<&str>) -> Option<&'a Release> {
    releases
        .iter()
        .filter(|r| {
            let mk2_or_mk3 = r.version.major == 4 && matches!(our_model, Some("mk2" | "mk3"));
            let mk4 = r.version.major == 5 && matches!(our_model, Some("mk4"));

            !r.is_edge && (mk2_or_mk3 || mk4)
        })
        .max_by(|a, b| a.version.cmp(&b.version))
}

fn fetch_download_page() -> Result<String, ureq::Error> {
    ureq::get(DOWNLOADS)
        .call()
        .map(|r| r.into_string().expect("bad utf-8"))
}

fn firmware_regex() -> Regex {
    Regex::new(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]+-(v[0-9]+\.[0-9]+\.[0-9]+X?)(-mk.)?-coldcard.dfu")
        .unwrap()
}
