pub const API_BASE_URL: &str = "https://drive-api.proton.me";

/// Required by Proton for every request (see the SDK's operational
/// requirements: https://github.com/ProtonDriveApps/sdk). Pattern:
/// external-drive-{name}@{semver}-{channel}. Update the version segment as
/// this crate's version changes; never spoof this as an official client.
pub const APP_VERSION: &str = "external-drive-proton_drive_client_rust@0.1.0-alpha";
