fn main() {
    let mut windows_attributes = tauri_build::WindowsAttributes::new();
    windows_attributes = windows_attributes.app_manifest(std::fs::read_to_string("rakshak.manifest").unwrap());

    tauri_build::try_build(
        tauri_build::Attributes::new().windows_attributes(windows_attributes)
    ).expect("failed to run tauri-build");
}
