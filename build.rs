fn main() {
    println!("cargo:rerun-if-changed=ui/app.slint");

    // The iPhone app consumes the portable library through its C ABI and has
    // its own native SwiftUI interface. Avoid generating the desktop Slint UI
    // when Cargo is building the no-default-features iOS core.
    if std::env::var_os("CARGO_FEATURE_DESKTOP").is_some() {
        slint_build::compile("ui/app.slint").unwrap();
    }

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("icon.ico");
        res.set_manifest(r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#);
        if let Err(e) = res.compile() {
            println!("cargo:warning=Failed to compile windows resource: {}", e);
        }
    }
}
