fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../assets/brand/icon.ico");
        res.set("ProductName", "AuraClean by mjojo");
        res.set(
            "FileDescription",
            "AuraClean — Hyper-Safe Windows Maintenance Suite by mjojo",
        );
        res.set("CompanyName", "mjojo");
        res.set("LegalCopyright", "Copyright © 2026 mjojo");
        let _ = res.compile();
    }
}
