//! ShieldGuard Tauri Application Entrypoint
//! In Phase 3, this initializes the Tauri runtime, custom window, system tray,
//! and IPC named-pipe client bridge.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("ShieldGuard Desktop UI Client v{}", core_engine::version());
    println!("Backend named pipe: {}", core_engine::ipc::DEFAULT_PIPE_NAME);
    Ok(())
}
