use crate::error::Result;
use crate::session;

pub fn run() -> Result<()> {
    session::clear()?;
    println!("Logged out.");
    Ok(())
}
