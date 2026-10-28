use std::{env, error::Error, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| "generate-algorithm-capabilities".into());
    let Some(output) = arguments.next() else {
        return Err(format!("usage: {} <output-path>", program.to_string_lossy()).into());
    };
    if arguments.next().is_some() {
        return Err("expected exactly one output path argument".into());
    }

    fs::write(output, openpgp_policy::algorithm_capabilities_json()?)?;
    Ok(())
}
