use defmt_decoder::Table;
use defmt_decoder::{DecodeError, Frame, Locations, StreamDecoder};
use std::env;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;
use structopt::StructOpt;

/// Serial errors
#[derive(Debug, thiserror::Error)]
pub enum SerialError {
    #[error("Invalid parity requested \"{0}\"")]
    InvalidParityString(String),
    #[error("Invalid stop bits requested \"{0}\"")]
    InvalidStopBitsString(String),
    #[error("Defmt data not found")]
    DefmtDataNotFound,
}

#[derive(Debug, StructOpt)]
#[structopt()]
struct Opts {
    /// Path to the elf file with defmt metadata
    #[structopt(name = "elf", required(true))]
    elf: PathBuf,

    /// Path to the uart port device
    #[structopt(name = "port", required(true))]
    port: String,

    #[structopt(name = "ip", default_value = "127.0.0.1")]
    ip: String,

    /// Shows defmt parsing errors. By default these are ignored.
    #[structopt(long, short = "d")]
    display_parsing_errors: bool,
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::from_args();

    //Taken from: https://github.com/knurling-rs/probe-run/blob/main/src/main.rs
    const DEFAULT_LOG_FORMAT_WITHOUT_TIMESTAMP: &str = "{L} {s}\n└─ {m} @ {F}:{l}";
    const DEFAULT_VERBOSE_HOST_LOG_FORMAT: &str = "(HOST) {L} {s}\n└─ {m} @ {F}:{l}";
    
    defmt_decoder::log::init_logger(Some(DEFAULT_LOG_FORMAT_WITHOUT_TIMESTAMP), Some(DEFAULT_VERBOSE_HOST_LOG_FORMAT), false, move |metadata| {
        metadata.target().starts_with("defmt")
    });

    let current_dir = &env::current_dir()?;

    let elf_data = std::fs::read(&opts.elf)?;
    let (table, locations) = extract_defmt_info(&elf_data)?;
    let table = table.unwrap();

    let mut decoder_and_encoding = (table.new_stream_decoder(), table.encoding());

    let connection_string = format!("{}:{}", opts.ip, opts.port);
    let mut stream = TcpStream::connect(connection_string)?;

    let mut read_buf = [0; 1024];
    loop {

        let num_bytes_read = match stream.read(&mut read_buf) {
            Ok(count) => Ok(count),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(0),
            Err(error) => {log::warn!("GNA"); Err(error)},
        }?;

        if num_bytes_read != 0 {
            let (stream_decoder, encoding) = &mut decoder_and_encoding;
            stream_decoder.received(&read_buf[..num_bytes_read]);
            match decode_and_print_defmt_logs(
                &mut **stream_decoder,
                locations.as_ref(),
                current_dir,
                encoding.can_recover(),
            ) {
                Ok(_) => {}
                Err(error) => {
                    if opts.display_parsing_errors {
                        log::error!("Error parsing uart data: {}", error);
                    }
                }
            }
        } else {
            return Err(anyhow::anyhow!("Connection lost"));
        }
    }
}

fn extract_defmt_info(elf_bytes: &[u8]) -> anyhow::Result<(Option<Table>, Option<Locations>)> {
    let defmt_table = match env::var("PROBE_RUN_IGNORE_VERSION").as_deref() {
        Ok("true") | Ok("1") => defmt_decoder::Table::parse_ignore_version(elf_bytes)?,
        _ => defmt_decoder::Table::parse(elf_bytes)?,
    };

    let mut defmt_locations = None;

    if let Some(table) = defmt_table.as_ref() {
        let locations = table.get_locations(elf_bytes)?;

        if !table.is_empty() && locations.is_empty() {
            log::warn!("insufficient DWARF info; compile your program with `debug = 2` to enable location info");
        } else if table
            .indices()
            .all(|idx| locations.contains_key(&(idx as u64)))
        {
            defmt_locations = Some(locations);
        } else {
            log::warn!("(BUG) location info is incomplete; it will be omitted from the output");
        }
    }

    Ok((defmt_table, defmt_locations))
}

fn decode_and_print_defmt_logs(
    stream_decoder: &mut dyn StreamDecoder,
    locations: Option<&Locations>,
    current_dir: &Path,
    encoding_can_recover: bool,
) -> anyhow::Result<()> {
    loop {
        match stream_decoder.decode() {
            Ok(frame) => forward_to_logger(&frame, locations, current_dir),
            Err(DecodeError::UnexpectedEof) => break,
            Err(DecodeError::Malformed) => match encoding_can_recover {
                // if recovery is impossible, abort
                false => return Err(DecodeError::Malformed.into()),
                // if recovery is possible, skip the current frame and continue with new data
                true => continue,
            },
        }
    }

    Ok(())
}

fn forward_to_logger(frame: &Frame, locations: Option<&Locations>, current_dir: &Path) {
    let (file, line, mod_path) = location_info(frame, locations, current_dir);
    defmt_decoder::log::log_defmt(frame, file.as_deref(), line, mod_path.as_deref());
}

fn location_info(
    frame: &Frame,
    locations: Option<&Locations>,
    current_dir: &Path,
) -> (Option<String>, Option<u32>, Option<String>) {
    locations
        .map(|locations| &locations[&frame.index()])
        .map(|location| {
            let path = if let Ok(relpath) = location.file.strip_prefix(&current_dir) {
                relpath.display().to_string()
            } else {
                location.file.display().to_string()
            };
            (
                Some(path),
                Some(location.line as u32),
                Some(location.module.clone()),
            )
        })
        .unwrap_or((None, None, None))
}