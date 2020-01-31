use std::collections::HashMap;
use std::env::args;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;
use wintracer::{ContinueStatus, DebugEventKind, ExceptionCode, WinTracer};

fn main() -> Result<(), &'static str> {
    let args = args().collect::<Vec<_>>();
    if args.len() != 4 {
        println!(
            "Usage: wintracer PROGRAM INFILE OUTFILE\n\n  \
			PROGRAM    path to exe file\n  \
			INFILE     file of list of breakpoint addresses\n  \
			OUTFILE    output trace file"
        );
        return Ok(());
    }

    let program = &args[1];
    let infile = &args[2];
    let outfile = &args[3];

    let addresses = read_addresses(Path::new(infile));
    let mut tracer = WinTracer::spawn(Path::new(program))?;
    let continue_status = ContinueStatus::Continue;

    for address in addresses {
        tracer.insert_breakpoint(address)?;
    }

    let mut hits = HashMap::new();

    loop {
        match tracer.next(continue_status)? {
            event => {
                //println!("{:?}", event);

                match event.kind {
                    DebugEventKind::Exception(e) => match e.code {
                        ExceptionCode::Wx86Breakpoint => {
                            let counter = hits.entry(e.address).or_insert(0);
                            *counter += 1;
                        }

                        ExceptionCode::Breakpoint => {
                            println!("System breakpoint 0x{:016x} hit!", e.address);
                        }

                        _ => unimplemented!(),
                    },

                    DebugEventKind::ExitProcess => break,

                    _ => {
                        println!("Unhandled: {:?}", event);
                    }
                }
            }
        }
    }

    write_tracefile(&hits, Path::new(outfile));
    Ok(())
}

fn read_addresses(path: &Path) -> Vec<usize> {
    let f = File::open(path).unwrap();
    let f = BufReader::new(f);
    f.lines()
        .map(|x| usize::from_str_radix(&x.unwrap(), 16).unwrap())
        .collect::<Vec<_>>()
}

fn write_tracefile(hits: &HashMap<usize, usize>, path: &Path) {
    let mut f = File::create(path).unwrap();

    for hit in hits {
        writeln!(f, "{:x} {}", hit.0, hit.1).unwrap();
    }
}
