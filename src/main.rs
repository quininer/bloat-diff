use std::fs;
use std::path::{ PathBuf, Path };
use std::collections::HashMap;
use argh::FromArgs;
use indexmap::IndexSet;
use object::{ Object, ObjectSection, ObjectSymbol, ObjectSymbolTable, SymbolIndex };

/// Bloat differ
#[derive(FromArgs)]
struct Options {
    /// first file
    #[argh(positional)]
    file0: PathBuf,

    /// second file
    #[argh(positional)]
    file1: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let options: Options = argh::from_env();

    let file0 = fs::File::open(&options.file0)?;
    let file0 = unsafe {
        memmap2::Mmap::map(&file0)?
    };
    let file0 = object::File::parse(&*file0)?;

    let file1 = fs::File::open(&options.file1)?;
    let file1 = unsafe {
        memmap2::Mmap::map(&file1)?
    };
    let file1 = object::File::parse(&*file1)?;

    let mut map0 = collect_map(&file0);
    let map1 = collect_map(&file1);

    let mut newsym = Vec::new();
    for sym in file1.symbol_table()
        .into_iter()
        .map(|symtab| symtab.symbols())
        .flatten()
        .filter(|sym| matches!(sym.kind(), object::SymbolKind::Text) && sym.name().is_ok())
    {
        if let Some(list) = map0.symmap.get_mut(sym.name().unwrap_or_default())
            && let Some(pos) = list.iter()
                .position(|idx0| map0.sizemap.get(idx0) == map1.sizemap.get(&sym.index()))
        {
            list.remove(pos);
            continue
        }

        newsym.push(sym.index());
    }

    let mut oldsym = map0.symmap.values().flatten().copied().collect::<Vec<_>>();
    oldsym.sort_unstable_by_key(|&idx| file0.symbol_by_index(idx).unwrap().address());

    let mut files = IndexSet::default();

    let (oldcode, oldsym) = collect_changed(&options.file0, &file0, &map0.sizemap, &oldsym, &mut files)?;
    let (newcode, newsym) = collect_changed(&options.file1, &file1, &map1.sizemap, &newsym, &mut files)?;

    let mut changedcode: HashMap<_, i64> = HashMap::with_capacity(oldcode.len());
    let mut changedsym: HashMap<_, i64> = HashMap::with_capacity(oldcode.len());

    for (&(fileid, ..), &count) in &oldcode {
        *changedcode.entry(fileid).or_default() -= count as i64;
    }
    for (&(fileid, ..), &count) in &newcode {
        *changedcode.entry(fileid).or_default() += count as i64;
    }
    drop((oldcode, newcode));

    for (&key, &count) in &oldsym {
        let sym = file0.symbol_by_index(key).unwrap();
        let sym = sym.name().unwrap_or_default();
        *changedsym.entry(sym).or_default() -= count as i64;
    }

    for (&key, &count) in &newsym {
        let sym = file1.symbol_by_index(key).unwrap();
        let sym = sym.name().unwrap_or_default();
        *changedsym.entry(sym).or_default() += count as i64;
    }
    drop((oldsym, newsym));

    let mut sum = 0;

    let mut changedcode = changedcode.into_iter().collect::<Vec<_>>();
    changedcode.sort_unstable_by_key(|(_, count)| *count);
    for &(fileid, count) in &changedcode {
        if count == 0 {
            continue
        }

        sum += count;

        println!("[code] {}\t{}", files[fileid], count);
    }

    let mut changedsym = changedsym.into_iter().collect::<Vec<_>>();
    changedsym.sort_unstable_by_key(|(_, count)| *count);
    for &(sym, count) in &changedsym {
        sum += count;
        println!("[sym] {}\t{}", sym, count);
    }

    println!("sum: {}", sum);

    Ok(())    
}

struct SymbolMap<'data> {
    sizemap: HashMap<SymbolIndex, u64>,
    symmap: HashMap<&'data str, Vec<SymbolIndex>>
}

fn collect_map<'data>(obj: &object::File<'data>) -> SymbolMap<'data> {
    let mut symbols = obj.symbols().collect::<Vec<_>>();
    let mut sizemap = HashMap::new();
    let mut symmap: HashMap<_, Vec<_>> = HashMap::new();

    symbols.sort_by_key(|sym| sym.address());

    let mut idx = 0;
    while idx < symbols.len() {
        let sym = &symbols[idx];

        if !matches!(sym.kind(), object::SymbolKind::Text)
            || sym.name().is_err()
        {
            idx += 1;
            continue
        }
        
        let size = if obj.format() != object::BinaryFormat::MachO {
            sym.size()
        } else if let Some(sym2) = symbols.get(idx + 1) {
            sym2.address() - sym.address()
        } else {
            // TODO text section only
            let section = obj.section_by_index(sym.section_index().unwrap()).unwrap();
            section.address() + section.size() - sym.address()
        };

        sizemap.insert(sym.index(), size);
        symmap.entry(sym.name().ok().unwrap_or_default()).or_default().push(sym.index());
        idx += 1;
    }

    SymbolMap { sizemap, symmap }
}

fn collect_changed(
    path: &Path,
    obj: &object::File<'_>,
    sizemap: &HashMap<SymbolIndex, u64>,
    syms: &[SymbolIndex],
    files: &mut IndexSet<String>
)
    -> anyhow::Result<(
        HashMap<(usize, u32, u32), u64>,
        HashMap<SymbolIndex, u64>,
    )>
{
    use addr2line::Loader;
    use addr2line::fallible_iterator::FallibleIterator;

    let addr2line = Loader::new(path)
        .map_err(|err| anyhow::format_err!("addr2lin: {}", err))?;

    let mut changed: HashMap<_, u64> = HashMap::new();
    let mut unknown: HashMap<_, u64> = HashMap::new();

    for &symidx in syms {
        let sym = obj.symbol_by_index(symidx).unwrap();
        let &symlen = sizemap.get(&symidx).unwrap();

        let mut sum = 0;
        for (offset, len, _line) in addr2line.find_location_range(
            sym.address(),
            sym.address() + symlen
        )
            .map_err(|err| anyhow::format_err!("addr2line: {:?}", err))?
        {
            sum += len;

            if let Some(frame) = addr2line.find_frames(offset)
                .map_err(|err| anyhow::format_err!("addr2line: {:?}", err))?
                .filter(|frame| Ok(frame.function.is_some() && frame.location.is_some()))
                .last()?
            {
                let location = frame.location.unwrap();
                let file = location.file.unwrap();
                let fileid = files.insert_full(file.into()).0;
                *changed
                    .entry((fileid, location.line.unwrap_or_default(), location.column.unwrap_or_default()))
                    .or_default()
                    += len;                
            } else {
                *unknown.entry(symidx).or_default() += len;
            }
        }

        if sum < symlen {
            *unknown.entry(symidx).or_default() += symlen - sum;
        }
    }

    Ok((changed, unknown))
}
