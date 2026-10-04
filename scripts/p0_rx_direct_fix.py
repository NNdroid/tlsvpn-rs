from pathlib import Path

path = Path("src/frame.rs")
s = path.read_text()
needle = """    fn buffered_frames_are_consumed_before_reader_reentry() {
        let mut burst = Vec::new();
"""
assert needle in s
start = s.index(needle)
old = """        let mut scanner = FrameScanner::new();

        let (first, first_seq) = scanner.read_frame(&mut reader).unwrap().unwrap();
"""
pos = s.index(old, start)
new = """        let mut scanner = FrameScanner::new();
        // This regression specifically locks the legacy scanner's buffered-burst
        // behavior. Direct-fill intentionally reads header/payload separately and
        // has its own fragmented/WouldBlock regression coverage below.
        scanner.direct_fill = false;

        let (first, first_seq) = scanner.read_frame(&mut reader).unwrap().unwrap();
"""
s = s[:pos] + s[pos:].replace(old, new, 1)
path.write_text(s)
