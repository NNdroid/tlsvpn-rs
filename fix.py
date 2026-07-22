import os, re
for root, _, files in os.walk('src'):
    for f in files:
        if f.endswith('.rs'):
            p = os.path.join(root, f)
            with open(p, encoding='utf-8') as f_in:
                s = f_in.read()
            s = re.sub(r'use (ctr::cipher::KeyIvInit|sha2::Digest|std::io::Read|clap::Parser);\r?\n', '', s)
            s = re.sub(r'use std::io::\{Read, Write\};', 'use std::io::Write;', s)
            with open(p, 'w', encoding='utf-8') as f_out:
                f_out.write(s)
