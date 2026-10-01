#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str):
    p = Path(path)
    s = p.read_text()
    if old not in s:
        raise SystemExit(f"marker missing in {path}: {old[:160]!r}")
    p.write_text(s.replace(old, new, 1))

replace_once(
    "src/client.rs",
    '''        Some(RxSessionActor::new(\n            Arc::new(move |batch| delivery.enqueue(batch)),\n            None,\n        ))''',
    '''        Some(RxSessionActor::new(\n            Arc::new(move |batch| {\n                delivery.enqueue(batch);\n                delivery.acquire()\n            }),\n            None,\n        ))''',
)

replace_once(
    "src/server.rs",
    '''                    Arc::new(move |batch| {\n                        for ordered in batch {\n                            if actor_mac != [0u8; 6] {\n                                vswitch.process_session_frame(&actor_client_id, actor_mac, ordered);\n                            } else {\n                                vswitch.process_frame(&actor_client_id, ordered);\n                            }\n                        }\n                    }),''',
    '''                    Arc::new(move |mut batch| {\n                        for ordered in batch.drain(..) {\n                            if actor_mac != [0u8; 6] {\n                                vswitch.process_session_frame(&actor_client_id, actor_mac, ordered);\n                            } else {\n                                vswitch.process_frame(&actor_client_id, ordered);\n                            }\n                        }\n                        batch\n                    }),''',
)
