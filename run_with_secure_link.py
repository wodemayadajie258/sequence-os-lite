#!/usr/bin/env python3
"""
run_with_secure_link.py

Simple wrapper to run the demo using the secure Link implementation (link_secure.Link)
This script does not modify other repository files. It lives in the "加密实现" branch and
lets you use the secure implementation without changing your main code.

Usage:
  # write a JSON state (as string)
  python run_with_secure_link.py write '{"agent":"demo","step":0}' mypassword

  # write a JSON state from a file
  python run_with_secure_link.py writefile state.json mypassword

  # read a link
  python run_with_secure_link.py read <link_id> mypassword

  # read and migrate on read (will write a new secure link id if old was read)
  python run_with_secure_link.py read-migrate <link_id> mypassword

Note: Back up your link_store before running writes: cp -r link_store link_store.bak
"""

import sys
import json
import os
from link_secure import Link

USAGE = __doc__

def main(argv):
    if len(argv) < 2:
        print(USAGE)
        return 1
    cmd = argv[1]
    L = Link(store_dir=os.environ.get("LINK_STORE_DIR", "./link_store"))

    try:
        if cmd == "write":
            if len(argv) < 4:
                print("Usage: write '<json_state>' password")
                return 2
            state_str = argv[2]
            pwd = argv[3]
            state = json.loads(state_str)
            lid = L.write(state, pwd)
            print(lid)
            return 0

        if cmd == "writefile":
            if len(argv) < 4:
                print("Usage: writefile state.json password")
                return 2
            path = argv[2]
            pwd = argv[3]
            with open(path, 'r', encoding='utf-8') as f:
                state = json.load(f)
            lid = L.write(state, pwd)
            print(lid)
            return 0

        if cmd == "read":
            if len(argv) < 4:
                print("Usage: read <link_id> password")
                return 2
            lid = argv[2]
            pwd = argv[3]
            state = L.read(lid, pwd, migrate_on_read=False)
            print(json.dumps(state, ensure_ascii=False))
            return 0

        if cmd == "read-migrate":
            if len(argv) < 4:
                print("Usage: read-migrate <link_id> password")
                return 2
            lid = argv[2]
            pwd = argv[3]
            state = L.read(lid, pwd, migrate_on_read=True)
            print(json.dumps(state, ensure_ascii=False))
            return 0

        print("Unknown command", cmd)
        print(USAGE)
        return 3
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 4

if __name__ == '__main__':
    sys.exit(main(sys.argv))
