#!/usr/bin/env python3
"""
patch_ryu.py — φτιάχνει ryu 4.34 για Python 3.10 + eventlet >= 0.36.

Τρέχει στο build του Dockerfile.mininet μετά το pip install ryu.

Patch 1: eventlet >= 0.36 αφαίρεσε ALREADY_HANDLED από eventlet.wsgi.
         Το ryu/app/wsgi.py το κάνει bare import → προσθέτουμε try/except.

Patch 2: Python 3.10 αφαίρεσε collections.Callable/Mapping/κτλ
         (μεταφέρθηκαν στο collections.abc). Αντικαθιστούμε σε όλα τα .py του ryu.
"""
import glob

# ── Patch 1: wsgi.py ALREADY_HANDLED ─────────────────────────────────────────
WSGI = '/usr/local/lib/python3.10/dist-packages/ryu/app/wsgi.py'
try:
    t = open(WSGI).read()
    patched_wsgi = 'from eventlet.wsgi import ALREADY_HANDLED' not in t
    if not patched_wsgi:
        t = t.replace(
            'from eventlet.wsgi import ALREADY_HANDLED',
            'try:\n    from eventlet.wsgi import ALREADY_HANDLED\n'
            'except ImportError:\n    ALREADY_HANDLED = b""'
        )
        open(WSGI, 'w').write(t)
        print(f'[patch] {WSGI} — ALREADY_HANDLED fixed')
    else:
        print(f'[patch] {WSGI} — already patched')
except Exception as e:
    print(f'[patch] wsgi error: {e}')

# ── Patch 2: collections.abc για Python 3.10 ─────────────────────────────────
ABC_NAMES = [
    'Callable', 'Mapping', 'MutableMapping', 'MutableSequence',
    'Sequence', 'Iterable', 'Iterator', 'MutableSet', 'Set',
]
patched = 0
for f in glob.glob(
    '/usr/local/lib/python3.10/dist-packages/ryu/**/*.py',
    recursive=True,
):
    try:
        t = open(f).read()
        nt = t
        for name in ABC_NAMES:
            nt = nt.replace('collections.' + name, 'collections.abc.' + name)
        # Αφαίρεση διπλού abc (αν τρέξει ξανά)
        nt = nt.replace('collections.abc.abc.', 'collections.abc.')
        if nt != t:
            open(f, 'w').write(nt)
            patched += 1
    except Exception:
        pass

print(f'[patch] collections.abc: {patched} αρχεία διορθώθηκαν')
print('[patch] ryu Python 3.10 compatibility: DONE')
